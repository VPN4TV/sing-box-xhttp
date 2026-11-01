package libbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

// VPN4TV: UDP through the outline and wireproxy bridges.
//
// Without it the apps had two bad choices for a profile made only of bridges:
// send all UDP — QUIC, calls, WebRTC, DNS — around the tunnel with the real
// address (what they did), or drop it. A SOCKS client asks for UDP one of two
// ways, and both are served only after the greeting and the password check of
// socks5Handshake:
//
//   - UDP over TCP (sing-box's own protocol, a CONNECT to
//     sp.v2.udp-over-tcp.arpa): the datagrams travel framed inside that same
//     authenticated TCP connection. Nothing listens for UDP on the loopback, so
//     the password covers the datagrams as it covers TCP, and "sing-box reaches
//     every bridge over TCP only" stays true. This is what the apps' socks
//     outbounds use (udp_over_tcp).
//
//   - UDP ASSOCIATE (RFC 1928, section 7), for any other SOCKS client. The
//     relay is a fresh UDP socket on the loopback that lives as long as the
//     control connection (and no longer than the idle timeout) and takes
//     datagrams from one source only, since UDP carries no password: the
//     address the request names when it is a concrete loopback one, otherwise
//     the first loopback source that sends a well-formed datagram. Datagrams
//     from anywhere else, and fragments, are dropped without a word. On Linux
//     and Android the relay binds a random address of 127.0.0.0/8, so an app
//     racing to the relay first has some 40 bits to guess instead of a port.
//
// Upstream is the bridge's own packet path: a Shadowsocks UDP session to the
// Outline server, or UDP sockets inside the AmneziaWG netstack.

const (
	// socks5UDPMaxHeader is the longest SOCKS5 UDP header: RSV FRAG ATYP, a
	// 255-byte name and the port. Every packet buffer keeps that much free in
	// front of the payload so a header can go in without a copy.
	socks5UDPMaxHeader = 3 + 1 + 1 + 255 + 2
	// bridgePacketBufferSize fits any UDP datagram behind that headroom.
	bridgePacketBufferSize = socks5UDPMaxHeader + 65535
	// sing-box writes the UDP-over-TCP request together with the first
	// datagram, which is there as soon as the session exists.
	uotRequestTimeout = 30 * time.Second
)

// bridgeUDPIdleTimeout ends a UDP session nothing has crossed for that long.
// sing-box ends its own sessions sooner (5 minutes by default, less for QUIC
// and DNS), so this only catches clients that keep the TCP side open and go
// quiet.
const bridgeUDPIdleTimeout = 5 * time.Minute

// bridgeUDPIdleOverride, when positive, replaces it (tests).
var bridgeUDPIdleOverride atomic.Int64

func udpIdleTimeout() time.Duration {
	if d := bridgeUDPIdleOverride.Load(); d > 0 {
		return time.Duration(d)
	}
	return bridgeUDPIdleTimeout
}

// bridgeRelayRandomLoopback: the platforms where every address of
// 127.0.0.0/8 is local without configuration. macOS and Windows hosts only
// have 127.0.0.1, where the relay keeps the listener's address.
var bridgeRelayRandomLoopback = runtime.GOOS == "linux" || runtime.GOOS == "android"

var bridgePacketBufferPool = sync.Pool{New: func() any {
	b := make([]byte, bridgePacketBufferSize)
	return &b
}}

func getPacketBuffer() *[]byte  { return bridgePacketBufferPool.Get().(*[]byte) }
func putPacketBuffer(b *[]byte) { bridgePacketBufferPool.Put(b) }

var (
	errSocks5UDPShort    = errors.New("socks5 udp: short datagram")
	errSocks5UDPFragment = errors.New("socks5 udp: fragmented datagram")
	errSocks5UDPAddress  = errors.New("socks5 udp: bad address")
	// errPacketDropped marks a write error that costs one datagram, not the
	// session.
	errPacketDropped = errors.New("datagram dropped")
)

func dropped(reason any) error { return fmt.Errorf("%w: %v", errPacketDropped, reason) }

// parseSocks5UDP splits a SOCKS5 UDP request datagram
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA
//
// into its destination and payload; the payload aliases b. FRAG other than 0 is
// refused: reassembly is optional in RFC 1928 and nobody sends fragments.
func parseSocks5UDP(b []byte) (M.Socksaddr, []byte, error) {
	if len(b) < 4 {
		return M.Socksaddr{}, nil, errSocks5UDPShort
	}
	if b[2] != 0 {
		return M.Socksaddr{}, nil, errSocks5UDPFragment
	}
	var dest M.Socksaddr
	off := 4
	switch b[3] {
	case 0x01:
		if len(b) < off+4+2 {
			return M.Socksaddr{}, nil, errSocks5UDPShort
		}
		dest.Addr = netip.AddrFrom4([4]byte(b[off : off+4]))
		off += 4
	case 0x04:
		if len(b) < off+16+2 {
			return M.Socksaddr{}, nil, errSocks5UDPShort
		}
		dest.Addr = netip.AddrFrom16([16]byte(b[off : off+16])).Unmap()
		off += 16
	case 0x03:
		if len(b) < off+1 {
			return M.Socksaddr{}, nil, errSocks5UDPShort
		}
		length := int(b[off])
		off++
		if length == 0 {
			return M.Socksaddr{}, nil, errSocks5UDPAddress
		}
		if len(b) < off+length+2 {
			return M.Socksaddr{}, nil, errSocks5UDPShort
		}
		dest = M.ParseSocksaddrHostPort(string(b[off:off+length]), 0).Unwrap()
		off += length
	default:
		return M.Socksaddr{}, nil, errSocks5UDPAddress
	}
	dest.Port = binary.BigEndian.Uint16(b[off:])
	if dest.Port == 0 {
		return M.Socksaddr{}, nil, errSocks5UDPAddress
	}
	return dest, b[off+2:], nil
}

// socks5UDPHeaderLen is the header length for a datagram from src, or 0 when
// src cannot be written into one.
func socks5UDPHeaderLen(src M.Socksaddr) int {
	switch {
	case src.IsIPv4():
		return 4 + 4 + 2
	case src.IsIPv6():
		return 4 + 16 + 2
	case src.IsDomain() && len(src.Fqdn) <= 255:
		return 4 + 1 + len(src.Fqdn) + 2
	default:
		return 0
	}
}

// putSocks5UDPHeader writes the header of a datagram from src into b, which is
// exactly socks5UDPHeaderLen(src) long.
func putSocks5UDPHeader(b []byte, src M.Socksaddr) {
	b[0], b[1], b[2] = 0, 0, 0
	var off int
	switch {
	case src.IsIPv4():
		b[3] = 0x01
		ip := src.Addr.As4()
		off = 4 + copy(b[4:], ip[:])
	case src.IsIPv6():
		b[3] = 0x04
		ip := src.Addr.As16()
		off = 4 + copy(b[4:], ip[:])
	default:
		b[3] = 0x03
		b[4] = byte(len(src.Fqdn))
		off = 5 + copy(b[5:], src.Fqdn)
	}
	binary.BigEndian.PutUint16(b[off:], src.Port)
}

// appendSocks5UDP appends a whole SOCKS5 UDP datagram for addr to dst.
func appendSocks5UDP(dst []byte, addr M.Socksaddr, payload []byte) []byte {
	addr = addr.Unwrap()
	header := make([]byte, socks5UDPHeaderLen(addr))
	if len(header) == 0 {
		return dst
	}
	putSocks5UDPHeader(header, addr)
	return append(append(dst, header...), payload...)
}

func writeSocks5Reply(c net.Conn, reply byte, bound netip.AddrPort) error {
	b := make([]byte, 0, 22)
	b = append(b, socks5Version, reply, 0x00)
	if ip := bound.Addr().Unmap(); ip.Is6() {
		raw := ip.As16()
		b = append(append(b, 0x04), raw[:]...)
	} else if ip.Is4() {
		raw := ip.As4()
		b = append(append(b, 0x01), raw[:]...)
	} else {
		b = append(b, 0x01, 0, 0, 0, 0)
	}
	b = binary.BigEndian.AppendUint16(b, bound.Port())
	_, err := c.Write(b)
	return err
}

// bridgePacketSession is one upstream UDP session of a bridge. Datagrams back
// from upstream go to the bridgePacketHandler the session was opened with.
type bridgePacketSession interface {
	// WriteTo sends one datagram to dest, an address or a name. Called from
	// one goroutine at a time.
	WriteTo(p []byte, dest M.Socksaddr) error
	Close() error
}

// bridgePacketHandler takes what upstream sends back, on the session's own
// goroutines (more than one at a time is fine).
type bridgePacketHandler interface {
	// handlePacket gets a datagram from src: b[off:] is the payload, b[:off]
	// is free room for a header. b is only valid during the call.
	handlePacket(b []byte, off int, src M.Socksaddr)
	// handleEnd says upstream can deliver nothing more.
	handleEnd(err error)
}

// bridgePacketOpener opens an upstream session; nil means the bridge has no
// packet path, and UDP is refused.
type bridgePacketOpener func(ctx context.Context, handler bridgePacketHandler) (bridgePacketSession, error)

// bridgePacketPeer is the client end of a UDP session: the relay socket of an
// association or the stream of a UDP-over-TCP connection.
type bridgePacketPeer interface {
	// readPacket returns the next datagram the client sends and where it goes;
	// the payload aliases b. An error ends the session.
	readPacket(b []byte) ([]byte, M.Socksaddr, error)
	// writePacket sends b[off:] to the client as coming from src, using b[:off]
	// for the header. Safe for concurrent use. An error that is not
	// errPacketDropped ends the session.
	writePacket(b []byte, off int, src M.Socksaddr) error
}

// bridgePacketRelay moves datagrams between a peer and an upstream session
// until either side ends, the control connection goes, or nothing crosses for
// bridgeUDPIdleTimeout.
type bridgePacketRelay struct {
	peer    bridgePacketPeer
	session bridgePacketSession

	closeMu sync.Mutex
	closers []io.Closer
	stopped chan struct{}
	isStop  bool

	last    atomic.Int64
	up      atomic.Int64
	down    atomic.Int64
	drops   atomic.Int64
	idleOut atomic.Bool
}

func newBridgePacketRelay(peer bridgePacketPeer, closers ...io.Closer) *bridgePacketRelay {
	r := &bridgePacketRelay{peer: peer, closers: closers, stopped: make(chan struct{})}
	r.touch()
	return r
}

func (r *bridgePacketRelay) touch() { r.last.Store(time.Now().UnixNano()) }

// addCloser registers something to close with the session, or closes it at
// once when the session already ended.
func (r *bridgePacketRelay) addCloser(c io.Closer) {
	r.closeMu.Lock()
	if !r.isStop {
		r.closers = append(r.closers, c)
		r.closeMu.Unlock()
		return
	}
	r.closeMu.Unlock()
	_ = c.Close()
}

func (r *bridgePacketRelay) stop() {
	r.closeMu.Lock()
	if r.isStop {
		r.closeMu.Unlock()
		return
	}
	r.isStop = true
	closers := r.closers
	r.closers = nil
	close(r.stopped)
	r.closeMu.Unlock()
	for _, c := range closers {
		_ = c.Close()
	}
}

func (r *bridgePacketRelay) handlePacket(b []byte, off int, src M.Socksaddr) {
	r.touch()
	if err := r.peer.writePacket(b, off, src); err != nil {
		if errors.Is(err, errPacketDropped) {
			r.drops.Add(1)
			return
		}
		r.stop()
		return
	}
	r.down.Add(int64(len(b) - off))
}

func (r *bridgePacketRelay) handleEnd(error) { r.stop() }

// open opens the upstream session; it is closed with the relay.
func (r *bridgePacketRelay) open(opener bridgePacketOpener) error {
	session, err := opener(context.Background(), r)
	if err != nil {
		return err
	}
	r.session = session
	r.addCloser(session)
	return nil
}

// run carries client datagrams upstream until the session ends, then closes
// everything. The session's readers deliver the other way on their own.
func (r *bridgePacketRelay) run() {
	defer r.stop()
	go r.watchIdle(udpIdleTimeout())
	b := getPacketBuffer()
	defer putPacketBuffer(b)
	for {
		payload, dest, err := r.peer.readPacket(*b)
		if err != nil {
			return
		}
		r.touch()
		if err := r.session.WriteTo(payload, dest); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			r.drops.Add(1)
			continue
		}
		r.up.Add(int64(len(payload)))
	}
}

func (r *bridgePacketRelay) watchIdle(idle time.Duration) {
	tick := idle / 4
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	} else if tick > 30*time.Second {
		tick = 30 * time.Second
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopped:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, r.last.Load())) >= idle {
				r.idleOut.Store(true)
				r.stop()
				return
			}
		}
	}
}

func (r *bridgePacketRelay) summary() string {
	s := fmt.Sprintf("up=%d down=%d dropped=%d", r.up.Load(), r.down.Load(), r.drops.Load())
	if r.idleOut.Load() {
		s += " (idle)"
	}
	return s
}

// serveBridgeUDP serves the UDP requests of a bridge's SOCKS client: a UDP
// ASSOCIATE, or a CONNECT to the UDP-over-TCP names. It returns false for any
// other request, which the caller serves as plain TCP.
func serveBridgeUDP(client net.Conn, request socks5Request, opener bridgePacketOpener, logf func(string, ...any)) bool {
	switch {
	case request.command == socks5CommandUDPAssociate:
		serveUDPAssociate(client, request, opener, logf)
		return true
	case request.command == socks5CommandConnect && (request.host == uot.MagicAddress || request.host == uot.LegacyMagicAddress):
		serveUDPOverTCP(client, request, opener, logf)
		return true
	}
	return false
}

// ---- UDP over TCP ----

func serveUDPOverTCP(client net.Conn, request socks5Request, opener bridgePacketOpener, logf func(string, ...any)) {
	if opener == nil {
		_ = writeSocks5Reply(client, socks5ReplyGeneralFailure, netip.AddrPort{})
		logf("udp-over-tcp refused: this bridge has no UDP")
		return
	}
	if err := writeSocks5Reply(client, socks5ReplySucceeded, netip.AddrPort{}); err != nil {
		return
	}
	reader := bufio.NewReaderSize(client, 16*1024)
	var uotRequest uot.Request // version 1: no request, every datagram addressed
	if request.host == uot.MagicAddress {
		_ = client.SetReadDeadline(time.Now().Add(uotRequestTimeout))
		parsed, err := uot.ReadRequest(reader)
		_ = client.SetReadDeadline(time.Time{})
		if err != nil {
			logf("udp-over-tcp request: %v", err)
			return
		}
		uotRequest = *parsed
	}
	peer := &uotPeer{
		reader:      reader,
		conn:        uot.NewConn(client, uotRequest),
		isConnect:   uotRequest.IsConnect,
		destination: uotRequest.Destination.Unwrap(),
	}
	relay := newBridgePacketRelay(peer, client)
	if err := relay.open(opener); err != nil {
		relay.stop()
		logf("udp-over-tcp: upstream: %v", err)
		return
	}
	relay.run()
	logf("udp-over-tcp closed: %s", relay.summary())
}

// uotPeer reads the sing-box UDP-over-TCP framing (uot.Conn): [address]
// length payload, the address only when the session is not connected.
type uotPeer struct {
	reader      *bufio.Reader
	conn        *uot.Conn // writes only: the reader above owns the read side
	isConnect   bool
	destination M.Socksaddr
}

func (p *uotPeer) readPacket(b []byte) ([]byte, M.Socksaddr, error) {
	for {
		dest := p.destination
		if !p.isConnect {
			var err error
			dest, err = uot.AddrParser.ReadAddrPort(p.reader)
			if err != nil {
				return nil, M.Socksaddr{}, err
			}
			dest = dest.Unwrap()
		}
		var size [2]byte
		if _, err := io.ReadFull(p.reader, size[:]); err != nil {
			return nil, M.Socksaddr{}, err
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length > len(b) {
			// Cannot happen with our buffers; keep the stream in step anyway.
			if _, err := p.reader.Discard(length); err != nil {
				return nil, M.Socksaddr{}, err
			}
			continue
		}
		if _, err := io.ReadFull(p.reader, b[:length]); err != nil {
			return nil, M.Socksaddr{}, err
		}
		return b[:length], dest, nil
	}
}

func (p *uotPeer) writePacket(b []byte, off int, src M.Socksaddr) error {
	src = src.Unwrap()
	if !p.isConnect && !src.IsValid() {
		return dropped("no source address")
	}
	return p.conn.WritePacket(buf.As(b[off:]), src)
}

// ---- UDP ASSOCIATE ----

func serveUDPAssociate(client net.Conn, request socks5Request, opener bridgePacketOpener, logf func(string, ...any)) {
	if opener == nil {
		// socks5Handshake already refuses this; keep the reply right anyway.
		_ = writeSocks5Reply(client, socks5ReplyNoCommand, netip.AddrPort{})
		return
	}
	local := M.AddrPortFromNet(client.LocalAddr())
	remote := M.AddrPortFromNet(client.RemoteAddr())
	relaySocket, err := listenUDPRelay(local.Addr())
	if err != nil {
		_ = writeSocks5Reply(client, socks5ReplyGeneralFailure, netip.AddrPort{})
		logf("udp associate: relay: %v", err)
		return
	}
	peer := newUDPAssociatePeer(relaySocket, remote.Addr(), request.addr())
	relay := newBridgePacketRelay(peer, client, relaySocket)
	if err := relay.open(opener); err != nil {
		_ = writeSocks5Reply(client, socks5ReplyGeneralFailure, netip.AddrPort{})
		relay.stop()
		logf("udp associate: upstream: %v", err)
		return
	}
	bound := M.AddrPortFromNet(relaySocket.LocalAddr())
	if err := writeSocks5Reply(client, socks5ReplySucceeded, bound); err != nil {
		relay.stop()
		return
	}
	// The association lasts as long as the control connection; nothing more
	// is expected on it.
	go func() {
		_, _ = io.Copy(io.Discard, client)
		relay.stop()
	}()
	relay.run()
	logf("udp associate closed: %s, foreign=%d malformed=%d", relay.summary(), peer.foreign.Load(), peer.malformed.Load())
}

// listenUDPRelay opens the relay socket of an association next to the
// listener the client reached (ip).
func listenUDPRelay(ip netip.Addr) (*net.UDPConn, error) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		ip = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	if bridgeRelayRandomLoopback && ip.Is4() && ip.IsLoopback() {
		var random [3]byte
		if _, err := rand.Read(random[:]); err == nil && random[2] != 0 && random[2] != 255 {
			candidate := netip.AddrFrom4([4]byte{127, random[0], random[1], random[2]})
			if c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(candidate, 0))); err == nil {
				return c, nil
			}
		}
	}
	network := "udp4"
	if ip.Is6() {
		network = "udp6"
	}
	return net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
}

// udpAssociatePeer is the relay socket of one association, bound to a single
// client source.
type udpAssociatePeer struct {
	relay *net.UDPConn
	// controlIP is the client's address on the control connection.
	controlIP netip.Addr
	// wantIP / wantPort, when set, are the source the request named.
	wantIP   netip.Addr
	wantPort uint16
	// client is the source the association is bound to, once known. Written
	// by the reader only.
	client    atomic.Pointer[netip.AddrPort]
	foreign   atomic.Int64
	malformed atomic.Int64
}

// newUDPAssociatePeer: requested is DST.ADDR/DST.PORT of the request, the
// address the client says it will send from. Only a loopback address or an
// unspecified one with a port can be that: sing-box puts the destination of
// the first datagram there instead, which must not be mistaken for the source.
func newUDPAssociatePeer(relay *net.UDPConn, controlIP netip.Addr, requested M.Socksaddr) *udpAssociatePeer {
	p := &udpAssociatePeer{relay: relay, controlIP: controlIP.Unmap()}
	if requested.IsIP() && requested.Port != 0 {
		ip := requested.Addr.Unmap()
		switch {
		case ip.IsLoopback():
			p.wantIP, p.wantPort = ip, requested.Port
		case ip.IsUnspecified():
			p.wantPort = requested.Port
		}
	}
	return p
}

// acceptable reports whether src may become the association's client.
func (p *udpAssociatePeer) acceptable(src netip.AddrPort) bool {
	if p.wantIP.IsValid() && src.Addr() != p.wantIP {
		return false
	}
	if p.wantPort != 0 && src.Port() != p.wantPort {
		return false
	}
	if p.controlIP.IsLoopback() {
		return src.Addr().IsLoopback()
	}
	return src.Addr() == p.controlIP
}

func (p *udpAssociatePeer) readPacket(b []byte) ([]byte, M.Socksaddr, error) {
	for {
		n, src, err := p.relay.ReadFromUDPAddrPort(b)
		if err != nil {
			if isTransientPacketError(err) {
				continue
			}
			return nil, M.Socksaddr{}, err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		bound := p.client.Load()
		if (bound != nil && src != *bound) || (bound == nil && !p.acceptable(src)) {
			p.foreign.Add(1)
			continue
		}
		dest, payload, err := parseSocks5UDP(b[:n])
		if err != nil {
			p.malformed.Add(1)
			continue
		}
		if bound == nil {
			p.client.Store(&src)
		}
		return payload, dest, nil
	}
}

func (p *udpAssociatePeer) writePacket(b []byte, off int, src M.Socksaddr) error {
	client := p.client.Load()
	if client == nil {
		return dropped("no client yet")
	}
	src = src.Unwrap()
	headerLen := socks5UDPHeaderLen(src)
	if headerLen == 0 || headerLen > off {
		return dropped("source does not fit a header")
	}
	putSocks5UDPHeader(b[off-headerLen:off], src)
	if _, err := p.relay.WriteToUDPAddrPort(b[off-headerLen:], *client); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		return dropped(err)
	}
	return nil
}

// isTransientPacketError: an ICMP error reported on a later read (connection
// refused or reset), which costs nothing but that read.
func isTransientPacketError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

// isFatalPacketError: the socket is gone (closed, or failing in a way more
// reads will not fix). Anything else — a datagram that would not decrypt, one
// that did not fit — costs only that datagram.
func isFatalPacketError(err error) bool {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return !opErr.Timeout() && !isTransientPacketError(err)
	}
	return false
}
