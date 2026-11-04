package libbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"strings"
	"sync"
	"syscall"

	M "github.com/sagernet/sing/common/metadata"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// Outline bridge for Shadowsocks variants that sing-box cannot handle natively
// (notably ss:// links with the SIP002 ?prefix= parameter used by Outline TLS-
// looking obfuscation). Mirrors the embedded xray bridge architecture: the
// bridge runs in the same Go runtime as sing-box, exposes one local SOCKS5
// inbound per Shadowsocks endpoint on 127.0.0.127:<port>, and sing-box routes
// to those inbounds via regular socks outbounds.
//
// Sockets created by outline-sdk's StreamDialer are protected via the same
// platformInterfaceWrapper.AutoDetectInterfaceControl callback used by xray
// (Android's VpnService.protect). The protection is wired through a custom
// transport.StreamDialer that wraps net.Dialer.Control.

// OutlineEndpointConfig describes one Shadowsocks endpoint that outline-sdk
// will dial. Passed in as JSON from Kotlin; the fields mirror what we already
// parse on the client side.
//
// Shape: { "dns": ["9.9.9.9"], "endpoints": [ { "url": "ss://...", "port": 30000 }, ... ] }
type outlineConfig struct {
	// DNS servers for the server names of every endpoint that has none of its
	// own; see bridgeDNSServers. Absent: the system resolver, as before.
	DNS       bridgeDNSServers  `json:"dns,omitempty"`
	Endpoints []outlineEndpoint `json:"endpoints"`
}

type outlineEndpoint struct {
	URL  string `json:"url"`
	Port int    `json:"port"`
	// Listen address for this endpoint's SOCKS5 inbound. Android and Linux bind
	// the whole 127.0.0.0/8, so the mobile clients use 127.0.0.127 to stay clear
	// of anything the user runs; macOS and Windows only have 127.0.0.1, where
	// binding 127.0.0.127 fails with "can't assign requested address". Empty
	// means the historical default, so mobile profiles keep working untouched.
	Listen string `json:"listen,omitempty"`
	// Optional username/password for this endpoint's SOCKS5 inbound; see
	// bridgeSocksAuth. Empty keeps the historical no-auth inbound.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// DNS servers for this endpoint's server name, instead of the config's.
	// A dynamic key is no different: the app puts the key it fetched into URL
	// before the start, and its server name goes the same way.
	DNS bridgeDNSServers `json:"dns,omitempty"`
	// UDPAssociate lets SOCKS UDP ASSOCIATE in; off, it is refused (0x07).
	// UDP over TCP, which the apps use, needs nothing.
	UDPAssociate bool `json:"udp_associate,omitempty"`
}

// bridgeListenHost is what an endpoint binds when the profile does not say.
const bridgeListenHost = "127.0.0.127"

func endpointListenHost(listen string) string {
	if listen != "" {
		return listen
	}
	return bridgeListenHost
}

var (
	outlineMu        sync.Mutex
	outlineListeners []net.Listener
	outlineLogMu     sync.Mutex
	outlineLogLines  []string
)

const outlineLogMax = 200

func outlineLog(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	stdlog.Println("outline:", line)
	outlineLogMu.Lock()
	defer outlineLogMu.Unlock()
	outlineLogLines = append(outlineLogLines, line)
	if len(outlineLogLines) > outlineLogMax {
		outlineLogLines = outlineLogLines[len(outlineLogLines)-outlineLogMax:]
	}
}

// OutlineLog returns up to the last [outlineLogMax] log lines emitted by the
// outline bridge, separated by newlines. Exposed via gomobile for diagnostics.
// Wrapped in StringBox: gomobile-exported `string` return on 32-bit ARM
// triggers `bulkBarrierPreWrite: unaligned arguments` (golang/go#46893)
// because the two-word string header lands on a 4-byte aligned stack slot;
// the write barrier then corrupts the heap and GC blames a bad pointer
// later. Heap-allocating the wrapper struct sidesteps the issue.
func OutlineLog() *StringBox {
	outlineLogMu.Lock()
	defer outlineLogMu.Unlock()
	return wrapString(strings.Join(outlineLogLines, "\n"))
}

// newOutlineProviders builds a fresh ProviderContainer whose root TCP dialer
// has a Control function that calls platformInterfaceWrapper.AutoDetectInterfaceControl
// (Android's VpnService.protect) on the raw fd. This bypasses the TUN that
// sing-box installs — without it outline traffic loops back through the TUN
// and deadlocks. The root UDP dialer and listener get the same Control: the
// Shadowsocks UDP socket to the server would loop through the TUN just the
// same.
//
// With a resolver the root dialers find the server's address through it, for
// TCP and UDP alike, instead of the system resolver — which on Android asks
// the DNS of the VPN network, that is our own tunnel (see bridge_dns.go).
func newOutlineProviders(resolver *bridgeResolver) *configurl.ProviderContainer {
	var streams transport.StreamDialer = &transport.TCPDialer{Dialer: protectedNetDialer()}
	var packets transport.PacketDialer = &transport.UDPDialer{Dialer: protectedNetDialer()}
	if resolver != nil {
		streams = &outlineStreamDialer{dialer: protectedNetDialer(), resolver: resolver}
		packets = &outlinePacketDialer{dialer: protectedNetDialer(), resolver: resolver}
	}
	c := &configurl.ProviderContainer{
		StreamDialers: configurl.NewExtensibleProvider[transport.StreamDialer](streams),
		PacketDialers: configurl.NewExtensibleProvider[transport.PacketDialer](packets),
		PacketListeners: configurl.NewExtensibleProvider[transport.PacketListener](&transport.UDPListener{
			ListenConfig: net.ListenConfig{Control: protectedNetDialer().Control},
		}),
	}
	configurl.RegisterDefaultProviders(c)
	return c
}

// outlineStreamDialer is the root TCP dialer of an endpoint with DNS servers.
type outlineStreamDialer struct {
	dialer   net.Dialer
	resolver *bridgeResolver
}

func (d *outlineStreamDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	conn, err := d.resolver.dial(ctx, &d.dialer, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// outlinePacketDialer is the root UDP dialer of an endpoint with DNS servers:
// the Shadowsocks UDP socket of every session to the server.
type outlinePacketDialer struct {
	dialer   net.Dialer
	resolver *bridgeResolver
}

func (d *outlinePacketDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return d.resolver.dial(ctx, &d.dialer, "udp", addr)
}

func protectedNetDialer() net.Dialer {
	return net.Dialer{
		Control: func(network, address string, conn syscall.RawConn) error {
			err := bridgeControl(network, address, conn)
			if err != nil {
				outlineLog("protect(%s) failed: %v", address, err)
			}
			return err
		},
	}
}

// StartOutlineBridge starts SOCKS5 inbounds for every endpoint in the JSON
// config. Each inbound forwards new connections through outline-sdk to the
// Shadowsocks endpoint described by the corresponding ss:// URL.
//
// If a previous bridge is running it is stopped first.
func StartOutlineBridge(configJSON string) error {
	outlineMu.Lock()
	defer outlineMu.Unlock()

	stopOutlineLocked()

	var cfg outlineConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("outline: parse config: %w", err)
	}
	if len(cfg.Endpoints) == 0 {
		return errors.New("outline: no endpoints")
	}

	// One cap on UDP sessions for the whole bridge.
	sessions := newBridgeUDPSessions(outlineLog)
	for i, ep := range cfg.Endpoints {
		// An endpoint without a key (a dynamic key the app could not fetch) gets
		// no listener. outline-sdk takes an empty config for no transport at all,
		// a plain direct dialer, so the endpoint would carry traffic past the VPN
		// with the real address, and urltest tends to pick it, the direct path
		// being the fastest. Without a listener sing-box's socks outbound is
		// refused and urltest marks it dead. Not an error: the other endpoints
		// and the rest of the profile go on.
		if strings.TrimSpace(ep.URL) == "" {
			outlineLog("endpoint %d (port %d): no key, left out", i, ep.Port)
			continue
		}
		resolver := newBridgeResolver(pickBridgeDNS(ep.DNS, cfg.DNS), outlineLog)
		if resolver != nil {
			outlineLog("endpoint %d: server names through DNS %s", i, resolver)
		}
		providers := newOutlineProviders(resolver)
		dialer, err := providers.NewStreamDialer(context.Background(), ep.URL)
		if err != nil {
			stopOutlineLocked()
			return fmt.Errorf("outline: build dialer for endpoint %d: %w", i, err)
		}
		udp := &bridgeUDP{
			open:      newOutlinePacketOpener(providers, ep.URL, i),
			associate: ep.UDPAssociate,
			sessions:  sessions,
			logf:      outlineLog,
		}
		listenAddr := fmt.Sprintf("%s:%d", endpointListenHost(ep.Listen), ep.Port)
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			stopOutlineLocked()
			return fmt.Errorf("outline: listen %s: %w", listenAddr, err)
		}
		outlineListeners = append(outlineListeners, ln)
		go runOutlineSocks(ln, dialer, udp, newBridgeSocksAuth(ep.Username, ep.Password))
	}
	return nil
}

// newOutlinePacketOpener builds the UDP side of an endpoint: one Shadowsocks
// UDP session per SOCKS UDP session, to the same server with the same key.
//
// The ?prefix= of the key does not apply to UDP. outline-sdk puts it on TCP
// only — its packet listener leaves it out ("TODO: support UDP prefix" in
// x/configurl) and so do the Outline apps — and the server never looks at it:
// a Shadowsocks server takes any salt, the prefix is just the start of the
// salt chosen to look like something else on the wire. Every UDP datagram is a
// plain AEAD packet with a fresh random salt, which outline-ss-server (and any
// other Shadowsocks server) decrypts with the key alone.
//
// A key the UDP side cannot be built for keeps its TCP: the endpoint then
// refuses UDP, as before.
func newOutlinePacketOpener(providers *configurl.ProviderContainer, url string, index int) bridgePacketOpener {
	listener, err := providers.NewPacketListener(context.Background(), url)
	if err != nil {
		outlineLog("endpoint %d: no UDP: %v", index, err)
		return nil
	}
	return func(ctx context.Context, handler bridgePacketHandler) (bridgePacketSession, error) {
		conn, err := listener.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		session := &outlinePacketSession{conn: conn}
		go session.read(handler)
		return session, nil
	}
}

// outlineMaxDatagram is the most outline-sdk hands back from one read: it
// decrypts into a 16 KiB buffer of its own (clientUDPBufferSize in
// transport/shadowsocks), salt, tag and address included.
const outlineMaxDatagram = 16 * 1024

// outlinePacketBuffers holds the read buffers of the sessions: a datagram from
// the server with room for a SOCKS header in front.
var outlinePacketBuffers = newBridgeBufferPool(socks5UDPMaxHeader + outlineMaxDatagram)

// outlinePacketSession is one Shadowsocks UDP association: a connected UDP
// socket to the server, every datagram carrying its own target address.
type outlinePacketSession struct {
	conn net.PacketConn
}

// WriteTo hands names to the server as names, like the TCP side does.
func (s *outlinePacketSession) WriteTo(p []byte, dest M.Socksaddr) error {
	_, err := s.conn.WriteTo(p, dest)
	return err
}

func (s *outlinePacketSession) Close() error { return s.conn.Close() }

func (s *outlinePacketSession) read(handler bridgePacketHandler) {
	b := outlinePacketBuffers.get()
	defer outlinePacketBuffers.put(b)
	failures := 0
	for {
		n, addr, err := s.conn.ReadFrom((*b)[socks5UDPMaxHeader:])
		if err != nil {
			// A datagram that does not decrypt (or an ICMP error) costs only
			// itself; a run of them that never ends means a dead socket.
			failures++
			if isFatalPacketError(err) || failures > 1000 {
				handler.handleEnd(err)
				return
			}
			continue
		}
		failures = 0
		handler.handlePacket((*b)[:socks5UDPMaxHeader+n], socks5UDPMaxHeader, M.SocksaddrFromNet(addr).Unwrap())
	}
}

// StopOutlineBridge stops every running outline SOCKS inbound.
func StopOutlineBridge() error {
	outlineMu.Lock()
	defer outlineMu.Unlock()
	stopOutlineLocked()
	return nil
}

func stopOutlineLocked() {
	for _, ln := range outlineListeners {
		_ = ln.Close()
	}
	outlineListeners = nil
}

// runOutlineSocks accepts SOCKS5 clients on ln and forwards each accepted
// connection to dialer.DialStream(realDest) where realDest comes from the
// SOCKS CONNECT request (the outline-sdk dialer already wraps the SS endpoint,
// so the target address must be the real website, not the SS server itself).
// UDP requests go to udp (see bridge_udp.go).
func runOutlineSocks(ln net.Listener, dialer transport.StreamDialer, udp *bridgeUDP, auth *bridgeSocksAuth) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go handleOutlineClient(client, dialer, udp, auth)
	}
}

func handleOutlineClient(client net.Conn, dialer transport.StreamDialer, udp *bridgeUDP, auth *bridgeSocksAuth) {
	defer client.Close()
	request, err := socks5Handshake(client, auth, udp.associateAllowed())
	if err != nil {
		outlineLog("socks5 handshake failed: %v", err)
		return
	}
	if serveBridgeUDP(client, request, udp) {
		return
	}
	realDest := request.dest()
	outlineLog("socks handshake ok, dialing real dest %s via outline-sdk", realDest)
	// NOTE: don't use context.WithTimeout here — outline-sdk's StreamDialer
	// keeps the dial ctx alive for the whole connection lifetime. If we cancel
	// it after DialStream returns, the underlying SS conn dies immediately and
	// io.Copy reports up=N down=0 because the read side is already closed.
	remote, err := dialer.DialStream(context.Background(), realDest)
	if err != nil {
		outlineLog("DialStream(%s) failed: %v", realDest, err)
		return
	}
	defer remote.Close()
	outlineLog("DialStream(%s) ok, piping", realDest)
	// Notify SOCKS client that CONNECT succeeded. We hard-code BND.ADDR=0.0.0.0:0
	// because sing-box doesn't read it — it only looks at REP.
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	pipe(client, remote)
}

// pipe copies traffic in both directions between a (client) and b (remote)
// until both halves close. Crucially we wait for BOTH halves to finish, not
// just one — closing prematurely on the first finished half kills the other
// direction (we previously saw download=0 because the upload half completed
// first and triggered defer client.Close()).
func pipe(a, b net.Conn) {
	type halfResult struct {
		bytes int64
		dir   string
		err   error
	}
	done := make(chan halfResult, 2)
	go func() {
		n, err := io.Copy(a, b)
		// Got EOF from b → no more data from remote. Tell client we're done
		// reading from us by half-closing if possible, but keep our read open.
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- halfResult{bytes: n, dir: "down", err: err}
	}()
	go func() {
		n, err := io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- halfResult{bytes: n, dir: "up", err: err}
	}()
	first := <-done
	second := <-done
	var up, down int64
	for _, r := range []halfResult{first, second} {
		if r.dir == "up" {
			up = r.bytes
		} else {
			down = r.bytes
		}
	}
	outlineLog("pipe closed: up=%d down=%d (first=%s err=%v)", up, down, first.dir, first.err)
}

// Reference syscall to avoid unused import in case future changes drop it.
var _ = syscall.SIGTERM
