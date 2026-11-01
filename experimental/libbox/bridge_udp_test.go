package libbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

// ---- SOCKS5 UDP header ----

func TestSocks5UDPHeaderVectors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		dest M.Socksaddr
	}{
		{
			"ipv4",
			[]byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x35},
			M.ParseSocksaddrHostPort("1.2.3.4", 53),
		},
		{
			"ipv6",
			[]byte{0, 0, 0, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB},
			M.ParseSocksaddrHostPort("2001:db8::1", 443),
		},
		{
			"domain",
			append(append([]byte{0, 0, 0, 0x03, 11}, "example.com"...), 0x00, 0x50),
			M.ParseSocksaddrHostPort("example.com", 80),
		},
	}
	for _, c := range cases {
		datagram := append(append([]byte{}, c.raw...), "payload"...)
		dest, payload, err := parseSocks5UDP(datagram)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if dest != c.dest || string(payload) != "payload" {
			t.Fatalf("%s: got %v %q", c.name, dest, payload)
		}
		if built := appendSocks5UDP(nil, c.dest, []byte("payload")); !bytes.Equal(built, datagram) {
			t.Fatalf("%s: built % x, want % x", c.name, built, datagram)
		}
		if n := socks5UDPHeaderLen(c.dest); n != len(c.raw) {
			t.Fatalf("%s: header length %d, want %d", c.name, n, len(c.raw))
		}
	}
}

func TestSocks5UDPHeaderNormalizesAddresses(t *testing.T) {
	// An IPv4-mapped IPv6 address is the IPv4 address; a name that is an IP
	// literal is that IP.
	mapped := []byte{0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 9, 8, 7, 6, 0x00, 0x35}
	dest, _, err := parseSocks5UDP(mapped)
	if err != nil || dest != M.ParseSocksaddrHostPort("9.8.7.6", 53) {
		t.Fatalf("mapped: %v %v", dest, err)
	}
	literal := append(append([]byte{0, 0, 0, 0x03, 8}, "10.0.0.1"...), 0x00, 0x35)
	dest, _, err = parseSocks5UDP(literal)
	if err != nil || !dest.IsIP() || dest.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("literal: %v %v", dest, err)
	}
	// Writing a mapped source gives an IPv4 header.
	built := appendSocks5UDP(nil, M.SocksaddrFrom(netip.MustParseAddr("::ffff:9.8.7.6"), 53), nil)
	if !bytes.Equal(built, []byte{0, 0, 0, 0x01, 9, 8, 7, 6, 0x00, 0x35}) {
		t.Fatalf("mapped source built % x", built)
	}
}

func TestSocks5UDPHeaderRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"short":           {0, 0, 0},
		"fragment":        {0, 0, 1, 0x01, 1, 2, 3, 4, 0x00, 0x35},
		"last fragment":   {0, 0, 0x81, 0x01, 1, 2, 3, 4, 0x00, 0x35},
		"unknown atyp":    {0, 0, 0, 0x05, 1, 2, 3, 4, 0x00, 0x35},
		"short ipv4":      {0, 0, 0, 0x01, 1, 2, 3, 4, 0x00},
		"short ipv6":      {0, 0, 0, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x00},
		"no domain len":   {0, 0, 0, 0x03},
		"empty domain":    {0, 0, 0, 0x03, 0, 0x00, 0x35},
		"short domain":    {0, 0, 0, 0x03, 5, 'a', 'b', 0x00, 0x35},
		"port zero":       {0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x00},
		"domain port 0":   append(append([]byte{0, 0, 0, 0x03, 1}, 'a'), 0, 0),
		"truncated port":  append(append([]byte{0, 0, 0, 0x03, 1}, 'a'), 0),
		"header only rsv": {0xff, 0xff},
	}
	for name, raw := range cases {
		if _, _, err := parseSocks5UDP(raw); err == nil {
			t.Errorf("%s: % x accepted", name, raw)
		}
	}
	if _, _, err := parseSocks5UDP([]byte{0, 0, 1, 0x01, 1, 2, 3, 4, 0x00, 0x35}); !errors.Is(err, errSocks5UDPFragment) {
		t.Errorf("fragment: %v", err)
	}
	longest := M.ParseSocksaddrHostPort(strings.Repeat("a", 255), 1)
	if n := socks5UDPHeaderLen(longest); n != socks5UDPMaxHeader {
		t.Errorf("255-byte name: header %d, want %d", n, socks5UDPMaxHeader)
	}
	if n := socks5UDPHeaderLen(M.ParseSocksaddrHostPort(strings.Repeat("a", 256), 1)); n != 0 {
		t.Errorf("256-byte name: header %d, want 0 (cannot be written)", n)
	}
	if n := socks5UDPHeaderLen(M.Socksaddr{}); n != 0 {
		t.Errorf("no address: header %d", n)
	}
}

// The header is the one sing-box's SOCKS client writes and reads.
func TestSocks5UDPHeaderMatchesSingBox(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	socket, err := net.DialUDP("udp4", nil, relay.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = relay.SetDeadline(time.Now().Add(5 * time.Second))
	_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
	client := socks.NewAssociatePacketConn(socket, M.Socksaddr{}, nil)
	raw := make([]byte, 2048)
	for _, dest := range testDestinations {
		// sing-box → us
		if _, err := client.WriteTo([]byte("ping"), dest); err != nil {
			t.Fatal(err)
		}
		n, from, err := relay.ReadFromUDP(raw)
		if err != nil {
			t.Fatal(err)
		}
		got, payload, err := parseSocks5UDP(raw[:n])
		if err != nil || got != dest || string(payload) != "ping" {
			t.Fatalf("sing-box wrote %v, we read %v %q %v", dest, got, payload, err)
		}
		// us → sing-box
		if _, err := relay.WriteToUDP(appendSocks5UDP(nil, dest, []byte("pong")), from); err != nil {
			t.Fatal(err)
		}
		buffer := buf.NewSize(2048)
		src, err := client.ReadPacket(buffer)
		if err != nil || src != dest || string(buffer.Bytes()) != "pong" {
			t.Fatalf("we wrote %v, sing-box read %v %q %v", dest, src, buffer.Bytes(), err)
		}
		buffer.Release()
	}
}

// ---- a bridge with a fake upstream ----

// echoUpstream answers every datagram with the same payload, from the address
// it was sent to.
type echoUpstream struct {
	mu       sync.Mutex
	sessions int
	closed   chan struct{}
}

func newEchoUpstream() *echoUpstream { return &echoUpstream{closed: make(chan struct{}, 64)} }

func (e *echoUpstream) open(_ context.Context, handler bridgePacketHandler) (bridgePacketSession, error) {
	e.mu.Lock()
	e.sessions++
	e.mu.Unlock()
	return &echoSession{handler: handler, upstream: e}, nil
}

func (e *echoUpstream) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions
}

func (e *echoUpstream) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-e.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream session was not closed")
	}
}

type echoSession struct {
	handler  bridgePacketHandler
	upstream *echoUpstream
	mu       sync.Mutex
	closed   bool
}

func (s *echoSession) WriteTo(p []byte, dest M.Socksaddr) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	b := make([]byte, socks5UDPMaxHeader+len(p))
	copy(b[socks5UDPMaxHeader:], p)
	s.handler.handlePacket(b, socks5UDPMaxHeader, dest)
	return nil
}

func (s *echoSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.upstream.closed <- struct{}{}
	}
	return nil
}

type testLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func (l *testLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// startTestBridge serves the bridge SOCKS handler on 127.0.0.1 with the given
// packet path and UDP ASSOCIATE allowed; CONNECT to anything else is refused.
func startTestBridge(t *testing.T, auth *bridgeSocksAuth, opener bridgePacketOpener) (M.Socksaddr, *testLog) {
	t.Helper()
	return startTestBridgeUDP(t, auth, &bridgeUDP{open: opener, associate: true})
}

// startTestBridgeUDP is startTestBridge with the UDP side as given; what the
// bridge logs goes to the returned testLog.
func startTestBridgeUDP(t *testing.T, auth *bridgeSocksAuth, udp *bridgeUDP) (M.Socksaddr, *testLog) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	log := &testLog{}
	udp.logf = log.logf
	if udp.sessions != nil {
		udp.sessions.logf = log.logf
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				request, err := socks5Handshake(c, auth, udp.associateAllowed())
				if err != nil {
					log.logf("handshake: %v", err)
					return
				}
				if !serveBridgeUDP(c, request, udp) {
					_ = writeSocks5Reply(c, socks5ReplyGeneralFailure, netip.AddrPort{})
				}
			}()
		}
	}()
	return M.SocksaddrFromNet(ln.Addr()), log
}

var testAuth = newBridgeSocksAuth("bridge", "pass-1234")

func singClient(server M.Socksaddr, user, pass string) *socks.Client {
	return socks.NewClient(N.SystemDialer, server, socks.Version5, user, pass)
}

var testDestinations = []M.Socksaddr{
	M.ParseSocksaddrHostPort("1.2.3.4", 53),
	M.ParseSocksaddrHostPort("2001:db8::1", 443),
	M.ParseSocksaddrHostPort("example.com", 3478),
}

// packetClient is the client side of a UDP session as sing-box holds it (the
// association or the UDP-over-TCP stream).
type packetClient interface {
	WriteTo(p []byte, addr net.Addr) (int, error)
	ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error)
	SetReadDeadline(t time.Time) error
}

// roundTrip sends one datagram per destination and expects it echoed from
// that destination.
func roundTrip(t *testing.T, conn packetClient, destinations []M.Socksaddr) {
	t.Helper()
	for i, dest := range destinations {
		payload := []byte(fmt.Sprintf("datagram %d to %s", i, dest))
		if _, err := conn.WriteTo(payload, dest); err != nil {
			t.Fatalf("write to %s: %v", dest, err)
		}
		buffer := buf.NewSize(4096)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		src, err := conn.ReadPacket(buffer)
		if err != nil {
			t.Fatalf("read after %s: %v", dest, err)
		}
		if !bytes.Equal(buffer.Bytes(), payload) {
			t.Fatalf("got %q, want %q", buffer.Bytes(), payload)
		}
		if src != dest {
			t.Fatalf("reply from %v, want %v", src, dest)
		}
		buffer.Release()
	}
}

// ---- UDP ASSOCIATE ----

// What sing-box's socks outbound does without udp_over_tcp: UDP ASSOCIATE with
// the password, then datagrams from its own socket.
func TestBridgeUDPAssociateWithSingBoxClient(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	conn, err := singClient(server, "bridge", "pass-1234").ListenPacket(context.Background(), testDestinations[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn.(packetClient), testDestinations)
	conn.Close()
	upstream.waitClosed(t)
}

func TestBridgeUDPAssociateRequiresPassword(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	for _, creds := range [][2]string{{"", ""}, {"bridge", "wrong"}, {"other", "pass-1234"}} {
		if conn, err := singClient(server, creds[0], creds[1]).ListenPacket(context.Background(), testDestinations[0]); err == nil {
			conn.Close()
			t.Fatalf("credentials %q got an association", creds)
		}
	}
	if upstream.count() != 0 {
		t.Fatal("an upstream session was opened without the password")
	}
}

// associate runs the handshake and UDP ASSOCIATE by hand, naming requested as
// the client address; it returns the control connection and the relay.
func associate(t *testing.T, server M.Socksaddr, requested []byte) (net.Conn, *net.UDPAddr) {
	t.Helper()
	control, err := net.DialTimeout("tcp", server.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	mustWrite(t, control, []byte{0x05, 0x01, 0x02})
	mustRead(t, control, []byte{0x05, 0x02})
	mustWrite(t, control, userPass("bridge", "pass-1234"))
	mustRead(t, control, []byte{0x01, 0x00})
	mustWrite(t, control, append([]byte{0x05, 0x03, 0x00}, requested...))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 || reply[3] != 0x01 {
		t.Fatalf("reply % x", reply)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
	if !relay.IP.IsLoopback() || relay.Port == 0 {
		t.Fatalf("relay %v", relay)
	}
	_ = control.SetDeadline(time.Time{})
	return control, relay
}

var anyAddress = []byte{0x01, 0, 0, 0, 0, 0, 0}

func loopbackSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sendAndWait sends one datagram from c to the relay and reports whether the
// echo came back.
func sendAndWait(t *testing.T, c *net.UDPConn, relay *net.UDPAddr, datagram []byte) bool {
	t.Helper()
	if _, err := c.WriteToUDP(datagram, relay); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	reply := make([]byte, 4096)
	n, from, err := c.ReadFromUDP(reply)
	if err != nil {
		return false
	}
	if from.Port != relay.Port || !from.IP.Equal(relay.IP) {
		t.Fatalf("reply from %v, relay is %v", from, relay)
	}
	dest, payload, err := parseSocks5UDP(reply[:n])
	if err != nil {
		t.Fatalf("reply % x: %v", reply[:n], err)
	}
	sent, sentPayload, _ := parseSocks5UDP(datagram)
	if dest != sent || !bytes.Equal(payload, sentPayload) {
		t.Fatalf("echo %v %q for %v %q", dest, payload, sent, sentPayload)
	}
	return true
}

func portBytes(c *net.UDPConn) []byte {
	port := c.LocalAddr().(*net.UDPAddr).Port
	return []byte{byte(port >> 8), byte(port)}
}

var echoDatagram = appendSocks5UDP(nil, M.ParseSocksaddrHostPort("1.2.3.4", 53), []byte("hello"))

// No address in the request: the first loopback source that sends a
// well-formed datagram owns the association, the rest are dropped silently.
func TestBridgeUDPAssociateBindsFirstSource(t *testing.T) {
	upstream := newEchoUpstream()
	server, log := startTestBridge(t, testAuth, upstream.open)
	control, relay := associate(t, server, anyAddress)
	first, second := loopbackSocket(t), loopbackSocket(t)
	// A fragment does not claim the association.
	fragment := append([]byte{}, echoDatagram...)
	fragment[2] = 1
	if sendAndWait(t, second, relay, fragment) {
		t.Fatal("a fragment was relayed")
	}
	if !sendAndWait(t, first, relay, echoDatagram) {
		t.Fatal("the first source got no answer")
	}
	if sendAndWait(t, second, relay, echoDatagram) {
		t.Fatal("a second source was relayed")
	}
	if !sendAndWait(t, first, relay, echoDatagram) {
		t.Fatal("the first source lost the association")
	}
	control.Close()
	upstream.waitClosed(t)
	waitFor(t, func() bool { return strings.Contains(log.text(), "foreign=1 malformed=1") }, log)
}

// A concrete loopback address in the request is the only source accepted.
func TestBridgeUDPAssociateRequestedSource(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	owner, other := loopbackSocket(t), loopbackSocket(t)
	_, relay := associate(t, server, append([]byte{0x01, 127, 0, 0, 1}, portBytes(owner)...))
	if sendAndWait(t, other, relay, echoDatagram) {
		t.Fatal("a source other than the requested one was relayed")
	}
	if !sendAndWait(t, owner, relay, echoDatagram) {
		t.Fatal("the requested source got no answer")
	}
}

// An unspecified address with a port pins the port.
func TestBridgeUDPAssociateRequestedPort(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	owner, other := loopbackSocket(t), loopbackSocket(t)
	_, relay := associate(t, server, append([]byte{0x01, 0, 0, 0, 0}, portBytes(owner)...))
	if sendAndWait(t, other, relay, echoDatagram) {
		t.Fatal("a source on another port was relayed")
	}
	if !sendAndWait(t, owner, relay, echoDatagram) {
		t.Fatal("the requested port got no answer")
	}
}

// A non-loopback address in the request is not the client's (sing-box and
// others put the destination there): the first loopback source still wins.
func TestBridgeUDPAssociateIgnoresForeignRequestAddress(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	_, relay := associate(t, server, []byte{0x01, 8, 8, 8, 8, 0x00, 0x35})
	if !sendAndWait(t, loopbackSocket(t), relay, echoDatagram) {
		t.Fatal("no answer")
	}
}

// The association ends with its control connection: the relay goes away and
// the upstream session is closed.
func TestBridgeUDPAssociateEndsWithControlConnection(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	control, relay := associate(t, server, anyAddress)
	client := loopbackSocket(t)
	if !sendAndWait(t, client, relay, echoDatagram) {
		t.Fatal("no answer")
	}
	control.Close()
	upstream.waitClosed(t)
	if sendAndWait(t, client, relay, echoDatagram) {
		t.Fatal("relayed after the control connection closed")
	}
	// The relay port is closed, not just silent: a fresh socket on it works.
	waitFor(t, func() bool {
		c, err := net.ListenUDP("udp4", relay)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, nil)
}

// An association nothing crosses ends on its own, and the server closes the
// control connection.
func TestBridgeUDPAssociateIdleTimeout(t *testing.T) {
	bridgeUDPIdleOverride.Store(int64(200 * time.Millisecond))
	defer bridgeUDPIdleOverride.Store(0)
	upstream := newEchoUpstream()
	server, log := startTestBridge(t, testAuth, upstream.open)
	control, relay := associate(t, server, anyAddress)
	if !sendAndWait(t, loopbackSocket(t), relay, echoDatagram) {
		t.Fatal("no answer")
	}
	upstream.waitClosed(t)
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("control connection still open: %v", err)
	}
	waitFor(t, func() bool { return strings.Contains(log.text(), "(idle)") }, log)
}

// A bridge without a packet path refuses both kinds of UDP request.
func TestBridgeUDPRefusedWithoutPacketPath(t *testing.T) {
	server, _ := startTestBridge(t, testAuth, nil)
	client := singClient(server, "bridge", "pass-1234")
	if conn, err := client.ListenPacket(context.Background(), testDestinations[0]); err == nil {
		conn.Close()
		t.Fatal("UDP ASSOCIATE accepted")
	}
	uotClient := &uot.Client{Dialer: client, Version: uot.Version}
	conn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, testDestinations[0])
	if err == nil {
		// The CONNECT reply is read lazily, with the first datagram.
		_, err = conn.Write([]byte("x"))
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = conn.Read(make([]byte, 16))
		}
		conn.Close()
	}
	if err == nil {
		t.Fatal("UDP over TCP accepted")
	}
}

// ---- UDP over TCP ----

func TestBridgeUDPOverTCPConnected(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	uotClient := &uot.Client{Dialer: singClient(server, "bridge", "pass-1234"), Version: uot.Version}
	for _, dest := range testDestinations {
		conn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, dest)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			payload := []byte(fmt.Sprintf("connected %d to %s", i, dest))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			reply := make([]byte, 4096)
			n, err := conn.Read(reply)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reply[:n], payload) {
				t.Fatalf("got %q, want %q", reply[:n], payload)
			}
		}
		conn.Close()
		upstream.waitClosed(t)
	}
}

func TestBridgeUDPOverTCPUnconnected(t *testing.T) {
	for _, version := range []uint8{uot.Version, uot.LegacyVersion} {
		upstream := newEchoUpstream()
		server, _ := startTestBridge(t, testAuth, upstream.open)
		uotClient := &uot.Client{Dialer: singClient(server, "bridge", "pass-1234"), Version: version}
		conn, err := uotClient.ListenPacket(context.Background(), testDestinations[0])
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, conn.(packetClient), testDestinations)
		conn.Close()
		upstream.waitClosed(t)
	}
}

func TestBridgeUDPOverTCPRequiresPassword(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	for _, creds := range [][2]string{{"", ""}, {"bridge", "wrong"}} {
		uotClient := &uot.Client{Dialer: singClient(server, creds[0], creds[1]), Version: uot.Version}
		if conn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, testDestinations[0]); err == nil {
			conn.Close()
			t.Fatalf("credentials %q got through", creds)
		}
	}
	if upstream.count() != 0 {
		t.Fatal("an upstream session was opened without the password")
	}
}

// The no-auth inbound (desktop, old profiles) serves UDP the same way.
func TestBridgeUDPWithoutAuth(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, nil, upstream.open)
	uotClient := &uot.Client{Dialer: singClient(server, "", ""), Version: uot.Version}
	conn, err := uotClient.ListenPacket(context.Background(), testDestinations[0])
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn.(packetClient), testDestinations[:1])
	conn.Close()
}

func TestBridgeUDPOverTCPIdleTimeout(t *testing.T) {
	bridgeUDPIdleOverride.Store(int64(200 * time.Millisecond))
	defer bridgeUDPIdleOverride.Store(0)
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	uotClient := &uot.Client{Dialer: singClient(server, "bridge", "pass-1234"), Version: uot.Version}
	conn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, testDestinations[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("once")); err != nil {
		t.Fatal(err)
	}
	upstream.waitClosed(t)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 64)
	if n, err := conn.Read(reply); err != nil || string(reply[:n]) != "once" {
		t.Fatalf("echo: %q %v", reply[:n], err)
	}
	if _, err := conn.Read(reply); err == nil || isTimeout(err) {
		t.Fatalf("stream still open after the idle timeout: %v", err)
	}
}

// ---- helpers ----

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func waitFor(t *testing.T, condition func() bool, log *testLog) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			if log != nil {
				t.Fatalf("condition not met; log:\n%s", log.text())
			}
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---- raw UDP-over-TCP sessions ----

// dialUoTRaw opens an unconnected UDP-over-TCP session (the version 2 request)
// by hand — greeting, password, CONNECT to the magic name, the request — the
// way sing-box's socks outbound with udp_over_tcp does, and reports a refused
// CONNECT as an error.
func dialUoTRaw(server, dest M.Socksaddr) (*uot.Conn, net.Conn, error) {
	c, err := net.DialTimeout("tcp", server.String(), 3*time.Second)
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	hello := append([]byte{0x05, 0x01, 0x02}, userPass("bridge", "pass-1234")...)
	connect := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(uot.MagicAddress))}, uot.MagicAddress...)
	connect = append(connect, 0, 0)
	if _, err := c.Write(append(hello, connect...)); err != nil {
		c.Close()
		return nil, nil, err
	}
	reply := make([]byte, 2+2+10)
	if _, err := io.ReadFull(c, reply); err != nil {
		c.Close()
		return nil, nil, err
	}
	if reply[2+2+1] != socks5ReplySucceeded {
		c.Close()
		return nil, nil, fmt.Errorf("CONNECT refused: % x", reply)
	}
	request := uot.Request{Destination: dest}
	if err := uot.WriteRequest(c, request); err != nil {
		c.Close()
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return uot.NewConn(c, request), c, nil
}

// uotEcho sends payload to dest and expects it back.
func uotEcho(conn *uot.Conn, dest M.Socksaddr, payload []byte) error {
	if _, err := conn.WriteTo(payload, dest); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	b := make([]byte, 65536)
	n, _, err := conn.ReadFrom(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(b[:n], payload) {
		return fmt.Errorf("echo of %d bytes differs (%d bytes back)", len(payload), n)
	}
	return nil
}

// ---- UDP ASSOCIATE is off unless asked for ----

// An endpoint that did not ask for UDP ASSOCIATE refuses it with 0x07 — after
// the password, like everything else — and still serves UDP over TCP.
func TestBridgeUDPAssociateOffByDefault(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridgeUDP(t, testAuth, &bridgeUDP{open: upstream.open})
	control, err := net.DialTimeout("tcp", server.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	mustWrite(t, control, []byte{0x05, 0x01, 0x02})
	mustRead(t, control, []byte{0x05, 0x02})
	mustWrite(t, control, userPass("bridge", "pass-1234"))
	mustRead(t, control, []byte{0x01, 0x00})
	mustWrite(t, control, append([]byte{0x05, 0x03, 0x00}, anyAddress...))
	mustRead(t, control, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	if conn, err := singClient(server, "bridge", "pass-1234").ListenPacket(context.Background(), testDestinations[0]); err == nil {
		conn.Close()
		t.Fatal("sing-box's client got an association")
	}
	uotClient := &uot.Client{Dialer: singClient(server, "bridge", "pass-1234"), Version: uot.Version}
	conn, err := uotClient.ListenPacket(context.Background(), testDestinations[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn.(packetClient), testDestinations)
	if n := upstream.count(); n != 1 {
		t.Fatalf("%d upstream sessions, want the UDP-over-TCP one only", n)
	}
}

// ---- the cap on sessions ----

func TestBridgeUDPCapRefusesWhenEverySessionIsBusy(t *testing.T) {
	bridgeUDPMaxOverride.Store(2)
	defer bridgeUDPMaxOverride.Store(0)
	upstream := newEchoUpstream()
	server, log := startTestBridgeUDP(t, testAuth, &bridgeUDP{open: upstream.open, sessions: newBridgeUDPSessions(nil)})
	dest := testDestinations[0]
	var raws []net.Conn
	defer func() {
		for _, raw := range raws {
			raw.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		conn, raw, err := dialUoTRaw(server, dest)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		raws = append(raws, raw)
		if err := uotEcho(conn, dest, []byte("busy")); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	if _, raw, err := dialUoTRaw(server, dest); err == nil {
		raw.Close()
		t.Fatal("a third session got in while both were busy")
	} else if !strings.Contains(err.Error(), "CONNECT refused: 05 02 01 00 05 01") {
		t.Fatalf("third session: %v", err)
	}
	waitFor(t, func() bool {
		return strings.Contains(log.text(), "udp: 2 sessions at once, the limit of this bridge: closed 0 idle for newer ones, refused 1")
	}, log)
	if n := upstream.count(); n != 2 {
		t.Fatalf("%d upstream sessions opened, want 2", n)
	}
	// One goes: there is room again.
	raws[0].Close()
	upstream.waitClosed(t)
	waitFor(t, func() bool {
		conn, raw, err := dialUoTRaw(server, dest)
		if err != nil {
			return false
		}
		raws = append(raws, raw)
		return uotEcho(conn, dest, []byte("room")) == nil
	}, log)
}

func TestBridgeUDPCapMakesRoomFromTheLongestIdle(t *testing.T) {
	bridgeUDPMaxOverride.Store(2)
	bridgeUDPEvictOverride.Store(int64(150 * time.Millisecond))
	defer bridgeUDPMaxOverride.Store(0)
	defer bridgeUDPEvictOverride.Store(0)
	upstream := newEchoUpstream()
	server, log := startTestBridgeUDP(t, testAuth, &bridgeUDP{open: upstream.open, sessions: newBridgeUDPSessions(nil)})
	dest := testDestinations[0]
	idle, idleRaw, err := dialUoTRaw(server, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer idleRaw.Close()
	busy, busyRaw, err := dialUoTRaw(server, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer busyRaw.Close()
	for _, conn := range []*uot.Conn{idle, busy} {
		if err := uotEcho(conn, dest, []byte("first")); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if err := uotEcho(busy, dest, []byte("still here")); err != nil {
		t.Fatal(err)
	}
	newer, newerRaw, err := dialUoTRaw(server, dest)
	if err != nil {
		t.Fatalf("the newer session was refused: %v", err)
	}
	defer newerRaw.Close()
	// The idle one was closed for it; the busy one was not.
	_ = idleRaw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := idleRaw.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the idle session is still open: %v", err)
	}
	for _, conn := range []*uot.Conn{busy, newer} {
		if err := uotEcho(conn, dest, []byte("after")); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool {
		text := log.text()
		return strings.Contains(text, "closed 1 idle for newer ones, refused 0") && strings.Contains(text, "(closed for a newer session)")
	}, log)
}

// ---- what a session holds ----

// Datagrams of any size cross a UDP-over-TCP session intact, whether they fit
// the stream's own buffer or get one for themselves, in any order.
func TestBridgeUDPOverTCPDatagramSizes(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	uotClient := &uot.Client{Dialer: singClient(server, "bridge", "pass-1234"), Version: uot.Version}
	conn, err := uotClient.ListenPacket(context.Background(), testDestinations[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := conn.(packetClient)
	for _, size := range []int{1, 0, uotReaderSize - 1, uotReaderSize, uotReaderSize + 1, 9000, 65535, 3, 20000, 1200} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i*7 + size)
		}
		dest := testDestinations[size%len(testDestinations)]
		if _, err := client.WriteTo(payload, dest); err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		buffer := buf.NewSize(65535)
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		src, err := client.ReadPacket(buffer)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if !bytes.Equal(buffer.Bytes(), payload) || src != dest {
			t.Fatalf("%d bytes to %v: got %d bytes from %v", size, dest, buffer.Len(), src)
		}
		buffer.Release()
	}
}

// A session that waits holds no goroutine for its idle timeout: with an
// upstream that has no reader of its own, the connection's goroutine is all a
// session has.
func TestBridgeUDPSessionsHoldNoIdleGoroutine(t *testing.T) {
	upstream := newEchoUpstream()
	server, _ := startTestBridge(t, testAuth, upstream.open)
	dest := testDestinations[0]
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	const n = 50
	var raws []net.Conn
	defer func() {
		for _, raw := range raws {
			raw.Close()
		}
	}()
	for i := 0; i < n; i++ {
		conn, raw, err := dialUoTRaw(server, dest)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
		if err := uotEcho(conn, dest, []byte("hold")); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if delta := runtime.NumGoroutine() - before; delta > n+5 {
		t.Fatalf("%d goroutines for %d waiting sessions, want about one each", delta, n)
	}
}

func TestAwgMaxDatagram(t *testing.T) {
	for mtu, want := range map[int]int{1420: 8192, 1280: 8192, 0: 8192, 4000: 16000, 20000: 65535} {
		if got := awgMaxDatagram(mtu); got != want {
			t.Errorf("MTU %d: %d, want %d", mtu, got, want)
		}
	}
}
