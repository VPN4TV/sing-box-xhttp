package libbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// handshakeResult runs socks5Handshake on one end of a pipe while the test
// plays the client on the other.
func startHandshake(t *testing.T, auth *bridgeSocksAuth) (client net.Conn, result chan error, dest chan string) {
	t.Helper()
	server, client := net.Pipe()
	result = make(chan error, 1)
	dest = make(chan string, 1)
	go func() {
		defer server.Close()
		d, err := socks5Handshake(server, auth)
		dest <- d
		result <- err
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client, result, dest
}

func mustWrite(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func mustRead(t *testing.T, c net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func userPass(user, pass string) []byte {
	b := []byte{0x01, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

var connectDomain = []byte{0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB}

func TestSocksHandshakeWithoutAuthIsUnchanged(t *testing.T) {
	// Whatever the client offers, the no-auth inbound answers 0x00 — the
	// historical behaviour the desktop daemon and old profiles rely on.
	for _, methods := range [][]byte{{0x00}, {0x02}, {0x00, 0x02}} {
		client, result, dest := startHandshake(t, nil)
		mustWrite(t, client, append([]byte{0x05, byte(len(methods))}, methods...))
		mustRead(t, client, []byte{0x05, 0x00})
		mustWrite(t, client, connectDomain)
		if err := <-result; err != nil {
			t.Fatalf("methods % x: %v", methods, err)
		}
		if d := <-dest; d != "example.com:443" {
			t.Fatalf("dest %q", d)
		}
		client.Close()
	}
}

func TestSocksHandshakeRejectsClientWithoutPassword(t *testing.T) {
	client, result, _ := startHandshake(t, newBridgeSocksAuth("u", "p"))
	mustWrite(t, client, []byte{0x05, 0x01, 0x00})
	mustRead(t, client, []byte{0x05, 0xFF})
	if err := <-result; err == nil {
		t.Fatal("a client offering no authentication was let in")
	}
}

func TestSocksHandshakeRejectsWrongPassword(t *testing.T) {
	for _, creds := range [][2]string{{"u", "wrong"}, {"wrong", "p"}, {"", ""}} {
		client, result, _ := startHandshake(t, newBridgeSocksAuth("u", "p"))
		mustWrite(t, client, []byte{0x05, 0x02, 0x00, 0x02})
		mustRead(t, client, []byte{0x05, 0x02})
		mustWrite(t, client, userPass(creds[0], creds[1]))
		mustRead(t, client, []byte{0x01, 0x01})
		if err := <-result; err == nil {
			t.Fatalf("credentials %q accepted", creds)
		}
		client.Close()
	}
}

func TestSocksHandshakeAcceptsRightPassword(t *testing.T) {
	client, result, dest := startHandshake(t, newBridgeSocksAuth("user", "secret"))
	mustWrite(t, client, []byte{0x05, 0x01, 0x02})
	mustRead(t, client, []byte{0x05, 0x02})
	mustWrite(t, client, userPass("user", "secret"))
	mustRead(t, client, []byte{0x01, 0x00})
	mustWrite(t, client, []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50})
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if d := <-dest; d != "1.2.3.4:80" {
		t.Fatalf("dest %q", d)
	}
}

func TestSocksHandshakeServesConnectOnly(t *testing.T) {
	for _, auth := range []*bridgeSocksAuth{nil, newBridgeSocksAuth("u", "p")} {
		client, result, _ := startHandshake(t, auth)
		if auth == nil {
			mustWrite(t, client, []byte{0x05, 0x01, 0x00})
			mustRead(t, client, []byte{0x05, 0x00})
		} else {
			mustWrite(t, client, []byte{0x05, 0x01, 0x02})
			mustRead(t, client, []byte{0x05, 0x02})
			mustWrite(t, client, userPass("u", "p"))
			mustRead(t, client, []byte{0x01, 0x00})
		}
		// UDP ASSOCIATE used to be misread as CONNECT. Only the header goes
		// out: net.Pipe is synchronous and the bridge answers after reading it.
		mustWrite(t, client, []byte{0x05, 0x03, 0x00, 0x01})
		mustRead(t, client, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if err := <-result; err == nil {
			t.Fatal("UDP ASSOCIATE accepted")
		}
		client.Close()
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// probeBridge opens a connection to a bridge and runs the greeting: with no
// credentials it offers no-auth only, with credentials it authenticates.
// Returns the bytes the bridge answered with.
func probeBridge(t *testing.T, port int, user, pass string) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if user == "" {
		mustWrite(t, c, []byte{0x05, 0x01, 0x00})
		reply := make([]byte, 2)
		_, _ = io.ReadFull(c, reply)
		return reply
	}
	mustWrite(t, c, []byte{0x05, 0x01, 0x02})
	mustRead(t, c, []byte{0x05, 0x02})
	mustWrite(t, c, userPass(user, pass))
	reply := make([]byte, 2)
	_, _ = io.ReadFull(c, reply)
	return reply
}

// The JSON fields reach the inbound: a real outline bridge with credentials
// refuses a client without them and lets the right pair through.
func TestOutlineBridgeRequiresConfiguredPassword(t *testing.T) {
	port := freePort(t)
	config, _ := json.Marshal(outlineConfig{Endpoints: []outlineEndpoint{{
		URL:      "ss://YWVzLTI1Ni1nY206c2VjcmV0@127.0.0.1:1?prefix=%16%03%01#t",
		Port:     port,
		Listen:   "127.0.0.1",
		Username: "bridge",
		Password: "pass-1234",
	}}})
	if err := StartOutlineBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopOutlineBridge()
	if got := probeBridge(t, port, "", ""); !bytes.Equal(got, []byte{0x05, 0xFF}) {
		t.Fatalf("no-auth client got % x, want 05 ff", got)
	}
	if got := probeBridge(t, port, "bridge", "wrong"); !bytes.Equal(got, []byte{0x01, 0x01}) {
		t.Fatalf("wrong password got % x, want 01 01", got)
	}
	if got := probeBridge(t, port, "bridge", "pass-1234"); !bytes.Equal(got, []byte{0x01, 0x00}) {
		t.Fatalf("right password got % x, want 01 00", got)
	}
}

// Without credentials in the config the outline bridge is the old no-auth one.
func TestOutlineBridgeWithoutPasswordIsUnchanged(t *testing.T) {
	port := freePort(t)
	config, _ := json.Marshal(outlineConfig{Endpoints: []outlineEndpoint{{
		URL:    "ss://YWVzLTI1Ni1nY206c2VjcmV0@127.0.0.1:1?prefix=%16%03%01#t",
		Port:   port,
		Listen: "127.0.0.1",
	}}})
	if err := StartOutlineBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopOutlineBridge()
	if got := probeBridge(t, port, "", ""); !bytes.Equal(got, []byte{0x05, 0x00}) {
		t.Fatalf("no-auth client got % x, want 05 00", got)
	}
}

func TestWireproxyBridgeRequiresConfiguredPassword(t *testing.T) {
	port := freePort(t)
	config, _ := json.Marshal(wireproxyConfig{Endpoints: []wireproxyEndpoint{{
		INI:      awg31Config,
		Port:     port,
		Listen:   "127.0.0.1",
		Username: "bridge",
		Password: "pass-1234",
	}}})
	if err := StartWireproxyBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopWireproxyBridge()
	if got := probeBridge(t, port, "", ""); !bytes.Equal(got, []byte{0x05, 0xFF}) {
		t.Fatalf("no-auth client got % x, want 05 ff", got)
	}
	if got := probeBridge(t, port, "bridge", "pass-1234"); !bytes.Equal(got, []byte{0x01, 0x00}) {
		t.Fatalf("right password got % x, want 01 00", got)
	}
}
