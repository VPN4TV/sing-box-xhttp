package libbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// End to end, in one process: the real bridges against real servers, driven
// by sing-box's own SOCKS and UDP-over-TCP clients — what the socks outbounds
// of the apps do.

// freeDualPort finds a port free for both TCP and UDP on 127.0.0.1.
func freeDualPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		l.Close()
		if err == nil {
			u.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

func startUDPEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go servePacketEcho(c)
	return M.SocksaddrFromNet(c.LocalAddr())
}

func servePacketEcho(c net.PacketConn) {
	b := make([]byte, 65536)
	for {
		n, from, err := c.ReadFrom(b)
		if err != nil {
			return
		}
		_, _ = c.WriteTo(b[:n], from)
	}
}

func serveStreamEcho(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

// tcpRoundTrip checks a CONNECT through the bridge still carries TCP.
func tcpRoundTrip(t *testing.T, server M.Socksaddr, dest M.Socksaddr) {
	t.Helper()
	conn, err := singClient(server, "bridge", "pass-1234").DialContext(context.Background(), N.NetworkTCP, dest)
	if err != nil {
		t.Fatalf("tcp to %s: %v", dest, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("tcp through the bridge")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("tcp echo %q %v", reply, err)
	}
}

// udpSessions opens the three kinds of UDP session sing-box can open through
// a bridge: UDP over TCP connected and not, and UDP ASSOCIATE.
func udpSessions(t *testing.T, server M.Socksaddr, dest M.Socksaddr) map[string]packetClient {
	t.Helper()
	client := singClient(server, "bridge", "pass-1234")
	uotClient := &uot.Client{Dialer: client, Version: uot.Version}
	sessions := map[string]packetClient{}
	unconnected, err := uotClient.ListenPacket(context.Background(), dest)
	if err != nil {
		t.Fatalf("udp over tcp: %v", err)
	}
	sessions["udp over tcp"] = unconnected.(packetClient)
	connected, err := uotClient.DialContext(context.Background(), N.NetworkUDP, dest)
	if err != nil {
		t.Fatalf("udp over tcp, connected: %v", err)
	}
	sessions["udp over tcp, connected"] = connected.(packetClient)
	associated, err := client.ListenPacket(context.Background(), dest)
	if err != nil {
		t.Fatalf("udp associate: %v", err)
	}
	sessions["udp associate"] = associated.(packetClient)
	t.Cleanup(func() {
		unconnected.Close()
		connected.Close()
		associated.Close()
	})
	return sessions
}

// echoThrough sends datagrams of a few sizes to dest and expects each back
// from want.
func echoThrough(t *testing.T, name string, conn packetClient, dest, want M.Socksaddr) {
	t.Helper()
	for _, size := range []int{1, 512, 1200, 8000} {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		if _, err := conn.WriteTo(payload, dest); err != nil {
			t.Fatalf("%s: write %d bytes to %s: %v", name, size, dest, err)
		}
		buffer := buf.NewSize(16384)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		src, err := conn.ReadPacket(buffer)
		if err != nil {
			t.Fatalf("%s: %d bytes to %s: no answer: %v", name, size, dest, err)
		}
		if !bytes.Equal(buffer.Bytes(), payload) {
			t.Fatalf("%s: %d bytes to %s: answer differs (%d bytes)", name, size, dest, buffer.Len())
		}
		// A connected UDP-over-TCP session does not carry addresses.
		if !strings.HasSuffix(name, "connected") && src != want {
			t.Fatalf("%s: answer from %v, want %v", name, src, want)
		}
		buffer.Release()
	}
}

// ---- Outline ----

func startShadowsocksServer(t *testing.T, method, password string) int {
	t.Helper()
	port := freeDualPort(t)
	ctx := baseContext(nil)
	options, err := parseConfig(ctx, fmt.Sprintf(`{
		"log": {"level": "error"},
		"inbounds": [{"type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": %d, "method": %q, "password": %q}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`, port, method, password))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	return port
}

// An Outline key with a TLS-looking prefix: TCP goes with the prefix, UDP as
// plain Shadowsocks AEAD packets, and a Shadowsocks server that knows nothing
// about prefixes (sing-box's) takes both.
func TestOutlineBridgeUDPThroughShadowsocks(t *testing.T) {
	for _, method := range []string{"chacha20-ietf-poly1305", "aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			ssPort := startShadowsocksServer(t, method, "outline-secret")
			udpEcho := startUDPEcho(t)
			tcpEchoListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcpEchoListener.Close()
			go serveStreamEcho(tcpEchoListener)

			userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":outline-secret"))
			bridgePort := freePort(t)
			config, _ := json.Marshal(outlineConfig{Endpoints: []outlineEndpoint{{
				URL:      fmt.Sprintf("ss://%s@127.0.0.1:%d/?outline=1&prefix=%%16%%03%%01%%00%%C2%%A8%%01%%01#e2e", userInfo, ssPort),
				Port:     bridgePort,
				Listen:   "127.0.0.1",
				Username: "bridge",
				Password: "pass-1234",
			}}})
			if err := StartOutlineBridge(string(config)); err != nil {
				t.Fatal(err)
			}
			defer StopOutlineBridge()
			server := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort))

			tcpRoundTrip(t, server, M.SocksaddrFromNet(tcpEchoListener.Addr()))
			for name, conn := range udpSessions(t, server, udpEcho) {
				echoThrough(t, name, conn, udpEcho, udpEcho)
			}
		})
	}
}
