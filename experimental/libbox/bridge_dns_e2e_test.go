package libbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// End to end: the real bridges with their servers given by name. The names
// are under .test, which no system resolver knows — a bridge that reaches its
// server found it through the DNS servers of its config.

// outlineKeyByName is an Outline key with a TLS-looking prefix for the
// Shadowsocks server on 127.0.0.1:port, by the given name.
func outlineKeyByName(name string, port int) string {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:outline-secret"))
	return fmt.Sprintf("ss://%s@%s/?outline=1&prefix=%%16%%03%%01#by-name", userInfo, net.JoinHostPort(name, strconv.Itoa(port)))
}

func TestOutlineBridgeFindsItsServerThroughConfigDNS(t *testing.T) {
	resetBridgeDNSCache(t)
	ssPort := startShadowsocksServer(t, "chacha20-ietf-poly1305", "outline-secret")
	dns := startFakeDNS(t)
	dns.set("outline-e2e.test.", "127.0.0.1")
	udpEcho := startUDPEcho(t)
	tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go serveStreamEcho(tcpEcho)

	bridgePort := freePort(t)
	config, _ := json.Marshal(outlineConfig{
		DNS: bridgeDNSServers{dns.addr()},
		Endpoints: []outlineEndpoint{{
			URL:      outlineKeyByName("outline-e2e.test", ssPort),
			Port:     bridgePort,
			Listen:   "127.0.0.1",
			Username: "bridge",
			Password: "pass-1234",
		}},
	})
	if err := StartOutlineBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopOutlineBridge()
	server := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort))

	tcpRoundTrip(t, server, M.SocksaddrFromNet(tcpEcho.Addr()))
	uotRoundTrip(t, server, udpEcho)
	if dns.countA("outline-e2e.test.") == 0 {
		t.Fatal("the config's DNS server was never asked")
	}
	log := OutlineLog().Value
	for _, want := range []string{"server names through DNS " + dns.addr(), "dns: outline-e2e.test is 127.0.0.1"} {
		if !strings.Contains(log, want) {
			t.Fatalf("bridge log lacks %q:\n%s", want, log)
		}
	}
}

// A dynamic key as the app hands it over: "dynamicUrl" next to the "url" it
// fetched. The bridge goes by url; the endpoint's own DNS servers replace the
// config's (here a silent one that would cost every connection 5 s).
func TestOutlineBridgeDynamicKeyThroughEndpointDNS(t *testing.T) {
	resetBridgeDNSCache(t)
	ssPort := startShadowsocksServer(t, "chacha20-ietf-poly1305", "outline-secret")
	silent, dns := startFakeDNS(t), startFakeDNS(t)
	silent.setSilent(true)
	dns.set("dynamic-e2e.test.", "127.0.0.1")
	udpEcho := startUDPEcho(t)
	bridgePort := freePort(t)
	config := fmt.Sprintf(`{
		"dns": [%q],
		"endpoints": [{
			"dynamicUrl": "https://keys.example.invalid/dynamic.json",
			"url": %q,
			"port": %d, "listen": "127.0.0.1", "username": "bridge", "password": "pass-1234",
			"dns": [%q]
		}]
	}`, silent.addr(), outlineKeyByName("dynamic-e2e.test", ssPort), bridgePort, dns.addr())
	if err := StartOutlineBridge(config); err != nil {
		t.Fatal(err)
	}
	defer StopOutlineBridge()
	start := time.Now()
	uotRoundTrip(t, M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort)), udpEcho)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("took %v: the config-wide servers were asked", elapsed)
	}
	if silent.countA("dynamic-e2e.test.") != 0 {
		t.Fatal("the config-wide server was asked although the endpoint has its own")
	}
}

// Without DNS servers the bridge asks the system resolver, as it always did —
// which knows nothing of .test.
func TestOutlineBridgeWithoutConfigDNSAsksTheSystem(t *testing.T) {
	resetBridgeDNSCache(t)
	ssPort := startShadowsocksServer(t, "chacha20-ietf-poly1305", "outline-secret")
	tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go serveStreamEcho(tcpEcho)
	bridgePort := freePort(t)
	config, _ := json.Marshal(outlineConfig{Endpoints: []outlineEndpoint{{
		URL:      outlineKeyByName("outline-nodns-e2e.test", ssPort),
		Port:     bridgePort,
		Listen:   "127.0.0.1",
		Username: "bridge",
		Password: "pass-1234",
	}}})
	if err := StartOutlineBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopOutlineBridge()
	conn, err := singClient(M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort)), "bridge", "pass-1234").
		DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFromNet(tcpEcho.Addr()))
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		_, err = conn.Write([]byte("x"))
		if err == nil {
			_, err = conn.Read(make([]byte, 1))
		}
		conn.Close()
	}
	if err == nil {
		t.Fatal("the server by name was reached without DNS servers")
	}
	log := OutlineLog().Value
	if strings.Contains(log, "dns: outline-nodns-e2e.test") || !strings.Contains(log, "outline-nodns-e2e.test") {
		t.Fatalf("expected a system resolver failure, not the bridge resolver:\n%s", log)
	}
}

// The AmneziaWG bridge with its peer endpoint by name.
func TestWireproxyBridgeFindsItsPeerThroughConfigDNS(t *testing.T) {
	resetBridgeDNSCache(t)
	ini := startWireGuardServer(t)
	if !strings.Contains(ini, "Endpoint = 127.0.0.1:") {
		t.Fatalf("unexpected INI:\n%s", ini)
	}
	ini = strings.Replace(ini, "Endpoint = 127.0.0.1:", "Endpoint = wg-e2e.test:", 1)
	dns := startFakeDNS(t)
	dns.set("wg-e2e.test.", "127.0.0.1")
	bridgePort := freePort(t)
	config, _ := json.Marshal(wireproxyConfig{
		DNS: bridgeDNSServers{dns.addr()},
		Endpoints: []wireproxyEndpoint{{
			INI:      ini,
			Port:     bridgePort,
			Listen:   "127.0.0.1",
			Username: "bridge",
			Password: "pass-1234",
		}},
	})
	if err := StartWireproxyBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopWireproxyBridge()
	server := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort))
	tcpRoundTrip(t, server, M.ParseSocksaddrHostPort("10.77.0.1", 80))
	uotRoundTrip(t, server, M.ParseSocksaddrHostPort("10.77.0.1", 7))
	if dns.countA("wg-e2e.test.") == 0 {
		t.Fatal("the config's DNS server was never asked")
	}
	if log := WireproxyLog().Value; !strings.Contains(log, "peer endpoint wg-e2e.test is 127.0.0.1") {
		t.Fatalf("bridge log:\n%s", log)
	}
}

// Without DNS servers the peer endpoint goes to the system resolver, as before:
// .test does not resolve, the start fails.
func TestWireproxyBridgeWithoutConfigDNSAsksTheSystem(t *testing.T) {
	resetBridgeDNSCache(t)
	ini := strings.Replace(startWireGuardServer(t), "Endpoint = 127.0.0.1:", "Endpoint = wg-nodns-e2e.test:", 1)
	config, _ := json.Marshal(wireproxyConfig{Endpoints: []wireproxyEndpoint{{
		INI:      ini,
		Port:     freePort(t),
		Listen:   "127.0.0.1",
		Username: "bridge",
		Password: "pass-1234",
	}}})
	done := make(chan error, 1)
	go func() { done <- StartWireproxyBridge(string(config)) }()
	select {
	case err := <-done:
		if err == nil {
			StopWireproxyBridge()
			t.Fatal("started with an endpoint nobody can resolve")
		}
		if !strings.Contains(err.Error(), "wg-nodns-e2e.test") || strings.Contains(err.Error(), "resolve peer endpoint") {
			t.Fatalf("expected the system resolver's failure: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the system resolver did not answer in 30 s")
	}
}

// Given DNS servers that do not know the name, the start fails with the name
// in the error — and never falls back to the system resolver.
func TestWireproxyBridgeFailsWhenConfigDNSCannotResolve(t *testing.T) {
	resetBridgeDNSCache(t)
	ini := strings.Replace(startWireGuardServer(t), "Endpoint = 127.0.0.1:", "Endpoint = wg-unknown-e2e.test:", 1)
	dns := startFakeDNS(t)
	config, _ := json.Marshal(wireproxyConfig{
		DNS: bridgeDNSServers{dns.addr()},
		Endpoints: []wireproxyEndpoint{{
			INI:      ini,
			Port:     freePort(t),
			Listen:   "127.0.0.1",
			Username: "bridge",
			Password: "pass-1234",
		}},
	})
	err := StartWireproxyBridge(string(config))
	if err == nil {
		StopWireproxyBridge()
		t.Fatal("started")
	}
	if !strings.Contains(err.Error(), "resolve peer endpoint wg-unknown-e2e.test") {
		t.Fatalf("error %v", err)
	}
	if dns.countA("wg-unknown-e2e.test.") == 0 {
		t.Fatal("the config's DNS server was not asked")
	}
}
