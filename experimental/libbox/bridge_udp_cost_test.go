package libbox

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

// What one open UDP session costs a bridge: heap, goroutine stacks,
// goroutines and descriptors, measured over costSessions sessions held open at
// once through the real bridges, the way sing-box's socks outbound opens them
// (UDP over TCP, one TCP connection per session, its client end in this same
// process as on a device).
//
// Skipped unless VPN4TV_BRIDGE_COST=1: it is a measurement, not a check.

const costSessions = 400

func costGate(t *testing.T) {
	t.Helper()
	if os.Getenv("VPN4TV_BRIDGE_COST") == "" {
		t.Skip("measurement: set VPN4TV_BRIDGE_COST=1")
	}
}

type costSnapshot struct {
	heap, stack uint64
	goroutines  int
	fds         int
}

func costMeasure() costSnapshot {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return costSnapshot{heap: m.HeapInuse, stack: m.StackInuse, goroutines: runtime.NumGoroutine(), fds: costOpenDescriptors()}
}

// costOpenDescriptors counts the open descriptors of the process.
func costOpenDescriptors() int {
	count := 0
	for fd := 0; fd < 1<<14; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			count++
		}
	}
	return count
}

func costReport(t *testing.T, name string, before, after costSnapshot, n int) {
	t.Helper()
	heap := float64(int64(after.heap)-int64(before.heap)) / float64(n) / 1024
	stack := float64(int64(after.stack)-int64(before.stack)) / float64(n) / 1024
	t.Logf("%s: %d open sessions: heap %+.1f MB, stacks %+.1f MB -> per session %.1f KB heap + %.1f KB stack = %.1f KB, %.2f goroutines, %.2f descriptors (the client end of each TCP connection included)",
		name, n,
		float64(int64(after.heap)-int64(before.heap))/1048576, float64(int64(after.stack)-int64(before.stack))/1048576,
		heap, stack, heap+stack,
		float64(after.goroutines-before.goroutines)/float64(n), float64(after.fds-before.fds)/float64(n))
	for _, sessions := range []float64{512, 4096, 16384} {
		t.Logf("%s:   %5.0f sessions would take about %.0f MB", name, sessions, (heap+stack)*sessions/1024)
	}
}

// costOpenSessions opens n sessions through server, one datagram echoed on
// each, and measures before and after.
func costOpenSessions(t *testing.T, name string, server, dest M.Socksaddr, n int) {
	t.Helper()
	payload := make([]byte, 1200)
	// Warm the pools so the first sessions do not pay for their creation.
	for i := 0; i < 4; i++ {
		if conn, raw, err := dialUoTRaw(server, dest); err == nil {
			_ = uotEcho(conn, dest, payload)
			raw.Close()
		}
	}
	time.Sleep(300 * time.Millisecond)
	before := costMeasure()
	raws := make([]net.Conn, 0, n)
	defer func() {
		for _, raw := range raws {
			raw.Close()
		}
	}()
	for i := 0; i < n; i++ {
		conn, raw, err := dialUoTRaw(server, dest)
		if err != nil {
			t.Fatalf("%s: session %d: %v", name, i, err)
		}
		raws = append(raws, raw)
		binary.BigEndian.PutUint32(payload, uint32(i))
		if err := uotEcho(conn, dest, payload); err != nil {
			t.Fatalf("%s: session %d: %v", name, i, err)
		}
	}
	after := costMeasure()
	costReport(t, name, before, after, n)
	for _, raw := range raws {
		raw.Close()
	}
	raws = nil
	time.Sleep(time.Second)
	closed := costMeasure()
	t.Logf("%s: after closing them: heap %+.1f MB vs before, goroutines %+d, descriptors %+d", name,
		float64(int64(closed.heap)-int64(before.heap))/1048576, closed.goroutines-before.goroutines, closed.fds-before.fds)
}

// costShadowsocksEcho is a stand-in Outline server: every datagram goes back
// to its sender as it came. A Shadowsocks client packet decrypts with the same
// key as a server one, so outline-sdk reads the echo as an answer from the
// target.
func costShadowsocksEcho(t *testing.T) int {
	t.Helper()
	port := freeDualPort(t)
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go servePacketEcho(u)
	return port
}

func TestBridgeUDPSessionCostOutline(t *testing.T) {
	costGate(t)
	ssPort := costShadowsocksEcho(t)
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:cost-secret"))
	bridgePort := freePort(t)
	config, _ := json.Marshal(outlineConfig{Endpoints: []outlineEndpoint{{
		URL:      "ss://" + userInfo + "@127.0.0.1:" + strconv.Itoa(ssPort) + "/?outline=1&prefix=%16%03%01#cost",
		Port:     bridgePort,
		Listen:   "127.0.0.1",
		Username: "bridge",
		Password: "pass-1234",
	}}})
	if err := StartOutlineBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopOutlineBridge()
	costOpenSessions(t, "outline", M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort)), M.ParseSocksaddrHostPort("1.2.3.4", 3478), costSessions)
}

func TestBridgeUDPSessionCostAmneziaWG(t *testing.T) {
	costGate(t)
	ini := startWireGuardServer(t)
	bridgePort := freePort(t)
	config, _ := json.Marshal(wireproxyConfig{Endpoints: []wireproxyEndpoint{{
		INI:      ini,
		Port:     bridgePort,
		Listen:   "127.0.0.1",
		Username: "bridge",
		Password: "pass-1234",
	}}})
	if err := StartWireproxyBridge(string(config)); err != nil {
		t.Fatal(err)
	}
	defer StopWireproxyBridge()
	costOpenSessions(t, "amneziawg", M.ParseSocksaddrHostPort("127.0.0.1", uint16(bridgePort)), M.ParseSocksaddrHostPort("10.77.0.1", 7), costSessions)
}
