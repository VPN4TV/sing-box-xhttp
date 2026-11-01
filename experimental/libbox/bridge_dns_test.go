package libbox

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---- a DNS server for the tests ----

// fakeDNS answers A and AAAA questions on 127.0.0.1 from a table, and counts
// them.
type fakeDNS struct {
	conn net.PacketConn

	mu      sync.Mutex
	names   map[string][]netip.Addr // "name." → addresses
	rcode   dnsmessage.RCode        // non-zero: every answer carries it
	silent  bool                    // answers nothing
	queries map[string]int          // "name. TYPE" → questions seen
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDNS{conn: conn, names: map[string][]netip.Addr{}, queries: map[string]int{}}
	t.Cleanup(func() { conn.Close() })
	go d.serve()
	return d
}

func (d *fakeDNS) addr() string { return d.conn.LocalAddr().String() }

func (d *fakeDNS) set(name string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	list := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		list = append(list, netip.MustParseAddr(addr))
	}
	d.names[name] = list
}

func (d *fakeDNS) setSilent(silent bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.silent = silent
}

func (d *fakeDNS) setRCode(rcode dnsmessage.RCode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rcode = rcode
}

// countA is how many A questions for name came in.
func (d *fakeDNS) countA(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[name+" "+dnsmessage.TypeA.String()]
}

func (d *fakeDNS) serve() {
	b := make([]byte, 1500)
	for {
		n, from, err := d.conn.ReadFrom(b)
		if err != nil {
			return
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(b[:n])
		if err != nil {
			continue
		}
		question, err := parser.Question()
		if err != nil {
			continue
		}
		name := question.Name.String()
		d.mu.Lock()
		d.queries[name+" "+question.Type.String()]++
		silent, rcode, addrs, known := d.silent, d.rcode, d.names[name], false
		if _, ok := d.names[name]; ok {
			known = true
		}
		d.mu.Unlock()
		if silent {
			continue
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID: header.ID, Response: true, Authoritative: true, RecursionAvailable: true, RCode: rcode,
			},
			Questions: []dnsmessage.Question{question},
		}
		if rcode == 0 {
			if !known {
				response.RCode = dnsmessage.RCodeNameError
			}
			for _, addr := range addrs {
				resource := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
				switch {
				case question.Type == dnsmessage.TypeA && addr.Is4():
					resource.Type = dnsmessage.TypeA
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: resource, Body: &dnsmessage.AResource{A: addr.As4()}})
				case question.Type == dnsmessage.TypeAAAA && addr.Is6():
					resource.Type = dnsmessage.TypeAAAA
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: resource, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}})
				}
			}
		}
		packed, err := response.Pack()
		if err == nil {
			_, _ = d.conn.WriteTo(packed, from)
		}
	}
}

// resetBridgeDNSCache forgets every answer, so a test starts from nothing.
func resetBridgeDNSCache(t *testing.T) {
	t.Helper()
	bridgeDNSCache.Lock()
	clear(bridgeDNSCache.entries)
	bridgeDNSCache.Unlock()
}

// setBridgeDNSTimes shortens how long answers and failures are kept, for the
// test only. Under the cache lock: lookup reads them there.
func setBridgeDNSTimes(t *testing.T, fresh, negative time.Duration) {
	t.Helper()
	bridgeDNSCache.Lock()
	oldFresh, oldNegative := bridgeDNSFresh, bridgeDNSNegative
	bridgeDNSFresh, bridgeDNSNegative = fresh, negative
	bridgeDNSCache.Unlock()
	t.Cleanup(func() {
		bridgeDNSCache.Lock()
		bridgeDNSFresh, bridgeDNSNegative = oldFresh, oldNegative
		bridgeDNSCache.Unlock()
	})
}

func lookupString(t *testing.T, r *bridgeResolver, host string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.lookup(ctx, host)
	if err != nil {
		t.Fatalf("lookup %s: %v", host, err)
	}
	return joinAddrs(addrs)
}

// ---- the field ----

func TestBridgeDNSServerParsing(t *testing.T) {
	good := map[string]string{
		"9.9.9.9":           "9.9.9.9:53",
		" 9.9.9.9:5353 ":    "9.9.9.9:5353",
		"2620:fe::fe":       "[2620:fe::fe]:53",
		"[2620:fe::fe]:853": "[2620:fe::fe]:853",
		"::ffff:1.2.3.4":    "1.2.3.4:53",
	}
	for value, want := range good {
		server, err := parseBridgeDNSServer(value)
		if err != nil || server.String() != want {
			t.Errorf("%q: %v %v, want %s", value, server, err, want)
		}
	}
	for _, value := range []string{"", "dns.google", "dns.google:53", "1.2.3.4:0", "0.0.0.0", "[::]:53", "1.2.3.4:99999", "1.2.3", "42", "[2620:fe::fe]"} {
		if server, err := parseBridgeDNSServer(value); err == nil {
			t.Errorf("%q accepted as %v", value, server)
		}
	}
}

// The field takes a list or a single string, top level and per endpoint; the
// endpoint's list replaces the top-level one; anything malformed costs only
// the field, with a line in the log, never the bridge.
func TestBridgeDNSFieldForms(t *testing.T) {
	var outline outlineConfig
	if err := json.Unmarshal([]byte(`{
		"dns": "9.9.9.9",
		"endpoints": [
			{"url": "ss://a", "port": 1, "dns": ["1.1.1.1", "8.8.8.8:53"]},
			{"url": "ss://b", "port": 2},
			{"url": "ss://c", "port": 3, "dns": 42},
			{"url": "ss://d", "port": 4, "dns": null, "dynamicUrl": "https://example.com/key"},
			{"url": "ss://e", "port": 5, "dns": ["dns.google", "149.112.112.112"]}
		]
	}`), &outline); err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53, 8.8.8.8:53", "9.9.9.9:53", "", "9.9.9.9:53", "149.112.112.112:53"}
	for i, endpoint := range outline.Endpoints {
		log := &testLog{}
		resolver := newBridgeResolver(pickBridgeDNS(endpoint.DNS, outline.DNS), log.logf)
		got := ""
		if resolver != nil {
			got = resolver.String()
		}
		if got != want[i] {
			t.Errorf("endpoint %d: servers %q, want %q (log %q)", i, got, want[i], log.text())
		}
		switch i {
		case 2:
			if !strings.Contains(log.text(), `"42" is not an IP address`) || !strings.Contains(log.text(), "no usable server") {
				t.Errorf("endpoint 2: log %q", log.text())
			}
		case 4:
			if !strings.Contains(log.text(), `"dns.google" is not an IP address, skipped`) {
				t.Errorf("endpoint 4: log %q", log.text())
			}
		}
	}

	var wireproxy wireproxyConfig
	if err := json.Unmarshal([]byte(`{"endpoints": [{"ini": "x", "port": 1, "dns": "[2620:fe::fe]:53"}, {"ini": "y", "port": 2}]}`), &wireproxy); err != nil {
		t.Fatal(err)
	}
	if r := newBridgeResolver(pickBridgeDNS(wireproxy.Endpoints[0].DNS, wireproxy.DNS), (&testLog{}).logf); r == nil || r.String() != "[2620:fe::fe]:53" {
		t.Errorf("wireproxy endpoint 0: %v", r)
	}
	// What older apps send: no field, the system resolver, nothing logged.
	log := &testLog{}
	if r := newBridgeResolver(pickBridgeDNS(wireproxy.Endpoints[1].DNS, wireproxy.DNS), log.logf); r != nil || log.text() != "" {
		t.Errorf("no dns field: resolver %v, log %q", r, log.text())
	}
}

// ---- lookups ----

func TestBridgeResolverAsksItsServersAndKeepsTheAnswer(t *testing.T) {
	resetBridgeDNSCache(t)
	dns := startFakeDNS(t)
	dns.set("srv.bridge.test.", "192.0.2.10", "2001:db8::10")
	log := &testLog{}
	r := newBridgeResolver(bridgeDNSServers{dns.addr()}, log.logf)
	if got := lookupString(t, r, "srv.bridge.test"); got != "192.0.2.10, 2001:db8::10" && got != "2001:db8::10, 192.0.2.10" {
		t.Fatalf("addresses %q", got)
	}
	asked := dns.countA("srv.bridge.test.")
	if asked != 1 {
		t.Fatalf("%d A questions, want 1", asked)
	}
	// Kept: no new question, in any case, with or without the final dot.
	for _, host := range []string{"srv.bridge.test", "SRV.Bridge.test.", "srv.bridge.test"} {
		lookupString(t, r, host)
	}
	if n := dns.countA("srv.bridge.test."); n != asked {
		t.Fatalf("asked again: %d A questions", n)
	}
	waitFor(t, func() bool { return strings.Contains(log.text(), "dns: srv.bridge.test is ") }, log)
}

// Callers that come while a name is being asked wait for that one question.
func TestBridgeResolverSharesOneQuestion(t *testing.T) {
	resetBridgeDNSCache(t)
	dns := startFakeDNS(t)
	dns.set("shared.bridge.test.", "192.0.2.20")
	r := newBridgeResolver(bridgeDNSServers{dns.addr()}, (&testLog{}).logf)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := r.lookup(context.Background(), "shared.bridge.test")
			if err == nil && joinAddrs(addrs) != "192.0.2.20" {
				err = &net.AddrError{Err: "wrong answer", Addr: joinAddrs(addrs)}
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := dns.countA("shared.bridge.test."); n != 1 {
		t.Fatalf("%d A questions for 32 callers, want 1", n)
	}
}

// An old answer is handed out at once and refreshed behind the caller's back;
// when the refresh fails the old answer stays.
func TestBridgeResolverRefreshesInTheBackgroundAndKeepsOldAnswers(t *testing.T) {
	resetBridgeDNSCache(t)
	setBridgeDNSTimes(t, 100*time.Millisecond, time.Minute)
	dns := startFakeDNS(t)
	dns.set("moving.bridge.test.", "192.0.2.1")
	log := &testLog{}
	r := newBridgeResolver(bridgeDNSServers{dns.addr()}, log.logf)
	if got := lookupString(t, r, "moving.bridge.test"); got != "192.0.2.1" {
		t.Fatalf("first answer %q", got)
	}
	time.Sleep(150 * time.Millisecond)
	dns.set("moving.bridge.test.", "192.0.2.2")
	// Stale: the old address now, the new one once the refresh is in.
	if got := lookupString(t, r, "moving.bridge.test"); got != "192.0.2.1" {
		t.Fatalf("stale answer %q, want the old address at once", got)
	}
	waitFor(t, func() bool { return lookupString(t, r, "moving.bridge.test") == "192.0.2.2" }, log)

	// The servers fail: the last answer stays in use.
	time.Sleep(150 * time.Millisecond)
	dns.setRCode(dnsmessage.RCodeServerFailure)
	if got := lookupString(t, r, "moving.bridge.test"); got != "192.0.2.2" {
		t.Fatalf("answer %q while the servers fail", got)
	}
	waitFor(t, func() bool { return strings.Contains(log.text(), "keeping 192.0.2.2") }, log)
	if got := lookupString(t, r, "moving.bridge.test"); got != "192.0.2.2" {
		t.Fatalf("answer %q after a failed refresh", got)
	}
}

// A name that did not resolve is not asked again for bridgeDNSNegative:
// connections in the meantime fail at once instead of waiting.
func TestBridgeResolverRemembersFailures(t *testing.T) {
	resetBridgeDNSCache(t)
	setBridgeDNSTimes(t, time.Minute, 300*time.Millisecond)
	dns := startFakeDNS(t)
	log := &testLog{}
	r := newBridgeResolver(bridgeDNSServers{dns.addr()}, log.logf)
	if _, err := r.lookup(context.Background(), "late.bridge.test"); err == nil {
		t.Fatal("an unknown name resolved")
	}
	asked := dns.countA("late.bridge.test.")
	if asked == 0 {
		t.Fatal("the server was not asked")
	}
	start := time.Now()
	if _, err := r.lookup(context.Background(), "late.bridge.test"); err == nil {
		t.Fatal("resolved on the second try")
	}
	if n := dns.countA("late.bridge.test."); n != asked || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("asked again at once (%d questions, %v)", n, time.Since(start))
	}
	dns.set("late.bridge.test.", "192.0.2.30")
	time.Sleep(350 * time.Millisecond)
	if got := lookupString(t, r, "late.bridge.test"); got != "192.0.2.30" {
		t.Fatalf("after the pause: %q", got)
	}
}

// A server that stays silent gets company after bridgeDNSStagger; the next
// one answers.
func TestBridgeResolverAsksTheNextServerAfterSilence(t *testing.T) {
	resetBridgeDNSCache(t)
	silent, good := startFakeDNS(t), startFakeDNS(t)
	silent.setSilent(true)
	good.set("quiet.bridge.test.", "192.0.2.40")
	r := newBridgeResolver(bridgeDNSServers{silent.addr(), good.addr()}, (&testLog{}).logf)
	start := time.Now()
	if got := lookupString(t, r, "quiet.bridge.test"); got != "192.0.2.40" {
		t.Fatalf("answer %q", got)
	}
	elapsed := time.Since(start)
	if elapsed < bridgeDNSStagger*9/10 || elapsed > bridgeDNSStagger+2*time.Second {
		t.Fatalf("answered after %v, want about %v", elapsed, bridgeDNSStagger)
	}
	if silent.countA("quiet.bridge.test.") == 0 {
		t.Fatal("the first server was not asked")
	}
}

// A server that fails outright hands over at once.
func TestBridgeResolverAsksTheNextServerAfterAnError(t *testing.T) {
	resetBridgeDNSCache(t)
	failing, good := startFakeDNS(t), startFakeDNS(t)
	failing.setRCode(dnsmessage.RCodeServerFailure)
	good.set("broken.bridge.test.", "192.0.2.50")
	r := newBridgeResolver(bridgeDNSServers{failing.addr(), good.addr()}, (&testLog{}).logf)
	start := time.Now()
	if got := lookupString(t, r, "broken.bridge.test"); got != "192.0.2.50" {
		t.Fatalf("answer %q", got)
	}
	if elapsed := time.Since(start); elapsed > bridgeDNSStagger/2 {
		t.Fatalf("answered after %v: the failure did not hand over at once", elapsed)
	}
}

func TestBridgeResolverFailsWhenEveryServerFails(t *testing.T) {
	resetBridgeDNSCache(t)
	first, second := startFakeDNS(t), startFakeDNS(t)
	first.setRCode(dnsmessage.RCodeServerFailure)
	second.setRCode(dnsmessage.RCodeRefused)
	log := &testLog{}
	r := newBridgeResolver(bridgeDNSServers{first.addr(), second.addr()}, log.logf)
	_, err := r.lookup(context.Background(), "nowhere.bridge.test")
	if err == nil {
		t.Fatal("resolved")
	}
	if !strings.Contains(err.Error(), second.addr()) {
		t.Fatalf("error %q does not name the last server", err)
	}
	waitFor(t, func() bool { return strings.Contains(log.text(), "dns: nowhere.bridge.test: ") }, log)
}

// Every socket the resolver opens goes through its control hook, which is the
// bridges' protect call (bridgeControl) unless a test watches it.
func TestBridgeResolverSocketsGoThroughControl(t *testing.T) {
	resetBridgeDNSCache(t)
	dns := startFakeDNS(t)
	dns.set("guarded.bridge.test.", "192.0.2.60")
	r := newBridgeResolver(bridgeDNSServers{dns.addr()}, (&testLog{}).logf)
	if reflect.ValueOf(r.control).Pointer() != reflect.ValueOf(bridgeControl).Pointer() {
		t.Fatal("the resolver does not protect its sockets with bridgeControl")
	}
	var mu sync.Mutex
	var seen []string
	r.control = func(network, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, network+" "+address)
		return nil
	}
	lookupString(t, r, "guarded.bridge.test")
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no socket went through the control hook")
	}
	for _, s := range seen {
		if !strings.HasPrefix(s, "udp") || !strings.HasSuffix(s, " "+dns.addr()) {
			t.Fatalf("socket %q, want UDP to %s only", s, dns.addr())
		}
	}
}

func TestBridgeOrderAddrsPutsIPv4First(t *testing.T) {
	in := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("192.0.2.2")}
	if got := joinAddrs(orderAddrs(in)); got != "192.0.2.1, 192.0.2.2, 2001:db8::1, 2001:db8::2" {
		t.Fatalf("order %q", got)
	}
}

// dial tries the addresses of a name in turn: here the IPv4 one refuses, the
// IPv6 one answers. An address literal is dialled without a question.
func TestBridgeResolverDialTriesAddressesInTurn(t *testing.T) {
	resetBridgeDNSCache(t)
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	// Nothing on the IPv4 side of that port, or the test means nothing.
	if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		c.Close()
		t.Skip("the port is taken on IPv4 too")
	}
	dns := startFakeDNS(t)
	dns.set("both.bridge.test.", "127.0.0.1", "::1")
	r := newBridgeResolver(bridgeDNSServers{dns.addr()}, (&testLog{}).logf)
	conn, err := r.dial(context.Background(), &net.Dialer{}, "tcp", net.JoinHostPort("both.bridge.test", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	if remote := conn.RemoteAddr().(*net.TCPAddr); !remote.IP.Equal(net.IPv6loopback) {
		t.Fatalf("connected to %v", remote)
	}
	conn.Close()
	asked := dns.countA("both.bridge.test.")
	conn, err = r.dial(context.Background(), &net.Dialer{}, "tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if dns.countA("both.bridge.test.") != asked {
		t.Fatal("an address literal was looked up")
	}
}
