package libbox

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTheBridgesWarningsAreKeptForTheReport(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	// A socks inbound, and an outbound to a port nothing listens on: every
	// connection through the bridge ends in a warning. The log level is
	// "error", as a release build could have it: warnings are kept anyway.
	config := `{"log":{"loglevel":"error","access":"none"},
	  "inbounds":[{"tag":"in","listen":"127.0.0.1","port":` + strconv.Itoa(port) + `,"protocol":"socks","settings":{"udp":false}}],
	  "outbounds":[{"tag":"out","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,
	    "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]}}]}`
	if err := StartXrayInstance(config); err != nil {
		t.Fatal(err)
	}
	defer StopXrayInstance()
	for range 3 {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// SOCKS5: no auth, then CONNECT example.com:80.
		conn.Write([]byte{5, 1, 0})
		reply := make([]byte, 2)
		conn.Read(reply)
		conn.Write(append([]byte{5, 1, 0, 3, 11}, append([]byte("example.com"), 0, 80)...))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		conn.Read(make([]byte, 64))
		conn.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(XrayProblems(), "2 more times") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	text := XrayProblems()
	t.Logf("kept:\n%s", text)
	if !strings.Contains(text, "more times") {
		t.Fatalf("the same failure of three connections is not one line: %q", text)
	}
	if strings.Count(text, "\n") < 2 || !strings.Contains(text, "started") {
		t.Fatalf("the start and the failed connections not kept: %q", text)
	}
	if strings.Count(text, "\n") > xrayProblemsKept {
		t.Fatalf("more than %d lines", xrayProblemsKept)
	}
	if err := StartXrayInstance(config); err != nil {
		t.Fatal(err)
	}
	// Xray writes its own start as a warning: that line alone.
	if got := XrayProblems(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "started") {
		t.Fatalf("a new start kept the last one's lines: %q", got)
	}
}

func TestARepeatIsCountedNotKept(t *testing.T) {
	l := &xrayProblemLog{}
	at := time.Date(2026, 11, 26, 17, 44, 9, 0, time.UTC)
	for i := range 5 {
		l.add(at.Add(time.Duration(i)*time.Second), "[Warning] dial tcp 203.0.113.1:443: i/o timeout")
	}
	l.add(at.Add(10*time.Second), "[Error] other")
	for i := range 100 {
		l.add(at, "[Warning] line "+strconv.Itoa(i))
	}
	l2 := &xrayProblemLog{}
	for i := range 5 {
		l2.add(at.Add(time.Duration(i)*time.Second), "[Warning] same")
	}
	if got := l2.text(); got != "17:44:09 [Warning] same (and 4 more times, the last at 17:44:13)\n" {
		t.Fatalf("%q", got)
	}
	if n := strings.Count(l.text(), "\n"); n != xrayProblemsKept {
		t.Fatalf("%d lines kept, want %d", n, xrayProblemsKept)
	}
}
