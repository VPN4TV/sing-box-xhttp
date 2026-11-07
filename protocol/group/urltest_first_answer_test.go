package group

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// probeOutbound answers the URL test's HEAD request after delay; a negative
// delay is a server that cannot be reached. With startAfter its probe starts
// that much later without counting it: the dial waits, and the connection asks
// for a handshake first, which restarts the URL test's clock.
type probeOutbound struct {
	tag        string
	delay      atomic.Int64
	startAfter time.Duration
}

type handshakeConn struct{ net.Conn }

func (handshakeConn) NeedHandshakeForWrite() bool { return true }

func newProbeOutbound(tag string, delay time.Duration) *probeOutbound {
	o := &probeOutbound{tag: tag}
	o.delay.Store(int64(delay))
	return o
}

func (o *probeOutbound) Type() string           { return "probe" }
func (o *probeOutbound) Tag() string            { return o.tag }
func (o *probeOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *probeOutbound) Dependencies() []string { return nil }

func (o *probeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.startAfter > 0 {
		select {
		case <-time.After(o.startAfter):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	delay := time.Duration(o.delay.Load())
	if delay < 0 {
		return nil, errors.New("unreachable")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
	}()
	if o.startAfter > 0 {
		return handshakeConn{client}, nil
	}
	return client, nil
}

func (o *probeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no UDP")
}

type probeManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *probeManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}

func selectedTag(g *URLTestGroup) string {
	if o := g.loadSelectedTCP(); o != nil {
		return o.Tag()
	}
	return ""
}

// The first round picks the first server that answers at once and the best
// one when the round ends; a later round keeps the pick until it ends.
func TestURLTestFirstAnswerThenBest(t *testing.T) {
	first := newProbeOutbound("first", 100*time.Millisecond)
	// "late" answers after "first" (at about 220 ms) and is the fastest of all,
	// like a server probed in a later batch of ten.
	late := newProbeOutbound("late", 20*time.Millisecond)
	late.startAfter = 200 * time.Millisecond
	outbounds := []adapter.Outbound{first}
	// Ten members in all: every probe starts at once (ten run at a time).
	for _, tag := range []string{"slow1", "slow2", "slow3", "slow4", "slow5", "slow6", "slow7"} {
		outbounds = append(outbounds, newProbeOutbound(tag, 900*time.Millisecond))
	}
	outbounds = append(outbounds, late, newProbeOutbound("down", -1))
	manager := &probeManager{outbounds: make(map[string]adapter.Outbound)}
	for _, o := range outbounds {
		manager.outbounds[o.Tag()] = o
	}
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	g, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), outbounds, "http://probe.test/generate_204", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	round := func() chan struct{} {
		done := make(chan struct{})
		go func() {
			_, _ = g.urlTest(ctx, true)
			close(done)
		}()
		return done
	}

	done := round()
	time.Sleep(400 * time.Millisecond)
	if got := selectedTag(g); got != "first" {
		t.Fatalf("first round, before its end: selected %q, want the first answer %q", got, "first")
	}
	<-done
	if got := selectedTag(g); got != "late" {
		t.Fatalf("first round, after its end: selected %q, want the best %q", got, "late")
	}

	late.delay.Store(int64(600 * time.Millisecond))
	first.delay.Store(int64(30 * time.Millisecond))
	done = round()
	time.Sleep(300 * time.Millisecond)
	if got := selectedTag(g); got != "late" {
		t.Fatalf("second round, before its end: selected %q, want the pick kept %q", got, "late")
	}
	<-done
	if got := selectedTag(g); got != "first" {
		t.Fatalf("second round, after its end: selected %q, want the best %q", got, "first")
	}
}

// A round where nothing answers leaves the group on its first outbound; the
// first answer of a later round is then picked at once, as in a first round.
func TestURLTestFirstAnswerAfterSilentRound(t *testing.T) {
	down := newProbeOutbound("down", -1)
	back := newProbeOutbound("back", -1)
	slow := newProbeOutbound("slow", -1)
	outbounds := []adapter.Outbound{down, back, slow}
	manager := &probeManager{outbounds: map[string]adapter.Outbound{"down": down, "back": back, "slow": slow}}
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	g, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), outbounds, "http://probe.test/generate_204", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = g.urlTest(ctx, true)
	if got := selectedTag(g); got != "down" {
		t.Fatalf("silent round: selected %q, want the first outbound %q", got, "down")
	}

	back.delay.Store(int64(50 * time.Millisecond))
	slow.delay.Store(int64(600 * time.Millisecond))
	done := make(chan struct{})
	go func() {
		_, _ = g.urlTest(ctx, true)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	if got := selectedTag(g); got != "back" {
		t.Fatalf("next round, before its end: selected %q, want the first answer %q", got, "back")
	}
	<-done
	if got := selectedTag(g); got != "back" {
		t.Fatalf("next round, after its end: selected %q, want the best %q", got, "back")
	}
}
