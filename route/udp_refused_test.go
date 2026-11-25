package route

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeOutbound struct {
	tag     string
	network []string
}

func (o *fakeOutbound) Type() string           { return "fake" }
func (o *fakeOutbound) Tag() string            { return o.tag }
func (o *fakeOutbound) Network() []string      { return o.network }
func (o *fakeOutbound) Dependencies() []string { return nil }
func (o *fakeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (o *fakeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// fakeSelector answers for the outbound it has chosen, as Selector does.
type fakeSelector struct {
	fakeOutbound
	manager *fakeManager
	now     string
}

func (s *fakeSelector) Now() string   { return s.now }
func (s *fakeSelector) All() []string { return nil }
func (s *fakeSelector) Network() []string {
	o, _ := s.manager.Outbound(s.now)
	return o.Network()
}

type fakeManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
	final     string
}

func (m *fakeManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}

func (m *fakeManager) Default() adapter.Outbound { return m.outbounds[m.final] }

type warnings struct {
	access sync.Mutex
	lines  []string
}

func (w *warnings) count() int {
	w.access.Lock()
	defer w.access.Unlock()
	return len(w.lines)
}

// warnLogger keeps the warnings, the rest goes nowhere.
type warnLogger struct {
	log.ContextLogger
	got *warnings
}

func (l warnLogger) Warn(args ...any) {
	var b strings.Builder
	for _, a := range args {
		b.WriteString(toString(a))
	}
	l.got.access.Lock()
	l.got.lines = append(l.got.lines, b.String())
	l.got.access.Unlock()
}

func toString(a any) string {
	if s, ok := a.(string); ok {
		return s
	}
	return "?"
}

func newRefusalRouter() (*Router, *fakeSelector, *warnings) {
	both := []string{N.NetworkTCP, N.NetworkUDP}
	manager := &fakeManager{outbounds: map[string]adapter.Outbound{}, final: "select"}
	selector := &fakeSelector{fakeOutbound: fakeOutbound{tag: "select"}, manager: manager, now: "auto"}
	for _, o := range []adapter.Outbound{
		&fakeOutbound{tag: "auto", network: both},
		&fakeOutbound{tag: "AL11", network: both},
		&fakeOutbound{tag: "AL11N", network: []string{N.NetworkTCP}},
		&fakeOutbound{tag: "direct", network: both},
		selector,
	} {
		manager.outbounds[o.Tag()] = o
	}
	got := &warnings{}
	return &Router{logger: warnLogger{ContextLogger: log.NewNOPFactory().Logger(), got: got}, outbound: manager}, selector, got
}

func flow(network string) *adapter.InboundContext {
	return &adapter.InboundContext{
		Network:     network,
		Source:      M.SocksaddrFrom(netip.MustParseAddr("172.19.0.1"), 40000),
		Destination: M.SocksaddrFrom(netip.MustParseAddr("142.250.0.1"), 443),
	}
}

func TestUDPForAServerWithoutUDPIsRefusedAtTheFirstLook(t *testing.T) {
	r, selector, got := newRefusalRouter()
	ctx := context.Background()
	verdict := func(network, outboundTag string) adapter.PreMatchAction {
		metadata := flow(network)
		return r.preMatchFlow(ctx, metadata, metadata.Destination, nil, outboundTag).Action
	}

	selector.now = "AL11N"
	if v := verdict(N.NetworkUDP, ""); v != adapter.PreMatchReject {
		t.Fatalf("UDP on the final with naive chosen: %v, want a rejection", v)
	}
	if v := verdict(N.NetworkUDP, "select"); v != adapter.PreMatchReject {
		t.Fatalf("UDP routed to select with naive chosen: %v, want a rejection", v)
	}
	if v := verdict(N.NetworkTCP, ""); v != adapter.PreMatchContinue {
		t.Fatalf("TCP with naive chosen: %v, want it to go on", v)
	}
	if v := verdict(N.NetworkUDP, "direct"); v != adapter.PreMatchContinue {
		t.Fatalf("UDP routed direct (Russia direct, torrents) with naive chosen: %v, want it to go on", v)
	}
	for _, chosen := range []string{"auto", "AL11"} {
		selector.now = chosen
		if v := verdict(N.NetworkUDP, ""); v != adapter.PreMatchContinue {
			t.Fatalf("UDP with %s chosen: %v, want it to go on", chosen, v)
		}
	}
	if n := got.count(); n != 1 {
		t.Fatalf("%d warnings for one chosen server, want 1: %q", n, got.lines)
	}
	if !strings.Contains(got.lines[0], "AL11N") {
		t.Fatalf("the warning does not name the chosen server: %q", got.lines[0])
	}
}

func TestTheRouterRejectsSuchUDPWithOneWarningPerServer(t *testing.T) {
	r, selector, got := newRefusalRouter()
	naive := r.outbound.Default()
	selector.now = "AL11N"
	for range 50 {
		err := r.refuseUDP(naive)
		if !R.IsRejected(err) {
			t.Fatalf("%v is not a rejection: the router would log it as an error", err)
		}
		if !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("unexpected error text %q", err.Error())
		}
	}
	if n := got.count(); n != 1 {
		t.Fatalf("%d warnings for 50 flows, want 1", n)
	}
	r.udpRefused.at = r.udpRefused.at.Add(-udpRefusedWarnEvery)
	_ = r.refuseUDP(naive)
	if n := got.count(); n != 2 {
		t.Fatalf("no warning again after %v: %d", udpRefusedWarnEvery, n)
	}
}
