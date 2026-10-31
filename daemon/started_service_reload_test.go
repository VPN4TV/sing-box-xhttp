package daemon

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	_ "github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/group"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testGateType is an outbound that holds an instance in the middle of its
// start. The profile's urltest group lists it, so the group starts only after
// the gate's Start returns, and a test can see the service while an instance
// sits there with a group that has not started.
const testGateType = "test-gate"

type testGateOptions struct {
	Gate      string   `json:"gate,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
}

type testGateOutbound struct {
	outbound.Adapter
	ctx      context.Context
	gate     string
	hold     func(ctx context.Context, gate string) error
	finished atomic.Bool
}

func (h *testGateOutbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		if h.gate != "" {
			return h.hold(h.ctx, h.gate)
		}
	case adapter.StartStateStarted:
		h.finished.Store(true)
	}
	return nil
}

func (h *testGateOutbound) Close() error {
	return nil
}

func (h *testGateOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, E.New("test outbound does not dial")
}

func (h *testGateOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("test outbound does not dial")
}

func newGateTestContext(hold func(ctx context.Context, gate string) error, created func(*testGateOutbound)) context.Context {
	outboundRegistry := outbound.NewRegistry()
	group.RegisterSelector(outboundRegistry)
	group.RegisterURLTest(outboundRegistry)
	outbound.Register[testGateOptions](outboundRegistry, testGateType, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options testGateOptions) (adapter.Outbound, error) {
		gateOutbound := &testGateOutbound{
			Adapter: outbound.NewAdapter(testGateType, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DependsOn),
			ctx:     ctx,
			gate:    options.Gate,
			hold:    hold,
		}
		if created != nil {
			created(gateOutbound)
		}
		return gateOutbound, nil
	})
	dnsTransportRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsTransportRegistry)
	return box.Context(context.Background(), inbound.NewRegistry(), outboundRegistry, endpoint.NewRegistry(), dnsTransportRegistry, boxService.NewRegistry(), certificate.NewRegistry())
}

// gateTestProfile: a selector over a urltest group whose first member is the
// gate, and "last", which depends on both groups and records the end of the
// start. The urltest link goes nowhere and the interval is long: nothing here
// dials.
func gateTestProfile(cachePath string, gate string) string {
	return fmt.Sprintf(`{
	"log": {"disabled": true},
	"experimental": {"cache_file": {"enabled": true, "path": %[1]q}},
	"outbounds": [
		{"type": "selector", "tag": "select", "outbounds": ["auto", "gate"]},
		{"type": "urltest", "tag": "auto", "outbounds": ["gate", "spare"], "url": "http://127.0.0.1:1/", "interval": "1h", "idle_timeout": "2h"},
		{"type": %[3]q, "tag": "gate", "gate": %[2]q},
		{"type": %[3]q, "tag": "spare"},
		{"type": %[3]q, "tag": "last", "depends_on": ["select", "auto"]}
	]
}`, cachePath, gate, testGateType)
}

func serviceState(s *StartedService) (ServiceStatus_Type, *Instance) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	return s.serviceStatus.Status, s.instance
}

func instanceGateOutbound(instance *Instance, tag string) *testGateOutbound {
	if instance == nil {
		return nil
	}
	it, loaded := instance.outboundManager.Outbound(tag)
	if !loaded {
		return nil
	}
	gateOutbound, _ := it.(*testGateOutbound)
	return gateOutbound
}

// finishedStarting reports whether the instance got through its whole start:
// "last" depends on both groups and records the final start stage.
func finishedStarting(instance *Instance) bool {
	last := instanceGateOutbound(instance, "last")
	return last != nil && last.finished.Load()
}

// readGroupsRecovered calls readGroups the way SubscribeGroups does, under the
// read lock, and returns a panic instead of crashing the test binary.
func readGroupsRecovered(s *StartedService) (groups *Groups, panicValue any) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	defer func() {
		panicValue = recover()
	}()
	return s.readGroups(), nil
}

func urlTestStarted(urlTest *group.URLTest) (started bool) {
	defer func() {
		if recover() != nil {
			started = false
		}
	}()
	_, _ = urlTest.URLTest(context.Background())
	return true
}

func requireURLTestGroupsStarted(t *testing.T, instance *Instance) {
	t.Helper()
	var urlTests int
	for _, it := range instance.outboundManager.Outbounds() {
		if urlTest, isURLTest := it.(*group.URLTest); isURLTest {
			urlTests++
			require.True(t, urlTestStarted(urlTest), "urltest group %s has not started", urlTest.Tag())
		}
	}
	require.NotZero(t, urlTests)
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Minute):
		t.Fatal("timed out waiting for ", what)
	}
}

func waitResult(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Minute):
		t.Fatal("timed out waiting for ", what)
		return nil
	}
}

type testGate struct {
	entered     chan struct{}
	release     chan struct{}
	failOnClose bool
}

func newTestGate(failOnClose bool) *testGate {
	return &testGate{
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
		failOnClose: failOnClose,
	}
}

// TestStartOrReloadSupersededStart: a StartOrReloadService that arrives while
// another one is still starting closes that instance and starts its own (or a
// CloseService closes it and a new start follows). When the first start
// returns afterwards, finished anyway or failed on the close, the service has
// to stay with the second instance: still starting, neither STARTED with the
// second instance's urltest group not started yet (readGroups -> URLTest.Now
// crashed on that in SubscribeGroups) nor FATAL with the second instance
// dropped while it runs.
func TestStartOrReloadSupersededStart(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		failOnClose bool
		closeFirst  bool
	}{
		{name: "reload, superseded start finishes"},
		{name: "reload, superseded start fails on the close", failOnClose: true},
		{name: "close and start, superseded start finishes", closeFirst: true},
		{name: "close and start, superseded start fails on the close", failOnClose: true, closeFirst: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testSupersededStart(t, testCase.failOnClose, testCase.closeFirst)
		})
	}
}

func testSupersededStart(t *testing.T, failOnClose bool, closeFirst bool) {
	gates := map[string]*testGate{
		"first":  newTestGate(failOnClose),
		"second": newTestGate(false),
	}
	ctx := newGateTestContext(func(ctx context.Context, name string) error {
		gate := gates[name]
		close(gate.entered)
		<-gate.release
		if gate.failOnClose {
			return ctx.Err()
		}
		return nil
	}, nil)
	s := NewStartedService(ServiceOptions{Context: ctx, LogMaxLines: 16})
	defer s.Close()
	dir := t.TempDir()
	start := func(name string) <-chan error {
		done := make(chan error, 1)
		go func() {
			done <- s.StartOrReloadService(context.Background(), gateTestProfile(filepath.Join(dir, name+".db"), name), nil)
		}()
		return done
	}

	firstDone := start("first")
	waitClosed(t, gates["first"].entered, "the first start to reach its gate")
	_, first := serviceState(s)
	require.NotNil(t, first)
	if closeFirst {
		require.NoError(t, s.CloseService())
		status, instance := serviceState(s)
		require.Equal(t, ServiceStatus_IDLE.String(), status.String())
		require.Nil(t, instance)
	}
	secondDone := start("second")
	waitClosed(t, gates["second"].entered, "the second start to reach its gate")
	_, second := serviceState(s)
	require.NotNil(t, second)
	require.NotSame(t, first, second)
	require.Error(t, first.ctx.Err(), "the first instance has not been closed")

	close(gates["first"].release)
	firstErr := waitResult(t, firstDone, "the first start to return")
	status, instance := serviceState(s)
	assert.Equal(t, ServiceStatus_STARTING.String(), status.String(), "status after the superseded start returned")
	assert.Same(t, second, instance, "instance after the superseded start returned")
	if instance != nil {
		// What SubscribeGroups reads once the status says STARTED: here the
		// urltest group of the instance has not started yet.
		groups, panicValue := readGroupsRecovered(s)
		assert.Nil(t, panicValue, "readGroups on an instance whose urltest group has not started")
		if groups != nil {
			for _, it := range groups.Group {
				if it.Tag == "auto" {
					assert.Empty(t, it.Selected, "selected outbound of a urltest group that has not started")
				}
			}
		}
	}

	close(gates["second"].release)
	secondErr := waitResult(t, secondDone, "the second start to return")
	assert.NoError(t, firstErr, "a start superseded by another must not report an error")
	require.NoError(t, secondErr)
	status, instance = serviceState(s)
	require.Equal(t, ServiceStatus_STARTED.String(), status.String())
	require.Same(t, second, instance)
	require.True(t, finishedStarting(instance))
	requireURLTestGroupsStarted(t, instance)
	groups, panicValue := readGroupsRecovered(s)
	require.Nil(t, panicValue)
	require.Len(t, groups.Group, 2)

	require.NoError(t, s.CloseService())
	status, instance = serviceState(s)
	require.Equal(t, ServiceStatus_IDLE.String(), status.String())
	require.Nil(t, instance)
	require.Error(t, second.ctx.Err())
}

// reloadScheduler runs the starts of the overlapping reloads in
// TestStartOrReloadOverlappingReloads one at a time. Every instance parks at
// its gate; a reload may begin, and a parked start may go on, only while no
// start code runs elsewhere. A reload therefore closes an instance only while
// that instance is parked, so the instances never race inside the box (a
// Close concurrent with a running Start is a separate problem), and what the
// test varies is the order in which reloads come in and parked starts come
// back: the bookkeeping StartOrReloadService does after Start.
type reloadScheduler struct {
	access  sync.Mutex
	changed *sync.Cond
	running int
	calls   map[string]*reloadCall
	parked  []*reloadCall
	done    bool
}

type reloadCall struct {
	running bool
	release chan bool
}

func (r *reloadScheduler) begin(name string) *reloadCall {
	call := &reloadCall{running: true, release: make(chan bool, 1)}
	r.access.Lock()
	defer r.access.Unlock()
	for r.running > 0 {
		r.changed.Wait()
	}
	r.running++
	r.calls[name] = call
	return call
}

func (r *reloadScheduler) end(call *reloadCall) {
	r.access.Lock()
	defer r.access.Unlock()
	if call.running {
		call.running = false
		r.running--
		r.changed.Broadcast()
	}
}

func (r *reloadScheduler) hold(ctx context.Context, name string) error {
	r.access.Lock()
	call := r.calls[name]
	call.running = false
	r.running--
	r.parked = append(r.parked, call)
	r.changed.Broadcast()
	r.access.Unlock()
	finishAnyway := <-call.release
	if finishAnyway {
		return nil
	}
	return ctx.Err()
}

func (r *reloadScheduler) finish() {
	r.access.Lock()
	r.done = true
	r.changed.Broadcast()
	r.access.Unlock()
}

// run lets parked starts go on, one at a time and in random order, until the
// reloaders are done and nothing is parked. check runs at every point where no
// start code runs.
func (r *reloadScheduler) run(check func()) {
	for {
		r.access.Lock()
		for r.running > 0 || len(r.parked) == 0 && !r.done {
			r.changed.Wait()
		}
		if len(r.parked) == 0 {
			r.access.Unlock()
			return
		}
		check()
		if !r.done && rand.IntN(2) == 0 {
			// Give the reloaders a chance to come in on top of the parked starts.
			r.access.Unlock()
			time.Sleep(time.Duration(rand.IntN(300)) * time.Microsecond)
			continue
		}
		index := rand.IntN(len(r.parked))
		call := r.parked[index]
		r.parked = append(r.parked[:index], r.parked[index+1:]...)
		call.running = true
		r.running++
		r.access.Unlock()
		// A start whose instance was closed meanwhile either fails on the
		// close or finishes anyway; one that was not closed finishes.
		call.release <- rand.IntN(2) == 0
	}
}

// TestStartOrReloadOverlappingReloads: several goroutines keep reloading, a
// reader polls readGroups whenever the status is STARTED, and the scheduler
// checks the service between starts. A STARTED status must always come with
// an instance that has finished starting, a superseded start must neither
// fail its caller nor drop the instance that superseded it, and every
// instance must end up closed.
func TestStartOrReloadOverlappingReloads(t *testing.T) {
	const (
		reloaders          = 4
		reloadsPerReloader = 12
	)
	var failures failureLog
	scheduler := &reloadScheduler{calls: make(map[string]*reloadCall)}
	scheduler.changed = sync.NewCond(&scheduler.access)
	var (
		gatesAccess sync.Mutex
		gates       []*testGateOutbound
	)
	ctx := newGateTestContext(scheduler.hold, func(gateOutbound *testGateOutbound) {
		if gateOutbound.gate != "" {
			gatesAccess.Lock()
			gates = append(gates, gateOutbound)
			gatesAccess.Unlock()
		}
	})
	s := NewStartedService(ServiceOptions{Context: ctx, LogMaxLines: 16})
	defer s.Close()
	dir := t.TempDir()

	var stopReader atomic.Bool
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for !stopReader.Load() {
			s.serviceAccess.RLock()
			if s.serviceStatus.Status == ServiceStatus_STARTED {
				if !finishedStarting(s.instance) {
					failures.add("reader: STARTED before the instance finished starting", "")
				}
				func() {
					defer func() {
						if panicValue := recover(); panicValue != nil {
							failures.add("reader: readGroups panicked", "%v", panicValue)
						}
					}()
					s.readGroups()
				}()
			}
			s.serviceAccess.RUnlock()
			time.Sleep(20 * time.Microsecond)
		}
	}()

	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		scheduler.run(func() {
			status, instance := serviceState(s)
			switch status {
			case ServiceStatus_STARTED:
				if !finishedStarting(instance) {
					failures.add("between starts: STARTED before the instance finished starting", "")
				}
			case ServiceStatus_STARTING:
				if instance == nil {
					failures.add("between starts: STARTING without an instance", "")
				}
			default:
				failures.add("between starts: unexpected status", "%s", status)
			}
		})
	}()

	var reloadersGroup sync.WaitGroup
	for reloader := range reloaders {
		reloadersGroup.Add(1)
		go func() {
			defer reloadersGroup.Done()
			for reload := range reloadsPerReloader {
				name := fmt.Sprintf("r%d-%d", reloader, reload)
				call := scheduler.begin(name)
				err := s.StartOrReloadService(context.Background(), gateTestProfile(filepath.Join(dir, name+".db"), name), nil)
				scheduler.end(call)
				if err != nil {
					failures.add("StartOrReloadService returned an error", "%s: %v", name, err)
				}
				time.Sleep(time.Duration(rand.IntN(200)) * time.Microsecond)
			}
		}()
	}
	reloadersDone := make(chan struct{})
	go func() {
		reloadersGroup.Wait()
		close(reloadersDone)
	}()
	waitClosed(t, reloadersDone, "the reloaders to finish")
	scheduler.finish()
	waitClosed(t, schedulerDone, "the scheduler to finish")
	stopReader.Store(true)
	waitClosed(t, readerDone, "the reader to finish")

	status, instance := serviceState(s)
	if status != ServiceStatus_STARTED || !finishedStarting(instance) {
		failures.add("after the last reload: not started", "status %s, instance finished starting: %v", status, finishedStarting(instance))
	} else {
		requireURLTestGroupsStarted(t, instance)
	}
	require.NoError(t, s.CloseService())
	gatesAccess.Lock()
	var leaked int
	for _, gateOutbound := range gates {
		if gateOutbound.ctx.Err() == nil {
			leaked++
		}
	}
	created := len(gates)
	gatesAccess.Unlock()
	if leaked > 0 {
		failures.add("instances never closed", "%d of %d", leaked, created)
	}
	failures.check(t)
	require.Equal(t, reloaders*reloadsPerReloader, created)
}

// failureLog collects failures from the goroutines of a test by kind, with the
// first detail of each.
type failureLog struct {
	access sync.Mutex
	kinds  []string
	count  map[string]int
	first  map[string]string
}

func (l *failureLog) add(kind string, format string, args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.count == nil {
		l.count = make(map[string]int)
		l.first = make(map[string]string)
	}
	if l.count[kind] == 0 {
		l.kinds = append(l.kinds, kind)
		l.first[kind] = fmt.Sprintf(format, args...)
	}
	l.count[kind]++
}

func (l *failureLog) check(t *testing.T) {
	t.Helper()
	l.access.Lock()
	defer l.access.Unlock()
	if len(l.kinds) == 0 {
		return
	}
	var report strings.Builder
	for _, kind := range l.kinds {
		fmt.Fprintf(&report, "\n  %s: %d", kind, l.count[kind])
		if l.first[kind] != "" {
			fmt.Fprintf(&report, " (first: %s)", l.first[kind])
		}
	}
	t.Fatal(report.String())
}
