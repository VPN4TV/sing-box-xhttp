//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// engineOutbound: an outbound whose engine start blocks until release is
// closed and then returns startErr; closes counts the engine's closes.
func engineOutbound(release chan struct{}, startErr error) (*Outbound, *atomic.Int32) {
	closes := &atomic.Int32{}
	h := &Outbound{
		logger: log.NewNOPFactory().Logger(),
		engine: newEngineStart(),
		startEngine: func() error {
			<-release
			return startErr
		},
		closeEngine: func() error {
			closes.Add(1)
			return nil
		},
	}
	return h, closes
}

func shortLimit(t *testing.T, limit time.Duration) {
	saved := engineStartLimit
	engineStartLimit = limit
	t.Cleanup(func() { engineStartLimit = saved })
}

func waitCtx(d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	_ = cancel
	return ctx
}

func TestAHungEngineHoldsNeitherTheStartNorConnectionsPastTheLimit(t *testing.T) {
	shortLimit(t, 300*time.Millisecond)
	release := make(chan struct{})
	h, _ := engineOutbound(release, nil)

	begun := time.Now()
	h.beginStart()
	if took := time.Since(begun); took > 50*time.Millisecond {
		t.Fatalf("the start waited %v for the engine", took)
	}
	if err := h.ensureStarted(waitCtx(50 * time.Millisecond)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a connection before the limit: %v, want its own deadline", err)
	}
	if h.engine.running.Load() {
		t.Fatal("running before the engine started: InterfaceUpdated would touch it")
	}
	time.Sleep(350 * time.Millisecond)
	at := time.Now()
	err := h.ensureStarted(context.Background())
	if err == nil || !strings.Contains(err.Error(), "has not started in") {
		t.Fatalf("a connection after the limit: %v", err)
	}
	if took := time.Since(at); took > 50*time.Millisecond {
		t.Fatalf("a connection after the limit waited %v", took)
	}

	close(release)
	<-h.engine.done
	if err := h.ensureStarted(context.Background()); err != nil {
		t.Fatalf("after a late start: %v", err)
	}
	if !h.engine.running.Load() {
		t.Fatal("not running after the start")
	}
}

func TestAConnectionWaitsForAnEngineThatStartsWithinTheLimit(t *testing.T) {
	release := make(chan struct{})
	h, _ := engineOutbound(release, nil)
	h.beginStart()
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()
	if err := h.ensureStarted(waitCtx(2 * time.Second)); err != nil {
		t.Fatalf("a connection while the engine starts: %v", err)
	}
}

func TestTheFirstConnectionBeginsTheStartWhenStartDidNot(t *testing.T) {
	release := make(chan struct{})
	close(release)
	h, _ := engineOutbound(release, nil)
	if err := h.ensureStarted(waitCtx(2 * time.Second)); err != nil {
		t.Fatalf("the first connection (iOS/tvOS path): %v", err)
	}
}

func TestCloseDoesNotWaitForAStartGoingOnAndTheStartClosesTheEngine(t *testing.T) {
	release := make(chan struct{})
	h, closes := engineOutbound(release, nil)
	h.beginStart()
	waiting := make(chan error, 1)
	go func() { waiting <- h.ensureStarted(context.Background()) }()

	at := time.Now()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(at); took > 50*time.Millisecond {
		t.Fatalf("Close waited %v for the start", took)
	}
	select {
	case err := <-waiting:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("a connection waiting at Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("a connection waiting at Close still waits")
	}
	if n := closes.Load(); n != 0 {
		t.Fatalf("the engine closed %d times while its start goes on", n)
	}
	close(release)
	<-h.engine.done
	deadline := time.Now().Add(time.Second)
	for closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := closes.Load(); n != 1 {
		t.Fatalf("the start closed the engine %d times after Close, want 1", n)
	}
	if err := h.Close(); err != nil || closes.Load() != 1 {
		t.Fatalf("a second Close: %v, %d closes", err, closes.Load())
	}
	h.beginStart() // nothing after Close
}

func TestCloseAfterTheStartClosesTheEngineOnce(t *testing.T) {
	release := make(chan struct{})
	close(release)
	h, closes := engineOutbound(release, nil)
	h.beginStart()
	<-h.engine.done
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if n := closes.Load(); n != 1 {
		t.Fatalf("%d closes, want 1", n)
	}
}

func TestCloseOfAnOutboundNeverUsedClosesItsClient(t *testing.T) {
	h, closes := engineOutbound(make(chan struct{}), nil)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if n := closes.Load(); n != 1 {
		t.Fatalf("%d closes, want 1", n)
	}
	if err := h.ensureStarted(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a connection after Close: %v", err)
	}
}

func TestAFailedStartIsEveryConnectionsError(t *testing.T) {
	release := make(chan struct{})
	close(release)
	failure := errors.New("failed to start engine: 3")
	h, _ := engineOutbound(release, failure)
	h.beginStart()
	<-h.engine.done
	for range 3 {
		if err := h.ensureStarted(context.Background()); !errors.Is(err, failure) {
			t.Fatalf("after a failed start: %v", err)
		}
	}
	if h.engine.running.Load() {
		t.Fatal("running after a failed start")
	}
}
