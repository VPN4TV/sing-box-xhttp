//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// VPN4TV: the Cronet engine of a naive outbound starts beside the service, not
// inside its start. Until 2026-11 Start called NaiveClient.Start, and on some
// 32-bit TVs (Haier, Xiaomi MiTV, TCL; Android 9–15) the engine now and then
// never handed over its stream engine (Cronet_Engine_GetStreamEngine): the
// whole service start, every server of the subscription, chosen or not, waited
// for it until the app's 45 s watchdog gave up (hang group 90b0f74e9d: 45
// reports a week, 56 TVs a month, most of them once). Now:
//   - Start begins the engine's start and returns; on iOS/tvOS the first
//     connection begins it, as since 2026-11-04 (an engine per outbound costs
//     in the 50 MiB Network Extension before anything goes through it);
//   - a connection waits for the engine within its own context, and no longer
//     than engineStartLimit after the start began; after that it fails at
//     once, so the auto selection takes other servers, and a server chosen by
//     hand fails alone instead of the whole VPN;
//   - an engine that starts late serves from then on;
//   - Close never waits for a start still going: that start closes the engine
//     when it ends.

// engineStartLimit: how long connections wait for an engine whose start has
// not ended. A var for the tests.
var engineStartLimit = 30 * time.Second

type engineStart struct {
	access sync.Mutex
	begun  bool
	ended  bool
	closed bool
	err    error         // the start's error, set before done is closed
	limit  time.Duration // engineStartLimit when the start began
	done   chan struct{} // closed when the start has ended
	late   chan struct{} // closed when engineStartLimit passed before the end
	stop   chan struct{} // closed by Close
	timer  *time.Timer
	// running: the engine has started and InterfaceUpdated may touch it.
	running atomic.Bool
}

func newEngineStart() *engineStart {
	return &engineStart{
		done: make(chan struct{}),
		late: make(chan struct{}),
		stop: make(chan struct{}),
	}
}

func closedChannel(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// beginStart starts the engine in its own goroutine, once; nothing after Close.
func (h *Outbound) beginStart() {
	s := h.engine
	s.access.Lock()
	if s.begun || s.closed {
		s.access.Unlock()
		return
	}
	s.begun = true
	begunAt := time.Now()
	limit := engineStartLimit
	s.limit = limit
	s.timer = time.AfterFunc(limit, func() {
		s.access.Lock()
		ended := s.ended
		if !ended {
			close(s.late)
		}
		s.access.Unlock()
		if !ended {
			h.logger.Warn("NaiveProxy engine has not started in ", limit, ": connections through ", h.Tag(), " fail until it does")
		}
	})
	s.access.Unlock()
	go func() {
		err := h.startEngine()
		if err == nil {
			s.running.Store(true)
		}
		s.access.Lock()
		s.ended = true
		s.err = err
		s.timer.Stop()
		late := closedChannel(s.late)
		closed := s.closed
		close(s.done)
		s.access.Unlock()
		if err != nil {
			h.logger.Error("start NaiveProxy: ", err)
			return
		}
		if late {
			h.logger.Info("NaiveProxy engine of ", h.Tag(), " started after ", time.Since(begunAt).Round(time.Second))
		}
		if closed {
			_ = h.closeEngine()
		}
	}()
}

// ensureStarted: nil once the engine runs; its start's error; or, while the
// start goes on, an error when the connection's context ends, when the start
// has taken engineStartLimit, or when the outbound is closed.
func (h *Outbound) ensureStarted(ctx context.Context) error {
	h.beginStart()
	s := h.engine
	select {
	case <-s.done:
		return s.err
	default:
	}
	select {
	case <-s.done:
		return s.err
	case <-s.late:
		return E.New("NaiveProxy engine has not started in ", s.limit)
	case <-s.stop:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeOutbound closes the engine, or leaves it to a start still going.
func (h *Outbound) closeOutbound() error {
	s := h.engine
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	pending := s.begun && !s.ended
	s.access.Unlock()
	if pending {
		return nil
	}
	err := h.closeEngine()
	if errors.Is(err, net.ErrClosed) {
		// A start that failed has closed the client already.
		return nil
	}
	return err
}
