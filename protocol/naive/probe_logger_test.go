//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type recordingLogger struct {
	logger.ContextLogger
	debug, errors int
}

func (r *recordingLogger) DebugContext(context.Context, ...any) { r.debug++ }
func (r *recordingLogger) ErrorContext(context.Context, ...any) { r.errors++ }

func TestProbeLoggerDemotesOnlyTheIPv6Probe(t *testing.T) {
	record := &recordingLogger{}
	l := probeLogger{record}
	failure := errors.New("connect: network is unreachable")
	probe := M.ParseSocksaddrHostPort("2001:4860:4860::8888", 443)
	l.ErrorContext(context.Background(), "open UDP connection to ", probe, ": ", failure)
	if record.debug != 1 || record.errors != 0 {
		t.Fatalf("probe: debug=%d errors=%d, want 1/0", record.debug, record.errors)
	}
	other := M.SocksaddrFrom(netip.MustParseAddr("2001:db8::1"), 443)
	l.ErrorContext(context.Background(), "open UDP connection to ", other, ": ", failure)
	l.ErrorContext(context.Background(), "socket pair failed: ", failure)
	if record.debug != 1 || record.errors != 2 {
		t.Fatalf("others: debug=%d errors=%d, want 1/2", record.debug, record.errors)
	}
}
