//go:build with_naive_outbound

package naive

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Chromium learns whether IPv6 reaches the internet by connecting a UDP socket
// to Google Public DNS, [2001:4860:4860::8888]:443; no packet is sent. Cronet
// asks our dialer for that socket, and on a network without global IPv6 the
// dial fails ("network is unreachable"). cronet-go logs that as an error under
// the outbound's name, once per naive outbound and again after network
// changes, which reads like a broken server in the log users send to support.
// It is the probe's normal answer: debug level.
var chromiumIPv6Probe = M.SocksaddrFrom(netip.MustParseAddr("2001:4860:4860::8888"), 443)

type probeLogger struct {
	logger.ContextLogger
}

func (l probeLogger) ErrorContext(ctx context.Context, args ...any) {
	// cronet-go: ErrorContext(ctx, "open UDP connection to ", destination, ": ", err)
	if len(args) >= 2 {
		if destination, ok := args[1].(M.Socksaddr); ok && destination == chromiumIPv6Probe {
			l.ContextLogger.DebugContext(ctx, args...)
			return
		}
	}
	l.ContextLogger.ErrorContext(ctx, args...)
}
