package route

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
)

// VPN4TV: UDP for a chosen server that carries TCP only — naive without UDP over
// TCP (our naive servers are Caddy's forwardproxy, which cannot carry it), olcRTC,
// http. Until 2026-11 such UDP reached the router, which logged "UDP is not
// supported by outbound: select" as an error for every flow and closed it; the
// customers' journals were all red (2026-11-25, TVs on AL11N and the like), and
// on a stack without an unreachable reply QUIC waited for its own timeout before
// going over TCP. Now the tun refuses the flow at its first look, with an ICMP
// port unreachable as a reject rule does, so apps go over TCP at once, and the
// journal gets one warning for the chosen server instead of a line per flow.

// udpRefusedWarnEvery: the warning for the same server comes back after this
// long, so a journal sent to support later still says why UDP is refused.
const udpRefusedWarnEvery = 10 * time.Minute

type udpRefusedLog struct {
	access sync.Mutex
	tag    string
	at     time.Time
}

// refuseUDP writes the warning when it is due and returns the error the router
// returns for such a flow: a rejection, which it logs at debug, not as an error.
func (r *Router) refuseUDP(outbound adapter.Outbound) error {
	tag := r.chosenServer(outbound)
	now := time.Now()
	r.udpRefused.access.Lock()
	warn := tag != r.udpRefused.tag || now.Sub(r.udpRefused.at) >= udpRefusedWarnEvery
	if warn {
		r.udpRefused.tag = tag
		r.udpRefused.at = now
	}
	r.udpRefused.access.Unlock()
	if warn {
		r.logger.Warn("UDP refused: the chosen server ", tag, " carries TCP only, apps go over TCP")
	}
	return &R.RejectedError{Cause: E.New("UDP is not supported by outbound: ", outbound.Tag())}
}

// chosenServer is the server a group ends at ("select" → "AL11N"), for the
// warning; the outbound's own tag when it is not a group.
func (r *Router) chosenServer(outbound adapter.Outbound) string {
	for range 8 {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		selected, loaded := r.outbound.Outbound(group.Now())
		if !loaded {
			break
		}
		outbound = selected
	}
	return outbound.Tag()
}
