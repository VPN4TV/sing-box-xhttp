//go:build with_olcrtc

package libbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	olcrtcmobile "github.com/openlibrecommunity/olcrtc/mobile"
)

const olcrtcBuiltIn = true

// olcrtcDefaultDNS is what the olcrtc client resolves the meeting host with
// when the endpoint does not say. Yandex first: under a Russian whitelist it is
// the resolver most likely to still answer; Google as the general fallback.
var olcrtcDefaultDNS = []string{"77.88.8.8:53", "8.8.8.8:53"}

// The SOCKS listener only opens once the WebRTC session is up, which takes
// as long as the meeting service takes — tens of seconds at times. Nobody
// waits for that at start: sing-box copes with a refused socks outbound by
// retrying, so readiness is only watched for the log. This bounds the watch.
const olcrtcReadyWatch = 2 * time.Minute

var (
	olcrtcMu          sync.Mutex
	olcrtcRuntimes    []*olcrtcmobile.Runtime
	olcrtcProtectOnce sync.Once
)

type olcrtcProtector struct{}

// Protect is olcrtc's process-wide socket hook: every socket its engines open
// (signalling, ICE, the meeting API) passes through here before use.
func (olcrtcProtector) Protect(fd int) bool {
	if wrapper := xrayPlatformWrap; wrapper != nil {
		return wrapper.AutoDetectInterfaceControl(fd) == nil
	}
	// No platform wrapper: the desktop. The binder needs the address to pick an
	// interface, which this hook does not carry, so the resolver below and the
	// dialers inside olcrtc (which honour the same hook) are what keep the
	// daemon's sockets bound — see olcrtcResolver.
	return true
}

// olcrtcResolver resolves through the given servers, over sockets that stay
// out of the tunnel. Tried in order; the first answer wins.
func olcrtcResolver(servers []string) *net.Resolver {
	dialer := net.Dialer{Timeout: 4 * time.Second, Control: func(network, address string, conn syscall.RawConn) error {
		return bridgeControl(network, address, conn)
	}}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, server := range servers {
				conn, err := dialer.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = errors.New("olcrtc: no DNS server configured")
			}
			return nil, lastErr
		},
	}
}

// StartOlcrtcBridge starts one olcrtc client per endpoint, each with its own
// SOCKS5 inbound on <listen>:<port>. A previous bridge is stopped first.
func StartOlcrtcBridge(configJSON string) error {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()
	stopOlcrtcLocked()

	cfg, err := parseOlcrtcConfig(configJSON)
	if err != nil {
		return err
	}
	olcrtcProtectOnce.Do(func() {
		olcrtcmobile.New().SetProtector(olcrtcProtector{})
	})

	for i, ep := range cfg.Endpoints {
		runtime, err := newOlcrtcRuntime(ep)
		if err != nil {
			stopOlcrtcLocked()
			return fmt.Errorf("olcrtc: endpoint %d: %w", i, err)
		}
		if err := runtime.Start(); err != nil {
			stopOlcrtcLocked()
			return fmt.Errorf("olcrtc: endpoint %d: start: %w", i, err)
		}
		olcrtcRuntimes = append(olcrtcRuntimes, runtime)
		olcrtcLog("endpoint %d starting, SOCKS5 will open on %s:%d", i, endpointListenHost(ep.Listen), ep.Port)
		go func(index int, r *olcrtcmobile.Runtime) {
			if err := r.WaitReady(int(olcrtcReadyWatch / time.Millisecond)); err != nil {
				olcrtcLog("endpoint %d not ready after %s: %v", index, olcrtcReadyWatch, err)
				return
			}
			olcrtcLog("endpoint %d ready", index)
		}(i, runtime)
	}
	return nil
}

func newOlcrtcRuntime(ep olcrtcEndpoint) (*olcrtcmobile.Runtime, error) {
	key, err := parseOlcrtcURI(ep.URL)
	if err != nil {
		return nil, err
	}
	r := olcrtcmobile.New()
	if err := r.SetProvider(key.Provider); err != nil {
		return nil, err
	}
	if err := r.SetTransport(key.Transport); err != nil {
		return nil, err
	}
	if err := r.SetRoom(key.Room); err != nil {
		return nil, err
	}
	if err := r.SetKey(key.KeyHex); err != nil {
		return nil, err
	}
	servers := olcrtcDefaultDNS
	if ep.DNS != "" {
		servers = append([]string{ep.DNS}, olcrtcDefaultDNS...)
	}
	if err := r.SetDNS(servers[0]); err != nil {
		return nil, err
	}
	r.SetResolver(olcrtcResolver(servers))
	if err := r.SetSocksListenHost(endpointListenHost(ep.Listen)); err != nil {
		return nil, err
	}
	if err := r.SetSocksPort(ep.Port); err != nil {
		return nil, err
	}
	// Transport parameters from the link, names as in docs/uri.md.
	switch key.Transport {
	case "vp8channel":
		if fps, batch := key.paramInt("vp8-fps"), key.paramInt("vp8-batch"); fps > 0 || batch > 0 {
			if err := r.SetVP8Options(fps, batch); err != nil {
				return nil, err
			}
		}
	case "seichannel":
		if fps, batch, frag, ack := key.paramInt("fps"), key.paramInt("batch"), key.paramInt("frag"), key.paramInt("ack-ms"); fps > 0 || batch > 0 || frag > 0 || ack > 0 {
			if err := r.SetSEIOptions(fps, batch, frag, ack); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

// StopOlcrtcBridge stops every running olcrtc client.
func StopOlcrtcBridge() error {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()
	stopOlcrtcLocked()
	return nil
}

func stopOlcrtcLocked() {
	for _, r := range olcrtcRuntimes {
		if err := r.Stop(3000); err != nil && !strings.Contains(err.Error(), "not running") {
			olcrtcLog("stop: %v", err)
		}
	}
	olcrtcRuntimes = nil
}
