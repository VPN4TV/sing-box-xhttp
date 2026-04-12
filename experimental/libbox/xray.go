package libbox

import (
	"strings"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/common/net"
	xraycore "github.com/xtls/xray-core/core"
	xrayserial "github.com/xtls/xray-core/infra/conf/serial"
	xrayinternet "github.com/xtls/xray-core/transport/internet"

	_ "github.com/xtls/xray-core/main/distro/all"
)

// Xray bridge for transports that sing-box cannot handle natively
// (xhttp, splithttp). The bridge runs an xray-core instance inside the same
// Go runtime as sing-box, so there's only one go.Seq, one libgojni.so and one
// gomobile binding — avoiding the duplicate-class / mid==null conflicts that
// arise when loading a separate libv2ray.aar.
//
// sing-box connects to the xray instance via SOCKS5 on 127.0.0.127 (non-
// standard loopback to avoid port scanners), where xray forwards traffic to
// the configured xhttp outbound.
//
// Outbound sockets created by xray are protected via Android's
// VpnService.protect (exposed as platformInterfaceWrapper.AutoDetectInterfaceControl)
// so they bypass the VPN TUN that sing-box installs — otherwise xray traffic
// would loop back through the TUN and deadlock.

var (
	xrayMu             sync.Mutex
	xrayInstance       *xraycore.Instance
	xrayPlatformWrap   *platformInterfaceWrapper
	xrayDialerInstalled bool
)

// setXrayPlatformWrapper is called from NewCommandServer to hand the box
// platform wrapper to the xray bridge.
func setXrayPlatformWrapper(w *platformInterfaceWrapper) {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	xrayPlatformWrap = w
}

// installXrayDialerController registers a controller that protects each
// outbound socket xray creates. Idempotent.
func installXrayDialerController() error {
	if xrayDialerInstalled {
		return nil
	}
	err := xrayinternet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
		wrapper := xrayPlatformWrap
		if wrapper == nil {
			return nil
		}
		// Skip loopback addresses — the inbound is on 127.0.0.127 and we
		// don't want to protect that (it's local, not routed through TUN).
		if strings.HasPrefix(address, "127.") {
			return nil
		}
		return c.Control(func(fd uintptr) {
			_ = wrapper.AutoDetectInterfaceControl(int(fd))
		})
	})
	if err != nil {
		return err
	}
	xrayDialerInstalled = true
	return nil
}

// Reference net package to avoid unused import when tags change.
var _ = net.ParseAddress

// StartXrayInstance starts an embedded xray-core instance with the given JSON
// configuration. If an instance is already running it is stopped first.
// Returns an error if the config is invalid or startup fails.
func StartXrayInstance(configJSON string) error {
	xrayMu.Lock()
	defer xrayMu.Unlock()

	if err := installXrayDialerController(); err != nil {
		return err
	}

	if xrayInstance != nil {
		_ = xrayInstance.Close()
		xrayInstance = nil
	}

	cfg, err := xrayserial.DecodeJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return err
	}
	pbConfig, err := cfg.Build()
	if err != nil {
		return err
	}
	instance, err := xraycore.New(pbConfig)
	if err != nil {
		return err
	}
	if err := instance.Start(); err != nil {
		return err
	}
	xrayInstance = instance
	return nil
}

// StopXrayInstance stops the running xray-core instance (if any).
func StopXrayInstance() error {
	xrayMu.Lock()
	defer xrayMu.Unlock()

	if xrayInstance == nil {
		return nil
	}
	err := xrayInstance.Close()
	xrayInstance = nil
	return err
}

// IsXrayRunning reports whether an xray instance is currently running.
func IsXrayRunning() bool {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	return xrayInstance != nil
}
