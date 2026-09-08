package libbox

import (
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/experimental/vpn4tvbridge"
)

// VPN4TV: one answer to "how does a bridge socket stay out of the tunnel" for
// every bridge (xray, outline, wireproxy, olcrtc).
//
// On Android and Apple the platform wrapper hands the descriptor to
// VpnService.protect / the NE interface control. The desktop daemon has no
// platform wrapper; there the daemon installs sing-box's own interface binder
// as vpn4tvbridge.ProtectHook. Without either, the socket is left alone —
// which is only safe before the TUN exists.
func bridgeControl(network, address string, conn syscall.RawConn) error {
	// Loopback is where the bridges listen; never bind it to an interface.
	if strings.HasPrefix(address, "127.") || strings.HasPrefix(address, "[::1]") {
		return nil
	}
	if wrapper := xrayPlatformWrap; wrapper != nil {
		return conn.Control(func(fd uintptr) {
			_ = wrapper.AutoDetectInterfaceControl(int(fd))
		})
	}
	if hook := vpn4tvbridge.ProtectHook; hook != nil {
		return hook(network, address, conn)
	}
	return nil
}
