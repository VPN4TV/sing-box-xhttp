package libbox

import "github.com/sagernet/sing-box/experimental/vpn4tvbridge"

// VPN4TV: expose the bridge entry points to the core-side starter (used by the
// desktop daemon, which cannot call the gomobile API). See
// experimental/vpn4tvbridge for why the dependency is inverted.
func init() {
	vpn4tvbridge.StartXrayHook = StartXrayInstance
	vpn4tvbridge.StartOutlineHook = StartOutlineBridge
	vpn4tvbridge.StartWireproxyHook = StartWireproxyBridge
	vpn4tvbridge.StartOlcrtcHook = StartOlcrtcBridge
	vpn4tvbridge.StopXrayHook = StopXrayInstance
	vpn4tvbridge.StopOutlineHook = StopOutlineBridge
	vpn4tvbridge.StopWireproxyHook = StopWireproxyBridge
	vpn4tvbridge.StopOlcrtcHook = StopOlcrtcBridge
}
