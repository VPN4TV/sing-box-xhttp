package libbox

import (
	"syscall"
	_ "unsafe"

	_ "github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// controlFn must match conn.controlFn exactly.
type controlFn = func(network, address string, c syscall.RawConn) error

// Link to the unexported package-level slice of control functions inside
// amneziawg-go/conn. We need to append our VpnService.protect hook to this
// list so the UDP sockets wireguard-go opens for its outbound bind are
// protected BEFORE the first packet is sent — otherwise the handshake
// initiation goes out through the sing-box TUN and loops back through our
// own outbound, which never delivers the handshake to the remote peer.
//
//go:linkname awgControlFns github.com/amnezia-vpn/amneziawg-go/v3/conn.controlFns
var awgControlFns []controlFn

func init() {
	awgControlFns = append(awgControlFns, func(network, address string, c syscall.RawConn) error {
		return bridgeControl(network, address, c)
	})
}
