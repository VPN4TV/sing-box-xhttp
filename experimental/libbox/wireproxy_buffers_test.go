package libbox

import (
	"net/netip"
	"reflect"
	"testing"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// VPN4TV: the reflection in capAwgNetstackBuffers still finds the stack of the
// amneziawg-go in go.mod, and the options reach it.
func TestCapAwgNetstackBuffers(t *testing.T) {
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.2")}, nil, 1420)
	require.NoError(t, err)
	defer tunDev.Close()
	require.NoError(t, capAwgNetstackBuffers(tnet))

	s := *(**stack.Stack)(unsafe.Pointer(reflect.ValueOf(tnet).Elem().FieldByName("stack").UnsafeAddr()))
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	require.Nil(t, s.TransportProtocolOption(tcp.ProtocolNumber, &receive))
	require.Equal(t, awgNetstackTCPBufferDefault, receive.Default)
	var send tcpip.TCPSendBufferSizeRangeOption
	require.Nil(t, s.TransportProtocolOption(tcp.ProtocolNumber, &send))
	require.Equal(t, awgNetstackTCPBufferDefault, send.Default)
	var moderate tcpip.TCPModerateReceiveBufferOption
	require.Nil(t, s.TransportProtocolOption(tcp.ProtocolNumber, &moderate))
	require.False(t, bool(moderate))
}
