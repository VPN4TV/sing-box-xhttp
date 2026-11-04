package libbox

import (
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// VPN4TV: the TCP buffers of an AmneziaWG endpoint's gVisor netstack, on
// iOS/tvOS only (startOneAwgEndpoint). amneziawg-go's CreateNetTUN keeps
// gVisor's defaults: 1 MiB send and receive buffers, the receive one auto-tuned
// up to 4 MiB. A connection whose reader stalls (paused video) holds what its
// buffer took, and a few of them fill the 50 MiB Network Extension. Here 256 KiB
// each, without auto-tuning (about 30 Mbit/s a connection at 70 ms).
//
// netstack.Net keeps its stack unexported, and the options apply to the
// connections made after they are set: the stack is reached by reflection right
// after CreateNetTUN, its type checked first. If amneziawg-go changes the field
// the endpoint keeps gVisor's defaults and says so in the bridge log.
const (
	awgNetstackTCPBufferDefault = 256 << 10
	awgNetstackTCPBufferMax     = 1 << 20
)

func capAwgNetstackBuffers(tnet *netstack.Net) error {
	if tnet == nil {
		return errors.New("no netstack")
	}
	field := reflect.ValueOf(tnet).Elem().FieldByName("stack")
	if !field.IsValid() || field.Type() != reflect.TypeOf((*stack.Stack)(nil)) {
		return errors.New("netstack.Net has no *stack.Stack field named stack")
	}
	s := *(**stack.Stack)(unsafe.Pointer(field.UnsafeAddr()))
	if s == nil {
		return errors.New("netstack without a stack")
	}
	receive := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: awgNetstackTCPBufferDefault, Max: awgNetstackTCPBufferMax}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		return fmt.Errorf("receive buffer: %v", err)
	}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: awgNetstackTCPBufferDefault, Max: awgNetstackTCPBufferMax}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		return fmt.Errorf("send buffer: %v", err)
	}
	moderate := tcpip.TCPModerateReceiveBufferOption(false)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		return fmt.Errorf("receive buffer auto-tuning: %v", err)
	}
	return nil
}
