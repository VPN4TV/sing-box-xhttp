package libbox

import (
	"strings"
	"testing"

	wireproxy "github.com/artem-russkikh/wireproxy-awg"
	"github.com/go-ini/ini"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// VPN4TV: an AmneziaWG 3.1 config pasted from the Amnezia client must survive
// the same path startOneAwgEndpoint takes — INI → wireproxy parser → IPC
// request → device — with every 3.0/3.1 field reaching the device. The
// clients hand the INI over verbatim, so this is the whole contract.
const awg31Config = `# awg31
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.1.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
S3 = 20
S4 = 25
H1 = 1000000-2000000
H2 = 2000001-3000000
H3 = 3000001-4000000
H4 = 4000001-5000000
I1 = <b 0x504f5354><rc 8><t>
HeaderProtectionKey = 2Q0lzZxKAOQoO9MmqcYOc2jr3ZW7KsSj4V6ZjxT9r3c=
ContentPaddingAddition = 0-64
RekeyAfterTime = 100-120
KeepaliveTimeout = 10-15
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 15-25
`

func TestAwg31ConfigReachesDevice(t *testing.T) {
	cfg, err := ini.LoadSources(ini.LoadOptions{Insensitive: true, AllowShadows: true, AllowNonUniqueSections: true}, []byte(awg31Config))
	if err != nil {
		t.Fatal(err)
	}
	deviceConf := &wireproxy.DeviceConfig{MTU: 1420}
	if err := wireproxy.ParseInterface(cfg, deviceConf); err != nil {
		t.Fatalf("parse interface: %v", err)
	}
	if err := wireproxy.ParsePeers(cfg, &deviceConf.Peers); err != nil {
		t.Fatalf("parse peers: %v", err)
	}
	section, err := cfg.GetSection("Interface")
	if err != nil {
		t.Fatal(err)
	}
	awgCfg, err := wireproxy.ParseASecConfig(section)
	if err != nil {
		t.Fatalf("parse AWG params: %v", err)
	}
	if awgCfg == nil {
		t.Fatal("AWG params were dropped")
	}
	deviceConf.ASecConfig = awgCfg

	request, err := wireproxy.CreateIPCRequest(deviceConf)
	if err != nil {
		t.Fatalf("IPC request: %v", err)
	}
	for _, key := range []string{"jc=4", "s3=20", "s4=25", "i1=", "header_protection_key=", "random_trailers=", "disable_cookies=", "keepalive_timeout="} {
		if !strings.Contains(strings.ToLower(request.IpcRequest), key) {
			t.Errorf("IPC request lacks %q:\n%s", key, request.IpcRequest)
		}
	}

	tunDev, _, err := netstack.CreateNetTUN(request.DeviceAddr, request.DNS, request.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(request.IpcRequest); err != nil {
		t.Fatalf("device rejected the AWG 3.1 request: %v", err)
	}
}
