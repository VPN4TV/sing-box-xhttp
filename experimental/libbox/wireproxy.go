package libbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	wireproxy "github.com/artem-russkikh/wireproxy-awg"
	"github.com/go-ini/ini"
)

// Wireproxy bridge for AmneziaWG subscriptions (1.0 through 3.1; the INI is
// handed over verbatim, so whatever the fork parses is supported).
//
// Mirrors the xray and outline bridge pattern: each WG/AWG endpoint is
// represented as a SOCKS5 inbound on 127.0.0.127:<port> that sing-box talks
// to via a regular socks outbound. Inside the bridge, traffic is handed to
// an in-process userspace WireGuard device (amneziawg-go via netstack) that
// speaks the real AWG protocol with its obfuscation params to the remote peer.
//
// The outer UDP socket of the WireGuard device is protected via the shared
// platformInterfaceWrapper.AutoDetectInterfaceControl (Android's
// VpnService.protect) so it bypasses the sing-box TUN — otherwise the WG
// datagrams would loop back through the TUN and deadlock. Because
// amneziawg-go's conn.controlFns slice is unexported, we cannot install a
// pre-bind Control hook; instead we type-assert the bind to *conn.StdNetBind
// and call its exported PeekLookAtSocketFd4/6 methods after dev.Up() to
// protect the already-bound sockets.

// WireproxyEndpointConfig describes one AWG endpoint passed in from Kotlin.
// Format: JSON with an array of endpoints. Each endpoint carries the WG INI
// string verbatim (we don't try to type-check field-by-field on the Kotlin
// side — the amneziawg-go parser is the source of truth).
type wireproxyConfig struct {
	Endpoints []wireproxyEndpoint `json:"endpoints"`
}

type wireproxyEndpoint struct {
	// See outlineEndpoint.Listen — same reason, same default.
	Listen string `json:"listen,omitempty"`
	INI    string `json:"ini"`
	Port   int    `json:"port"`
}

type awgRunner struct {
	listener net.Listener
	device   *device.Device
}

var (
	wireproxyMu      sync.Mutex
	wireproxyRunners []*awgRunner
)

// StartWireproxyBridge parses the config JSON, starts one AmneziaWG device
// plus one SOCKS5 inbound per endpoint, and returns nil on success. If a
// previous bridge is running it is stopped first.
func StartWireproxyBridge(configJSON string) error {
	wireproxyMu.Lock()
	defer wireproxyMu.Unlock()

	stopWireproxyLocked()

	var cfg wireproxyConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("wireproxy: parse config: %w", err)
	}
	if len(cfg.Endpoints) == 0 {
		return errors.New("wireproxy: no endpoints")
	}

	for i, ep := range cfg.Endpoints {
		runner, err := startOneAwgEndpoint(ep.INI, ep.Port, ep.Listen)
		if err != nil {
			stopWireproxyLocked()
			return fmt.Errorf("wireproxy: endpoint %d: %w", i, err)
		}
		wireproxyRunners = append(wireproxyRunners, runner)
		wireproxyLog("started endpoint %d on 127.0.0.127:%d", i, ep.Port)
	}
	return nil
}

// StopWireproxyBridge stops every running awg device + SOCKS inbound.
func StopWireproxyBridge() error {
	wireproxyMu.Lock()
	defer wireproxyMu.Unlock()
	stopWireproxyLocked()
	return nil
}

func stopWireproxyLocked() {
	for _, r := range wireproxyRunners {
		if r.listener != nil {
			_ = r.listener.Close()
		}
		if r.device != nil {
			r.device.Close()
		}
	}
	wireproxyRunners = nil
}

// startOneAwgEndpoint parses one wg-quick INI string, brings up an
// amneziawg-go device against a netstack tun, protects its UDP socket,
// and spawns a SOCKS5 inbound bound to <listen>:port that dials through
// the netstack.
func startOneAwgEndpoint(iniText string, port int, listen string) (*awgRunner, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}
	cfg, err := ini.LoadSources(iniOpt, []byte(iniText))
	if err != nil {
		return nil, fmt.Errorf("load INI: %w", err)
	}

	deviceConf := &wireproxy.DeviceConfig{MTU: 1420}
	if err := wireproxy.ParseInterface(cfg, deviceConf); err != nil {
		return nil, fmt.Errorf("parse interface: %w", err)
	}
	if err := wireproxy.ParsePeers(cfg, &deviceConf.Peers); err != nil {
		return nil, fmt.Errorf("parse peers: %w", err)
	}
	// Optional AWG obfuscation params in [Interface]
	if section, err := cfg.GetSection("Interface"); err == nil {
		if awgCfg, err := wireproxy.ParseASecConfig(section); err == nil && awgCfg != nil {
			deviceConf.ASecConfig = awgCfg
		}
	}

	ipcRequest, err := wireproxy.CreateIPCRequest(deviceConf)
	if err != nil {
		return nil, fmt.Errorf("create IPC request: %w", err)
	}

	tunDev, tnet, err := netstack.CreateNetTUN(ipcRequest.DeviceAddr, ipcRequest.DNS, ipcRequest.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netTUN: %w", err)
	}

	bind := conn.NewStdNetBind()
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			wireproxyLog("wg: "+format, args...)
		},
		Errorf: func(format string, args ...any) {
			wireproxyLog("wg ERR: "+format, args...)
		},
	}
	dev := device.NewDevice(tunDev, bind, wgLogger)
	if err := dev.IpcSet(ipcRequest.IpcRequest); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	// Protect the bound UDP sockets so WG traffic bypasses our own TUN.
	protectAwgBind(bind)

	listenAddr := fmt.Sprintf("%s:%d", endpointListenHost(listen), port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	go runAwgSocks(ln, tnet)

	return &awgRunner{listener: ln, device: dev}, nil
}

// protectAwgBind grabs the UDP4/UDP6 fds from an amneziawg-go StdNetBind and
// passes each to platformInterfaceWrapper.AutoDetectInterfaceControl. Reuses
// the xrayPlatformWrap global that xray and outline bridges already use.
func protectAwgBind(bind conn.Bind) {
	wrapper := xrayPlatformWrap
	if wrapper == nil {
		return
	}
	type fdPeeker interface {
		PeekLookAtSocketFd4() (int, error)
		PeekLookAtSocketFd6() (int, error)
	}
	peeker, ok := bind.(fdPeeker)
	if !ok {
		wireproxyLog("bind does not expose fd peekers; protect skipped")
		return
	}
	if fd, err := peeker.PeekLookAtSocketFd4(); err == nil && fd > 0 {
		if err := wrapper.AutoDetectInterfaceControl(fd); err != nil {
			wireproxyLog("protect v4 fd=%d failed: %v", fd, err)
		} else {
			wireproxyLog("protect v4 fd=%d ok", fd)
		}
	}
	if fd, err := peeker.PeekLookAtSocketFd6(); err == nil && fd > 0 {
		if err := wrapper.AutoDetectInterfaceControl(fd); err != nil {
			wireproxyLog("protect v6 fd=%d failed: %v", fd, err)
		} else {
			wireproxyLog("protect v6 fd=%d ok", fd)
		}
	}
}

// runAwgSocks accepts SOCKS5 clients on ln and forwards each accepted
// connection through tnet.DialContext, which routes through the userspace
// AmneziaWG device to the real peer.
func runAwgSocks(ln net.Listener, tnet *netstack.Net) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		go handleAwgClient(client, tnet)
	}
}

func handleAwgClient(client net.Conn, tnet *netstack.Net) {
	defer client.Close()
	realDest, err := socks5Handshake(client)
	if err != nil {
		wireproxyLog("socks5 handshake failed: %v", err)
		return
	}
	wireproxyLog("dialing %s via awg netstack", realDest)
	remote, err := tnet.DialContext(context.Background(), "tcp", realDest)
	if err != nil {
		wireproxyLog("netstack dial(%s) failed: %v", realDest, err)
		return
	}
	defer remote.Close()
	// Reply REP=0 with dummy bind addr — sing-box ignores it.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	pipe(client, remote)
}

// wireproxyLog pushes one line into the shared bridge log ring buffer, same
// pattern as outlineLog so the Kotlin OutlineBridge.startLogDumper can be
// reused (we'll add a WireproxyLog exported accessor below).
var (
	wireproxyLogMu    sync.Mutex
	wireproxyLogLines []string
)

const wireproxyLogMax = 200

func wireproxyLog(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	wireproxyLogMu.Lock()
	defer wireproxyLogMu.Unlock()
	wireproxyLogLines = append(wireproxyLogLines, line)
	if len(wireproxyLogLines) > wireproxyLogMax {
		wireproxyLogLines = wireproxyLogLines[len(wireproxyLogLines)-wireproxyLogMax:]
	}
}

// WireproxyLog returns up to the last wireproxyLogMax log lines emitted by
// the AWG bridge, separated by newlines. Exposed via gomobile for diagnostics.
// Wrapped — same 32-bit ARM unaligned-string-return reason as OutlineLog.
func WireproxyLog() *StringBox {
	wireproxyLogMu.Lock()
	defer wireproxyLogMu.Unlock()
	return wrapString(strings.Join(wireproxyLogLines, "\n"))
}

// Reference io to make sure it stays imported across refactors.
var _ = io.EOF
