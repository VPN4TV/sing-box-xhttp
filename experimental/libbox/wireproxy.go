package libbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	wireproxy "github.com/artem-russkikh/wireproxy-awg"
	"github.com/go-ini/ini"
	M "github.com/sagernet/sing/common/metadata"
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
	// Optional username/password for the SOCKS5 inbound; see bridgeSocksAuth.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// UDPAssociate lets SOCKS UDP ASSOCIATE in; off, it is refused (0x07).
	// UDP over TCP, which the apps use, needs nothing.
	UDPAssociate bool `json:"udp_associate,omitempty"`
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
		runner, err := startOneAwgEndpoint(ep)
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
func startOneAwgEndpoint(ep wireproxyEndpoint) (*awgRunner, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}
	cfg, err := ini.LoadSources(iniOpt, []byte(ep.INI))
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

	listenAddr := fmt.Sprintf("%s:%d", endpointListenHost(ep.Listen), ep.Port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	udp := &bridgeUDP{
		open:      newAwgPacketOpener(tnet, ipcRequest.DeviceAddr),
		associate: ep.UDPAssociate,
		logf:      wireproxyLog,
	}
	go runAwgSocks(ln, tnet, udp, newBridgeSocksAuth(ep.Username, ep.Password))

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
// AmneziaWG device to the real peer. UDP goes through the same netstack, from
// the interface addresses (Address = in the INI).
func runAwgSocks(ln net.Listener, tnet *netstack.Net, udp *bridgeUDP, auth *bridgeSocksAuth) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		go handleAwgClient(client, tnet, udp, auth)
	}
}

func handleAwgClient(client net.Conn, tnet *netstack.Net, udp *bridgeUDP, auth *bridgeSocksAuth) {
	defer client.Close()
	request, err := socks5Handshake(client, auth, udp.associateAllowed())
	if err != nil {
		wireproxyLog("socks5 handshake failed: %v", err)
		return
	}
	if serveBridgeUDP(client, request, udp) {
		return
	}
	realDest := request.dest()
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

// awgResolveTimeout bounds a name lookup through the tunnel; awgNegativeTTL is
// how long a name that did not resolve is not asked again — the lookup blocks
// the session's datagrams, and an app keeps sending while it waits.
const (
	awgResolveTimeout = 5 * time.Second
	awgNegativeTTL    = 10 * time.Second
	awgNameCacheSize  = 64
)

// newAwgPacketOpener: local are the tunnel's own addresses. The UDP sockets
// bind to one of them, not to 0.0.0.0 — gvisor takes a bound 0.0.0.0 for an
// address the interface lacks and finds no route ("network is unreachable").
func newAwgPacketOpener(tnet *netstack.Net, local []netip.Addr) bridgePacketOpener {
	var local4, local6 netip.Addr
	for _, addr := range local {
		addr = addr.Unmap()
		if addr.Is4() && !local4.IsValid() {
			local4 = addr
		} else if addr.Is6() && !local6.IsValid() {
			local6 = addr
		}
	}
	return func(_ context.Context, handler bridgePacketHandler) (bridgePacketSession, error) {
		return &awgPacketSession{
			tnet:    tnet,
			handler: handler,
			local4:  local4,
			local6:  local6,
			names:   make(map[string]awgName),
			addrs:   make(map[netip.AddrPort]*net.UDPAddr),
		}, nil
	}
}

type awgName struct {
	addr  netip.Addr
	err   error
	until time.Time
}

// awgPacketSession is one SOCKS UDP session inside the AmneziaWG netstack: an
// unconnected UDP socket per address family, opened with the first datagram
// of that family, so replies come back from any address the way they would
// through a NAT. Names are resolved by the tunnel's DNS (the INI's DNS =),
// exactly as tnet.DialContext does for TCP.
type awgPacketSession struct {
	tnet           *netstack.Net
	handler        bridgePacketHandler
	local4, local6 netip.Addr

	mu     sync.Mutex
	closed bool
	v4, v6 net.PacketConn // *gonet.UDPConn

	// Touched by WriteTo only, which runs on one goroutine.
	names map[string]awgName
	addrs map[netip.AddrPort]*net.UDPAddr
}

func (s *awgPacketSession) WriteTo(p []byte, dest M.Socksaddr) error {
	addr, err := s.resolve(dest)
	if err != nil {
		return err
	}
	c, err := s.socket(addr.Addr().Is4())
	if err != nil {
		return err
	}
	_, err = c.WriteTo(p, s.udpAddr(addr))
	return err
}

func (s *awgPacketSession) resolve(dest M.Socksaddr) (netip.AddrPort, error) {
	dest = dest.Unwrap()
	if dest.IsIP() {
		return dest.AddrPort(), nil
	}
	if !dest.IsDomain() {
		return netip.AddrPort{}, errSocks5UDPAddress
	}
	now := time.Now()
	if name, ok := s.names[dest.Fqdn]; ok && (name.err == nil || now.Before(name.until)) {
		if name.err != nil {
			return netip.AddrPort{}, name.err
		}
		return netip.AddrPortFrom(name.addr, dest.Port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), awgResolveTimeout)
	defer cancel()
	var name awgName
	answers, err := s.tnet.LookupContextHost(ctx, dest.Fqdn)
	if err != nil {
		name.err = err
	} else if name.addr = pickAwgAddr(answers); !name.addr.IsValid() {
		name.err = fmt.Errorf("no address for %s", dest.Fqdn)
	}
	name.until = now.Add(awgNegativeTTL)
	if len(s.names) >= awgNameCacheSize {
		clear(s.names)
	}
	s.names[dest.Fqdn] = name
	if name.err != nil {
		wireproxyLog("udp: resolve %s: %v", dest.Fqdn, name.err)
		return netip.AddrPort{}, name.err
	}
	return netip.AddrPortFrom(name.addr, dest.Port), nil
}

// pickAwgAddr prefers IPv4: there is no trying an address with UDP, and most
// AmneziaWG tunnels carry IPv4 only.
func pickAwgAddr(answers []string) netip.Addr {
	var v6 netip.Addr
	for _, answer := range answers {
		addr, err := netip.ParseAddr(answer)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			return addr
		}
		if !v6.IsValid() {
			v6 = addr
		}
	}
	return v6
}

func (s *awgPacketSession) udpAddr(addr netip.AddrPort) *net.UDPAddr {
	if cached, ok := s.addrs[addr]; ok {
		return cached
	}
	if len(s.addrs) >= awgNameCacheSize {
		clear(s.addrs)
	}
	// gonet takes the IP bytes as they are: 4 for IPv4, 16 for IPv6.
	udpAddr := &net.UDPAddr{IP: addr.Addr().AsSlice(), Port: int(addr.Port())}
	s.addrs[addr] = udpAddr
	return udpAddr
}

func (s *awgPacketSession) socket(v4 bool) (net.PacketConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, net.ErrClosed
	}
	slot, local := &s.v6, s.local6
	if v4 {
		slot, local = &s.v4, s.local4
	}
	if *slot != nil {
		return *slot, nil
	}
	if !local.IsValid() {
		return nil, errors.New("the tunnel has no address of this family")
	}
	c, err := s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		return nil, err
	}
	*slot = c
	go s.read(c)
	return c, nil
}

func (s *awgPacketSession) read(c net.PacketConn) {
	b := getPacketBuffer()
	defer putPacketBuffer(b)
	for {
		n, addr, err := c.ReadFrom((*b)[socks5UDPMaxHeader:])
		if err != nil {
			s.handler.handleEnd(err)
			return
		}
		s.handler.handlePacket((*b)[:socks5UDPMaxHeader+n], socks5UDPMaxHeader, M.SocksaddrFromNet(addr).Unwrap())
	}
}

func (s *awgPacketSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.v4 != nil {
		_ = s.v4.Close()
	}
	if s.v6 != nil {
		_ = s.v6.Close()
	}
	return nil
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
