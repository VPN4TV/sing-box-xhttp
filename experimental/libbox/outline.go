package libbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"strings"
	"sync"
	"syscall"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// Outline bridge for Shadowsocks variants that sing-box cannot handle natively
// (notably ss:// links with the SIP002 ?prefix= parameter used by Outline TLS-
// looking obfuscation). Mirrors the embedded xray bridge architecture: the
// bridge runs in the same Go runtime as sing-box, exposes one local SOCKS5
// inbound per Shadowsocks endpoint on 127.0.0.127:<port>, and sing-box routes
// to those inbounds via regular socks outbounds.
//
// Sockets created by outline-sdk's StreamDialer are protected via the same
// platformInterfaceWrapper.AutoDetectInterfaceControl callback used by xray
// (Android's VpnService.protect). The protection is wired through a custom
// transport.StreamDialer that wraps net.Dialer.Control.

// OutlineEndpointConfig describes one Shadowsocks endpoint that outline-sdk
// will dial. Passed in as JSON from Kotlin; the fields mirror what we already
// parse on the client side.
//
// Shape: { "endpoints": [ { "url": "ss://...", "port": 30000 }, ... ] }
type outlineConfig struct {
	Endpoints []outlineEndpoint `json:"endpoints"`
}

type outlineEndpoint struct {
	URL  string `json:"url"`
	Port int    `json:"port"`
	// Listen address for this endpoint's SOCKS5 inbound. Android and Linux bind
	// the whole 127.0.0.0/8, so the mobile clients use 127.0.0.127 to stay clear
	// of anything the user runs; macOS and Windows only have 127.0.0.1, where
	// binding 127.0.0.127 fails with "can't assign requested address". Empty
	// means the historical default, so mobile profiles keep working untouched.
	Listen string `json:"listen,omitempty"`
}

// bridgeListenHost is what an endpoint binds when the profile does not say.
const bridgeListenHost = "127.0.0.127"

func endpointListenHost(listen string) string {
	if listen != "" {
		return listen
	}
	return bridgeListenHost
}

var (
	outlineMu        sync.Mutex
	outlineListeners []net.Listener
	outlineLogMu     sync.Mutex
	outlineLogLines  []string
)

const outlineLogMax = 200

func outlineLog(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	stdlog.Println("outline:", line)
	outlineLogMu.Lock()
	defer outlineLogMu.Unlock()
	outlineLogLines = append(outlineLogLines, line)
	if len(outlineLogLines) > outlineLogMax {
		outlineLogLines = outlineLogLines[len(outlineLogLines)-outlineLogMax:]
	}
}

// OutlineLog returns up to the last [outlineLogMax] log lines emitted by the
// outline bridge, separated by newlines. Exposed via gomobile for diagnostics.
// Wrapped in StringBox: gomobile-exported `string` return on 32-bit ARM
// triggers `bulkBarrierPreWrite: unaligned arguments` (golang/go#46893)
// because the two-word string header lands on a 4-byte aligned stack slot;
// the write barrier then corrupts the heap and GC blames a bad pointer
// later. Heap-allocating the wrapper struct sidesteps the issue.
func OutlineLog() *StringBox {
	outlineLogMu.Lock()
	defer outlineLogMu.Unlock()
	return wrapString(strings.Join(outlineLogLines, "\n"))
}

// newOutlineProviders builds a fresh ProviderContainer whose root TCP dialer
// has a Control function that calls platformInterfaceWrapper.AutoDetectInterfaceControl
// (Android's VpnService.protect) on the raw fd. This bypasses the TUN that
// sing-box installs — without it outline traffic loops back through the TUN
// and deadlocks.
func newOutlineProviders() *configurl.ProviderContainer {
	c := &configurl.ProviderContainer{
		StreamDialers:   configurl.NewExtensibleProvider[transport.StreamDialer](&transport.TCPDialer{Dialer: protectedNetDialer()}),
		PacketDialers:   configurl.NewExtensibleProvider[transport.PacketDialer](&transport.UDPDialer{}),
		PacketListeners: configurl.NewExtensibleProvider[transport.PacketListener](&transport.UDPListener{}),
	}
	configurl.RegisterDefaultProviders(c)
	return c
}

func protectedNetDialer() net.Dialer {
	return net.Dialer{
		Control: func(network, address string, conn syscall.RawConn) error {
			wrapper := xrayPlatformWrap // shared with xray bridge — set in NewCommandServer
			if wrapper == nil {
				outlineLog("protect: no platform wrapper for %s", address)
				return nil
			}
			if strings.HasPrefix(address, "127.") {
				return nil
			}
			return conn.Control(func(fd uintptr) {
				err := wrapper.AutoDetectInterfaceControl(int(fd))
				if err != nil {
					outlineLog("protect(%s) fd=%d failed: %v", address, fd, err)
				} else {
					outlineLog("protect(%s) fd=%d ok", address, fd)
				}
			})
		},
	}
}

// StartOutlineBridge starts SOCKS5 inbounds for every endpoint in the JSON
// config. Each inbound forwards new connections through outline-sdk to the
// Shadowsocks endpoint described by the corresponding ss:// URL.
//
// If a previous bridge is running it is stopped first.
func StartOutlineBridge(configJSON string) error {
	outlineMu.Lock()
	defer outlineMu.Unlock()

	stopOutlineLocked()

	var cfg outlineConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("outline: parse config: %w", err)
	}
	if len(cfg.Endpoints) == 0 {
		return errors.New("outline: no endpoints")
	}

	providers := newOutlineProviders()
	for i, ep := range cfg.Endpoints {
		dialer, err := providers.NewStreamDialer(context.Background(), ep.URL)
		if err != nil {
			stopOutlineLocked()
			return fmt.Errorf("outline: build dialer for endpoint %d: %w", i, err)
		}
		listenAddr := fmt.Sprintf("%s:%d", endpointListenHost(ep.Listen), ep.Port)
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			stopOutlineLocked()
			return fmt.Errorf("outline: listen %s: %w", listenAddr, err)
		}
		outlineListeners = append(outlineListeners, ln)
		go runOutlineSocks(ln, dialer)
	}
	return nil
}

// StopOutlineBridge stops every running outline SOCKS inbound.
func StopOutlineBridge() error {
	outlineMu.Lock()
	defer outlineMu.Unlock()
	stopOutlineLocked()
	return nil
}

func stopOutlineLocked() {
	for _, ln := range outlineListeners {
		_ = ln.Close()
	}
	outlineListeners = nil
}

// runOutlineSocks accepts SOCKS5 clients on ln and forwards each accepted
// connection to dialer.DialStream(realDest) where realDest comes from the
// SOCKS CONNECT request (the outline-sdk dialer already wraps the SS endpoint,
// so the target address must be the real website, not the SS server itself).
func runOutlineSocks(ln net.Listener, dialer transport.StreamDialer) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go handleOutlineClient(client, dialer)
	}
}

func handleOutlineClient(client net.Conn, dialer transport.StreamDialer) {
	defer client.Close()
	realDest, err := socks5Handshake(client)
	if err != nil {
		outlineLog("socks5 handshake failed: %v", err)
		return
	}
	outlineLog("socks handshake ok, dialing real dest %s via outline-sdk", realDest)
	// NOTE: don't use context.WithTimeout here — outline-sdk's StreamDialer
	// keeps the dial ctx alive for the whole connection lifetime. If we cancel
	// it after DialStream returns, the underlying SS conn dies immediately and
	// io.Copy reports up=N down=0 because the read side is already closed.
	remote, err := dialer.DialStream(context.Background(), realDest)
	if err != nil {
		outlineLog("DialStream(%s) failed: %v", realDest, err)
		return
	}
	defer remote.Close()
	outlineLog("DialStream(%s) ok, piping", realDest)
	// Notify SOCKS client that CONNECT succeeded. We hard-code BND.ADDR=0.0.0.0:0
	// because sing-box doesn't read it — it only looks at REP.
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	pipe(client, remote)
}

// socks5Handshake reads the greeting + the CONNECT request and returns the
// requested destination "host:port" so the outline bridge can pass it to
// StreamDialer.DialStream (the dialer wraps the SS endpoint, so the target
// address is what the SS protocol expects as payload destination).
// sing-box always sends CONNECT with ATYP=03 (domain) or 01/04 (IPv4/IPv6).
func socks5Handshake(c net.Conn) (string, error) {
	buf := make([]byte, 262)
	// Greeting: VER(1) NMETHODS(1) METHODS(NMETHODS)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", errors.New("not socks5")
	}
	nm := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nm]); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return "", err
	}
	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(c, buf[:dlen]); err != nil {
			return "", err
		}
		host = string(buf[:dlen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", errors.New("unknown ATYP")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	port := int(buf[0])<<8 | int(buf[1])
	// Use JoinHostPort so IPv6 addresses get wrapped in brackets.
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// pipe copies traffic in both directions between a (client) and b (remote)
// until both halves close. Crucially we wait for BOTH halves to finish, not
// just one — closing prematurely on the first finished half kills the other
// direction (we previously saw download=0 because the upload half completed
// first and triggered defer client.Close()).
func pipe(a, b net.Conn) {
	type halfResult struct {
		bytes int64
		dir   string
		err   error
	}
	done := make(chan halfResult, 2)
	go func() {
		n, err := io.Copy(a, b)
		// Got EOF from b → no more data from remote. Tell client we're done
		// reading from us by half-closing if possible, but keep our read open.
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- halfResult{bytes: n, dir: "down", err: err}
	}()
	go func() {
		n, err := io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- halfResult{bytes: n, dir: "up", err: err}
	}()
	first := <-done
	second := <-done
	var up, down int64
	for _, r := range []halfResult{first, second} {
		if r.dir == "up" {
			up = r.bytes
		} else {
			down = r.bytes
		}
	}
	outlineLog("pipe closed: up=%d down=%d (first=%s err=%v)", up, down, first.dir, first.err)
}

// Reference syscall to avoid unused import in case future changes drop it.
var _ = syscall.SIGTERM
