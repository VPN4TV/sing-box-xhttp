package vpn4tvbridge

// VPN4TV: TrustTunnel (AdGuard's HTTP/2 + HTTP/3 VPN protocol) as a bridge on
// the desktop. The client is C++/Rust, so unlike the other bridges it does not
// live in this process: the official `trusttunnel_client` CLI is shipped next
// to the daemon and run as a child process in SOCKS mode, one per tt:// link,
// and sing-box reaches it through a socks outbound like any other bridge.
//
// The tt:// link is decoded here — it is a small TLV blob (QUIC varints,
// base64url) documented by the endpoint's deeplink crate — and written as the
// CLI's TOML next to the daemon's working directory. The password is in that
// file, so it is created 0600 and removed when the bridge stops.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// TrustTunnelConfig is the bridge section of the profile:
//
//	"trusttunnel": { "endpoints": [ { "url": "tt://?...", "port": 46890, "listen": "127.0.0.1" } ] }
type TrustTunnelConfig struct {
	Endpoints []TrustTunnelEndpoint `json:"endpoints"`
}

type TrustTunnelEndpoint struct {
	URL    string `json:"url"`
	Port   int    `json:"port"`
	Listen string `json:"listen,omitempty"`
}

// TrustTunnelBinary overrides where the CLI is looked for. Empty means next to
// this executable, which after installation is a root-only directory on every
// platform (the privileged helper on macOS, the service directory elsewhere).
var TrustTunnelBinary string

// TrustTunnelWorkDir is where the per-endpoint TOML files go. Empty means the
// process working directory (the daemon's, which is root-only).
var TrustTunnelWorkDir string

// DeepLink is what a tt:// link carries (deeplink crate, TLV version 1).
type DeepLink struct {
	Hostname           string
	Addresses          []string
	Username           string
	Password           string
	ClientRandomPrefix string
	CustomSNI          string
	HasIPv6            bool
	SkipVerification   bool
	CertificateDER     []byte
	UpstreamProtocol   string
	AntiDPI            bool
	Name               string
	DNSUpstreams       []string
}

const (
	tlvVersion            = 0x00
	tlvHostname           = 0x01
	tlvAddress            = 0x02
	tlvCustomSNI          = 0x03
	tlvHasIPv6            = 0x04
	tlvUsername           = 0x05
	tlvPassword           = 0x06
	tlvSkipVerification   = 0x07
	tlvCertificate        = 0x08
	tlvUpstreamProtocol   = 0x09
	tlvAntiDPI            = 0x0A
	tlvClientRandomPrefix = 0x0B
	tlvName               = 0x0C
	tlvDNSUpstreams       = 0x0D
	deepLinkVersion       = 1
)

// readVarint reads a QUIC-style variable-length integer (2-bit length prefix).
func readVarint(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, errors.New("truncated varint")
	}
	first := data[offset]
	size := 1 << (first >> 6)
	if offset+size > len(data) {
		return 0, 0, errors.New("truncated varint")
	}
	value := uint64(first & 0x3F)
	for i := 1; i < size; i++ {
		value = value<<8 | uint64(data[offset+i])
	}
	return value, offset + size, nil
}

func decodeStringArray(data []byte) ([]string, error) {
	var result []string
	offset := 0
	for offset < len(data) {
		length, next, err := readVarint(data, offset)
		if err != nil {
			return nil, err
		}
		end := next + int(length)
		if end > len(data) {
			return nil, errors.New("truncated list entry")
		}
		result = append(result, string(data[next:end]))
		offset = end
	}
	return result, nil
}

func decodeBool(data []byte) (bool, error) {
	if len(data) != 1 || data[0] > 1 {
		return false, errors.New("invalid boolean")
	}
	return data[0] == 1, nil
}

// DecodeDeepLink parses a tt:// or tt://? link.
func DecodeDeepLink(uri string) (*DeepLink, error) {
	if !strings.HasPrefix(uri, "tt://") {
		return nil, errors.New("trusttunnel: not a tt:// link")
	}
	encoded := strings.TrimPrefix(strings.TrimPrefix(uri, "tt://"), "?")
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return nil, E.Cause(err, "trusttunnel: decode link")
	}
	link := &DeepLink{HasIPv6: true, UpstreamProtocol: "http2"}
	offset := 0
	for offset < len(payload) {
		tag, next, err := readVarint(payload, offset)
		if err != nil {
			return nil, err
		}
		length, next, err := readVarint(payload, next)
		if err != nil {
			return nil, err
		}
		end := next + int(length)
		if end > len(payload) {
			return nil, fmt.Errorf("trusttunnel: truncated field 0x%02x", tag)
		}
		value := payload[next:end]
		offset = end
		switch tag {
		case tlvVersion:
			version, _, err := readVarint(value, 0)
			if err != nil {
				return nil, err
			}
			if version > deepLinkVersion {
				return nil, fmt.Errorf("trusttunnel: link version %d is newer than supported", version)
			}
		case tlvHostname:
			link.Hostname = string(value)
		case tlvAddress:
			link.Addresses = append(link.Addresses, string(value))
		case tlvCustomSNI:
			link.CustomSNI = string(value)
		case tlvHasIPv6:
			if link.HasIPv6, err = decodeBool(value); err != nil {
				return nil, err
			}
		case tlvUsername:
			link.Username = string(value)
		case tlvPassword:
			link.Password = string(value)
		case tlvSkipVerification:
			if link.SkipVerification, err = decodeBool(value); err != nil {
				return nil, err
			}
		case tlvCertificate:
			link.CertificateDER = append([]byte(nil), value...)
		case tlvUpstreamProtocol:
			if len(value) != 1 {
				return nil, errors.New("trusttunnel: invalid protocol")
			}
			switch value[0] {
			case 1:
				link.UpstreamProtocol = "http2"
			case 2:
				link.UpstreamProtocol = "http3"
			default:
				return nil, fmt.Errorf("trusttunnel: unknown protocol %d", value[0])
			}
		case tlvAntiDPI:
			if link.AntiDPI, err = decodeBool(value); err != nil {
				return nil, err
			}
		case tlvClientRandomPrefix:
			prefix := string(value)
			prefixPart, maskPart, _ := strings.Cut(prefix, "/")
			if _, err := hex.DecodeString(prefixPart); err != nil {
				return nil, E.Cause(err, "trusttunnel: client random prefix")
			}
			if _, err := hex.DecodeString(maskPart); err != nil {
				return nil, E.Cause(err, "trusttunnel: client random mask")
			}
			link.ClientRandomPrefix = prefix
		case tlvName:
			link.Name = string(value)
		case tlvDNSUpstreams:
			if link.DNSUpstreams, err = decodeStringArray(value); err != nil {
				return nil, err
			}
		default:
			// Unknown tags are skipped, as the reference decoder does.
		}
	}
	switch {
	case link.Hostname == "":
		return nil, errors.New("trusttunnel: link has no hostname")
	case len(link.Addresses) == 0:
		return nil, errors.New("trusttunnel: link has no addresses")
	case link.Username == "" || link.Password == "":
		return nil, errors.New("trusttunnel: link has no credentials")
	}
	return link, nil
}

func tomlString(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value) + `"`
}

func tomlStrings(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, tomlString(value))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// ClientTOML renders the CLI configuration for SOCKS mode on listen:port.
func (l *DeepLink) ClientTOML(listen string, port int) string {
	var b strings.Builder
	// The CLI refuses a config without vpn_mode; the kill switch is a TUN
	// feature and must stay off, or the SOCKS listener blocks when the
	// endpoint drops instead of letting sing-box fail over.
	b.WriteString("vpn_mode = \"general\"\nkillswitch_enabled = false\n\n[endpoint]\n")
	fmt.Fprintf(&b, "hostname = %s\n", tomlString(l.Hostname))
	fmt.Fprintf(&b, "addresses = %s\n", tomlStrings(l.Addresses))
	fmt.Fprintf(&b, "has_ipv6 = %t\n", l.HasIPv6)
	fmt.Fprintf(&b, "username = %s\n", tomlString(l.Username))
	fmt.Fprintf(&b, "password = %s\n", tomlString(l.Password))
	if l.ClientRandomPrefix != "" {
		fmt.Fprintf(&b, "client_random = %s\n", tomlString(l.ClientRandomPrefix))
	}
	fmt.Fprintf(&b, "skip_verification = %t\n", l.SkipVerification)
	if len(l.CertificateDER) > 0 {
		var pemText bytes.Buffer
		// The link packs one or more DER certificates back to back.
		rest := l.CertificateDER
		for len(rest) > 0 {
			size := derSequenceLength(rest)
			if size <= 0 || size > len(rest) {
				break
			}
			_ = pem.Encode(&pemText, &pem.Block{Type: "CERTIFICATE", Bytes: rest[:size]})
			rest = rest[size:]
		}
		fmt.Fprintf(&b, "certificate = %s\n", tomlString(pemText.String()))
	}
	fmt.Fprintf(&b, "upstream_protocol = %s\n", tomlString(l.UpstreamProtocol))
	fmt.Fprintf(&b, "anti_dpi = %t\n", l.AntiDPI)
	if l.CustomSNI != "" {
		fmt.Fprintf(&b, "custom_sni = %s\n", tomlString(l.CustomSNI))
	}
	if len(l.DNSUpstreams) > 0 {
		fmt.Fprintf(&b, "dns_upstreams = %s\n", tomlStrings(l.DNSUpstreams))
	}
	fmt.Fprintf(&b, "\n[listener.socks]\naddress = %s\n", tomlString(fmt.Sprintf("%s:%d", listen, port)))
	return b.String()
}

// derSequenceLength returns the total length of the DER SEQUENCE at the start
// of data, or 0 when it is not one.
func derSequenceLength(data []byte) int {
	if len(data) < 2 || data[0] != 0x30 {
		return 0
	}
	first := int(data[1])
	if first < 0x80 {
		return 2 + first
	}
	count := first & 0x7F
	if count == 0 || 2+count > len(data) {
		return 0
	}
	length := 0
	for i := 0; i < count; i++ {
		length = length<<8 | int(data[2+i])
	}
	return 2 + count + length
}

type trustTunnelProcess struct {
	command    *exec.Cmd
	configPath string
}

var (
	trustTunnelMu        sync.Mutex
	trustTunnelProcesses []*trustTunnelProcess
)

func trustTunnelBinaryPath() (string, error) {
	if TrustTunnelBinary != "" {
		return TrustTunnelBinary, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", E.Cause(err, "trusttunnel: locate daemon executable")
	}
	self, _ = filepath.EvalSymlinks(self)
	name := "trusttunnel_client"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(filepath.Dir(self), name)
	if _, err := os.Stat(path); err != nil {
		return "", E.Cause(err, "trusttunnel: client is not installed next to the daemon")
	}
	return path, nil
}

// StartTrustTunnel runs one CLI per endpoint. Replaces a running bridge.
func StartTrustTunnel(configJSON string) error {
	trustTunnelMu.Lock()
	defer trustTunnelMu.Unlock()
	stopTrustTunnelLocked()

	var config TrustTunnelConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return E.Cause(err, "trusttunnel: parse config")
	}
	if len(config.Endpoints) == 0 {
		return errors.New("trusttunnel: no endpoints")
	}
	binary, err := trustTunnelBinaryPath()
	if err != nil {
		return err
	}
	workDir := TrustTunnelWorkDir
	if workDir == "" {
		workDir, _ = os.Getwd()
	}
	for index, endpoint := range config.Endpoints {
		link, err := DecodeDeepLink(endpoint.URL)
		if err != nil {
			stopTrustTunnelLocked()
			return fmt.Errorf("trusttunnel: endpoint %d: %w", index, err)
		}
		listen := endpoint.Listen
		if listen == "" {
			listen = "127.0.0.127"
		}
		configPath := filepath.Join(workDir, fmt.Sprintf("trusttunnel-%d.toml", index))
		if err := os.WriteFile(configPath, []byte(link.ClientTOML(listen, endpoint.Port)), 0o600); err != nil {
			stopTrustTunnelLocked()
			return fmt.Errorf("trusttunnel: endpoint %d: write config: %w", index, err)
		}
		command := exec.Command(binary, "-c", configPath, "-l", "info")
		command.Dir = workDir
		command.Stdout = os.Stderr
		command.Stderr = os.Stderr
		if err := command.Start(); err != nil {
			_ = os.Remove(configPath)
			stopTrustTunnelLocked()
			return fmt.Errorf("trusttunnel: endpoint %d: start %s: %w", index, binary, err)
		}
		trustTunnelProcesses = append(trustTunnelProcesses, &trustTunnelProcess{command: command, configPath: configPath})
	}
	return nil
}

// StopTrustTunnel ends every client process and removes its config.
func StopTrustTunnel() error {
	trustTunnelMu.Lock()
	defer trustTunnelMu.Unlock()
	stopTrustTunnelLocked()
	return nil
}

func stopTrustTunnelLocked() {
	for _, process := range trustTunnelProcesses {
		if process.command.Process != nil {
			_ = process.command.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _ = process.command.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = process.command.Process.Kill()
				<-done
			}
		}
		_ = os.Remove(process.configPath)
	}
	trustTunnelProcesses = nil
}
