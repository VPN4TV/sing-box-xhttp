package libbox

// VPN4TV: olcRTC bridge — TCP over a WebRTC "video call" on a meeting service
// that stays reachable when nothing else does (the whitelist scenario). The
// runtime is openlibrecommunity/olcrtc (WTFPL); it exposes a local SOCKS5 that
// sing-box reaches through a socks outbound, exactly like the other bridges.
//
// This file is compiled into every build. The runtime itself lives behind the
// with_olcrtc tag (olcrtc.go); a build without it (the 32-bit ARM libbox, kept
// small for TV boxes) carries the same exported surface and refuses to start
// (olcrtc_stub.go), so the Java/Swift API is identical across ABIs.

import (
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// olcrtcConfig mirrors the other bridges: one SOCKS5 inbound per endpoint.
//
// Shape: { "endpoints": [ { "url": "olcrtc://...", "port": 45890, "listen": "127.0.0.1", "dns": "77.88.8.8:53" } ] }
type olcrtcConfig struct {
	Endpoints []olcrtcEndpoint `json:"endpoints"`
}

type olcrtcEndpoint struct {
	URL    string `json:"url"`
	Port   int    `json:"port"`
	Listen string `json:"listen,omitempty"`
	// DNS the olcrtc client resolves the meeting host with, "host:port". Under a
	// whitelist the usual public resolvers may be unreachable; empty picks the
	// built-in list (olcrtcDefaultDNS).
	DNS string `json:"dns,omitempty"`
}

// olcrtcKey is a parsed olcrtc:// link. The format is the client convention
// documented by the project (docs/uri.md), URI format v1:
//
//	olcrtc://<Provider>?<Transport>[<k=v&k=v>]@<RoomID>#<EncryptionKey>$<Comment>
type olcrtcKey struct {
	Provider  string
	Transport string
	Room      string
	KeyHex    string
	Comment   string
	Params    map[string]string
}

const olcrtcScheme = "olcrtc://"

// parseOlcrtcURI splits the link into its parts. It is deliberately lenient
// about what a room ID looks like (a Jitsi room is a full https URL), and
// strict about the encryption key, which the runtime needs as 64 hex digits.
func parseOlcrtcURI(uri string) (*olcrtcKey, error) {
	value := strings.TrimSpace(uri)
	if !strings.HasPrefix(strings.ToLower(value), olcrtcScheme) {
		return nil, errors.New("olcrtc: not an olcrtc:// link")
	}
	value = value[len(olcrtcScheme):]

	key := &olcrtcKey{Params: map[string]string{}}
	// The comment is free text after the last '$'; a room URL never carries one.
	if dollar := strings.LastIndex(value, "$"); dollar >= 0 {
		key.Comment = unescapeOlcrtc(value[dollar+1:])
		value = value[:dollar]
	}
	hash := strings.LastIndex(value, "#")
	if hash < 0 {
		return nil, errors.New("olcrtc: link carries no encryption key")
	}
	key.KeyHex = strings.ToLower(strings.TrimSpace(value[hash+1:]))
	value = value[:hash]

	question := strings.Index(value, "?")
	if question < 0 {
		return nil, errors.New("olcrtc: link carries no transport")
	}
	key.Provider = strings.ToLower(strings.TrimSpace(value[:question]))
	value = value[question+1:]

	// Transport, optionally followed by <k=v&k=v>, then '@' and the room.
	at := strings.Index(value, "@")
	if at < 0 {
		return nil, errors.New("olcrtc: link carries no room")
	}
	transportPart := value[:at]
	key.Room = strings.TrimSpace(value[at+1:])
	if open := strings.Index(transportPart, "<"); open >= 0 {
		closing := strings.LastIndex(transportPart, ">")
		if closing < open {
			return nil, errors.New("olcrtc: unterminated transport parameters")
		}
		for _, pair := range strings.Split(transportPart[open+1:closing], "&") {
			if pair == "" {
				continue
			}
			name, val, _ := strings.Cut(pair, "=")
			key.Params[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(val)
		}
		transportPart = transportPart[:open]
	}
	key.Transport = strings.ToLower(strings.TrimSpace(transportPart))

	switch {
	case key.Provider == "":
		return nil, errors.New("olcrtc: empty provider")
	case key.Transport == "":
		return nil, errors.New("olcrtc: empty transport")
	case key.Room == "":
		return nil, errors.New("olcrtc: empty room")
	case len(key.KeyHex) != 64:
		return nil, fmt.Errorf("olcrtc: encryption key must be 64 hex digits, got %d", len(key.KeyHex))
	}
	for _, r := range key.KeyHex {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return nil, errors.New("olcrtc: encryption key is not hex")
		}
	}
	return key, nil
}

func unescapeOlcrtc(value string) string {
	if decoded, err := url.PathUnescape(value); err == nil {
		return strings.TrimSpace(decoded)
	}
	return strings.TrimSpace(value)
}

// paramInt reads a numeric transport parameter, 0 when absent or malformed.
func (k *olcrtcKey) paramInt(name string) int {
	value, ok := k.Params[name]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

var (
	olcrtcLogMu    sync.Mutex
	olcrtcLogLines []string
)

const olcrtcLogMax = 200

func olcrtcLog(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	stdlog.Println("olcrtc:", line)
	olcrtcLogMu.Lock()
	defer olcrtcLogMu.Unlock()
	olcrtcLogLines = append(olcrtcLogLines, line)
	if len(olcrtcLogLines) > olcrtcLogMax {
		olcrtcLogLines = olcrtcLogLines[len(olcrtcLogLines)-olcrtcLogMax:]
	}
}

// OlcrtcLog returns the last log lines of the olcrtc bridge (see OutlineLog for
// why the string travels in a StringBox).
func OlcrtcLog() *StringBox {
	olcrtcLogMu.Lock()
	defer olcrtcLogMu.Unlock()
	return wrapString(strings.Join(olcrtcLogLines, "\n"))
}

// OlcrtcAvailable reports whether this build carries the olcrtc runtime. The
// apps use it to tell the user why an olcrtc key cannot connect on a device
// that got the small build.
func OlcrtcAvailable() bool {
	return olcrtcBuiltIn
}

func parseOlcrtcConfig(configJSON string) (*olcrtcConfig, error) {
	var cfg olcrtcConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("olcrtc: parse config: %w", err)
	}
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("olcrtc: no endpoints")
	}
	return &cfg, nil
}
