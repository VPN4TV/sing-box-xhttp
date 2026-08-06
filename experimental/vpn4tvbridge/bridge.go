// Package vpn4tvbridge lets a sing-box config carry the configuration of the
// embedded VPN4TV bridges (xray / outline / wireproxy) so the CORE can start
// them itself.
//
// On mobile the app drives the bridges explicitly (libbox.StartXrayInstance and
// friends are gomobile exports called from Swift/Kotlin before the tunnel comes
// up). The desktop client has no such channel — it only talks gRPC to the
// daemon — so instead the bridge configs travel inside the profile under a
// private top-level "vpn4tv" key:
//
//	{
//	  "vpn4tv": {
//	    "xray":      { ... xray-core config ... },
//	    "outline":   { "endpoints": [ { "url": "ss://...", "port": 43890 } ] },
//	    "wireproxy": { "endpoints": [ { "ini": "[Interface]...", "port": 44890 } ] }
//	  },
//	  "outbounds": [ ... socks outbounds pointing at those ports ... ]
//	}
//
// sing-box parses configs strictly, so Extract must remove the key before the
// rest of the pipeline sees it.
package vpn4tvbridge

import (
	"encoding/json"

	E "github.com/sagernet/sing/common/exceptions"
)

// Hooks installed by experimental/libbox at init time. This package must not
// import libbox: libbox imports daemon, and daemon imports this package, so a
// direct dependency would close an import cycle. Inverting it keeps the bridge
// implementations (which need libbox's platform interface for socket
// protection on Android) exactly where they are.
var (
	StartXrayHook      func(configJSON string) error
	StartOutlineHook   func(configJSON string) error
	StartWireproxyHook func(configJSON string) error
	StopXrayHook       func() error
	StopOutlineHook    func() error
	StopWireproxyHook  func() error
)

// Key is the private top-level config field carrying the bridge configs.
const Key = "vpn4tv"

// Config holds the three bridge configurations, each in the exact shape its
// libbox entry point already expects.
type Config struct {
	Xray      json.RawMessage `json:"xray,omitempty"`
	Outline   json.RawMessage `json:"outline,omitempty"`
	Wireproxy json.RawMessage `json:"wireproxy,omitempty"`
}

// IsEmpty reports whether there is nothing to start.
func (c *Config) IsEmpty() bool {
	return c == nil || (len(c.Xray) == 0 && len(c.Outline) == 0 && len(c.Wireproxy) == 0)
}

// Extract pulls the "vpn4tv" key out of a profile and returns the profile
// without it plus the parsed bridge config (nil when the key is absent).
// A profile that is not a JSON object is returned untouched.
func Extract(configContent string) (string, *Config, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configContent), &root); err != nil {
		// Not an object (or invalid) — let the normal parser report it.
		return configContent, nil, nil
	}
	raw, loaded := root[Key]
	if !loaded {
		return configContent, nil, nil
	}
	delete(root, Key)
	cleaned, err := json.Marshal(root)
	if err != nil {
		return configContent, nil, E.Cause(err, "vpn4tv: re-encode config")
	}
	var config Config
	if err = json.Unmarshal(raw, &config); err != nil {
		return string(cleaned), nil, E.Cause(err, "vpn4tv: parse bridge config")
	}
	return string(cleaned), &config, nil
}

// Start brings up every bridge present in the config. Bridges are process-wide
// singletons in libbox, so starting replaces whatever ran before. On the first
// failure the already-started bridges are stopped again, so a failed start
// never leaves half a chain running.
// Attach puts the bridge configs back into a config that Extract stripped.
// Formatting a profile must not silently drop them: the client stores what it
// gets back, and the bridges would be gone from the next start onwards.
func Attach(configContent string, config *Config) (string, error) {
	if config == nil || config.IsEmpty() {
		return configContent, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configContent), &root); err != nil {
		return "", E.Cause(err, "attach bridge config")
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", E.Cause(err, "encode bridge config")
	}
	root[Key] = encoded
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", E.Cause(err, "encode config")
	}
	return string(out), nil
}

func Start(config *Config) error {
	if config.IsEmpty() {
		return nil
	}
	// The hooks are installed by experimental/libbox. A binary that carries
	// bridge configs but never linked libbox would otherwise start with the
	// socks outbounds pointing at nothing — fail loudly instead.
	if StartXrayHook == nil && StartOutlineHook == nil && StartWireproxyHook == nil {
		return E.New("vpn4tv: config carries bridges but no bridge runtime is linked into this binary")
	}
	if len(config.Xray) > 0 && StartXrayHook != nil {
		if err := StartXrayHook(string(config.Xray)); err != nil {
			Stop()
			return E.Cause(err, "vpn4tv: start xray bridge")
		}
	}
	if len(config.Outline) > 0 && StartOutlineHook != nil {
		if err := StartOutlineHook(string(config.Outline)); err != nil {
			Stop()
			return E.Cause(err, "vpn4tv: start outline bridge")
		}
	}
	if len(config.Wireproxy) > 0 && StartWireproxyHook != nil {
		if err := StartWireproxyHook(string(config.Wireproxy)); err != nil {
			Stop()
			return E.Cause(err, "vpn4tv: start wireproxy bridge")
		}
	}
	return nil
}

// Stop tears down every bridge. Safe to call when nothing is running.
func Stop() {
	for _, stop := range []func() error{StopXrayHook, StopOutlineHook, StopWireproxyHook} {
		if stop != nil {
			_ = stop()
		}
	}
}
