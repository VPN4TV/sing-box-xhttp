package vpn4tvbridge

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestExtractRemovesKeyAndParsesBridges(t *testing.T) {
	const profile = `{
		"vpn4tv": {
			"xray": {"outbounds": []},
			"outline": {"endpoints": [{"url": "ss://x", "port": 43890}]}
		},
		"outbounds": [{"type": "socks", "tag": "a"}]
	}`
	cleaned, config, err := Extract(profile)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if strings.Contains(cleaned, Key) {
		t.Fatalf("private key left in the config: %s", cleaned)
	}
	var root map[string]json.RawMessage
	if err = json.Unmarshal([]byte(cleaned), &root); err != nil {
		t.Fatalf("cleaned config is not valid JSON: %v", err)
	}
	if _, loaded := root["outbounds"]; !loaded {
		t.Fatal("cleaned config lost the rest of the profile")
	}
	if config.IsEmpty() {
		t.Fatal("bridge config not parsed")
	}
	if len(config.Xray) == 0 || len(config.Outline) == 0 {
		t.Fatalf("missing bridge sections: %+v", config)
	}
	if len(config.Wireproxy) != 0 {
		t.Fatal("absent section should stay empty")
	}
}

func TestExtractPassesThroughPlainProfiles(t *testing.T) {
	const profile = `{"outbounds": [{"type": "direct"}]}`
	cleaned, config, err := Extract(profile)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if cleaned != profile {
		t.Fatalf("profile was rewritten: %s", cleaned)
	}
	if !config.IsEmpty() {
		t.Fatal("expected no bridge config")
	}
}

func TestExtractLeavesInvalidJSONToTheRealParser(t *testing.T) {
	const profile = `not json at all`
	cleaned, config, err := Extract(profile)
	if err != nil {
		t.Fatalf("extract should not fail here: %v", err)
	}
	if cleaned != profile || !config.IsEmpty() {
		t.Fatal("invalid input must be passed through untouched")
	}
}

func TestStartStopsEverythingOnFailure(t *testing.T) {
	var started, stopped []string
	StartXrayHook = func(string) error { started = append(started, "xray"); return nil }
	StartOutlineHook = func(string) error { return errors.New("boom") }
	StartWireproxyHook = func(string) error { started = append(started, "wireproxy"); return nil }
	StopXrayHook = func() error { stopped = append(stopped, "xray"); return nil }
	StopOutlineHook = func() error { stopped = append(stopped, "outline"); return nil }
	StopWireproxyHook = func() error { stopped = append(stopped, "wireproxy"); return nil }
	defer func() {
		StartXrayHook, StartOutlineHook, StartWireproxyHook = nil, nil, nil
		StopXrayHook, StopOutlineHook, StopWireproxyHook = nil, nil, nil
	}()

	config := &Config{
		Xray:      json.RawMessage(`{}`),
		Outline:   json.RawMessage(`{}`),
		Wireproxy: json.RawMessage(`{}`),
	}
	if err := Start(config); err == nil {
		t.Fatal("expected the outline failure to surface")
	}
	if len(started) != 1 || started[0] != "xray" {
		t.Fatalf("wireproxy must not start after a failure: %v", started)
	}
	if len(stopped) != 3 {
		t.Fatalf("every bridge should be stopped after a failed start: %v", stopped)
	}
}

func TestStartIsNoOpWithoutConfig(t *testing.T) {
	if err := Start(nil); err != nil {
		t.Fatalf("nil config should be a no-op: %v", err)
	}
	if err := Start(&Config{}); err != nil {
		t.Fatalf("empty config should be a no-op: %v", err)
	}
}
