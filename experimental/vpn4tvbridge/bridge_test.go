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

// Attach is what keeps FormatConfig from eating the bridges: the client stores
// whatever it gets back, so a stripped config would lose them for good.
func TestAttachRestoresBridges(t *testing.T) {
	original := `{"log":{"level":"info"},"vpn4tv":{"outline":{"endpoints":[{"url":"ss://x@1.2.3.4:8388","port":43890}]}},"outbounds":[]}`

	stripped, config, err := Extract(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stripped, Key) {
		t.Fatal("Extract left the bridge key in the config")
	}

	restored, err := Attach(stripped, config)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trips: what comes back out equals what went in.
	_, again, err := Extract(restored)
	if err != nil {
		t.Fatal(err)
	}
	if again == nil || again.Outline == nil {
		t.Fatal("the outline bridge did not survive the round trip")
	}
	if !strings.Contains(restored, "1.2.3.4:8388") {
		t.Fatal("the endpoint was lost")
	}
	// The rest of the config is untouched.
	if !strings.Contains(restored, `"level"`) {
		t.Fatal("the log section was lost")
	}
}

// A config without bridges must come back byte for byte, so Attach is safe to
// call unconditionally.
func TestAttachWithoutBridgesIsNoop(t *testing.T) {
	plain := `{"outbounds":[]}`
	restored, err := Attach(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if restored != plain {
		t.Fatalf("expected the config unchanged, got %s", restored)
	}
}
