package vpn4tvbridge

import (
	"strings"
	"testing"
)

// The link the endpoint on bell exported for the test user; the password in
// it was rotated afterwards.
const testDeepLink = "tt://?AAEBAQtiZWxsLmE0ZS5hcgULdnBuNHR2LXRlc3QGGGNkNzY1OWFmM2QzM2I3NDllMjIwYTcyOAIQYmVsbC5hNGUuYXI6ODQ0MwwOVlBONFRWIFRUIHRlc3Q"

func TestDecodeDeepLink(t *testing.T) {
	link, err := DecodeDeepLink(testDeepLink)
	if err != nil {
		t.Fatal(err)
	}
	if link.Hostname != "bell.a4e.ar" || link.Username != "vpn4tv-test" || link.Name != "VPN4TV TT test" {
		t.Fatalf("unexpected fields: %+v", link)
	}
	if len(link.Addresses) != 1 || link.Addresses[0] != "bell.a4e.ar:8443" {
		t.Fatalf("unexpected addresses: %v", link.Addresses)
	}
	if link.Password != "cd7659af3d33b749e220a728" || link.UpstreamProtocol != "http2" || !link.HasIPv6 || link.SkipVerification {
		t.Fatalf("unexpected fields: %+v", link)
	}
	toml := link.ClientTOML("127.0.0.1", 46890)
	for _, want := range []string{`vpn_mode = "general"`, `killswitch_enabled = false`, `hostname = "bell.a4e.ar"`, `addresses = ["bell.a4e.ar:8443"]`, `username = "vpn4tv-test"`, "[listener.socks]", `address = "127.0.0.1:46890"`} {
		if !strings.Contains(toml, want) {
			t.Errorf("TOML lacks %q:\n%s", want, toml)
		}
	}
	// The same link without the '?' is the older spelling.
	if _, err := DecodeDeepLink("tt://" + strings.TrimPrefix(testDeepLink, "tt://?")); err != nil {
		t.Errorf("old spelling rejected: %v", err)
	}
	for _, bad := range []string{"ss://x", "tt://?AAEB", "tt://?" + strings.TrimPrefix(testDeepLink, "tt://?")[:10]} {
		if _, err := DecodeDeepLink(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
