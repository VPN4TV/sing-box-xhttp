package libbox

import "testing"

func TestParseOlcrtcURI(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	parsed, err := parseOlcrtcURI("olcrtc://jitsi?datachannel@https://meet.example.org/room-42#" + key + "$RU%20/%20test")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Provider != "jitsi" || parsed.Transport != "datachannel" || parsed.Room != "https://meet.example.org/room-42" || parsed.KeyHex != key || parsed.Comment != "RU / test" {
		t.Fatalf("unexpected parse: %+v", parsed)
	}

	parsed, err = parseOlcrtcURI("olcrtc://wbstream?vp8channel<vp8-fps=15&vp8-batch=32>@stream-id#" + key)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Transport != "vp8channel" || parsed.paramInt("vp8-fps") != 15 || parsed.paramInt("vp8-batch") != 32 || parsed.Room != "stream-id" || parsed.Comment != "" {
		t.Fatalf("unexpected parse: %+v", parsed)
	}

	for _, bad := range []string{
		"ss://x",
		"olcrtc://jitsi?datachannel@room",
		"olcrtc://jitsi?datachannel@room#tooshort",
		"olcrtc://jitsi?datachannel@room#" + key[:63] + "g",
		"olcrtc://jitsi@room#" + key,
	} {
		if _, err := parseOlcrtcURI(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
