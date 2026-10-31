//go:build with_utls

package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// testdata/chrome155_clienthello.hex is the first TLS record of a fresh connection made by Google Chrome
// 155.0.8059.40 (macOS arm64) to https://www.example.com/, taken from refraction-networking/utls
// (testdata/chrome155_clienthello.hex at 6ebdceb2607e, BSD-3-Clause).

type helloExtension struct {
	id   uint16
	body []byte
}

type parsedHello struct {
	ciphers    []uint16
	extensions []helloExtension
}

func isGREASEValue(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func normalizeGREASE(v uint16) uint16 {
	if isGREASEValue(v) {
		return 0x0a0a
	}
	return v
}

func parseHelloForTest(t *testing.T, raw []byte) parsedHello {
	t.Helper()
	if raw[0] == 0x16 {
		raw = raw[5:] // TLS record header
	}
	require.Equal(t, byte(1), raw[0], "not a ClientHello")
	p := 4 + 2 + 32
	p += 1 + int(raw[p])
	cipherLen := int(binary.BigEndian.Uint16(raw[p:]))
	var hello parsedHello
	for i := 0; i < cipherLen; i += 2 {
		hello.ciphers = append(hello.ciphers, normalizeGREASE(binary.BigEndian.Uint16(raw[p+2+i:])))
	}
	p += 2 + cipherLen
	p += 1 + int(raw[p])
	end := p + 2 + int(binary.BigEndian.Uint16(raw[p:]))
	for p += 2; p < end; {
		id := binary.BigEndian.Uint16(raw[p:])
		length := int(binary.BigEndian.Uint16(raw[p+2:]))
		hello.extensions = append(hello.extensions, helloExtension{normalizeGREASE(id), raw[p+4 : p+4+length]})
		p += 4 + length
	}
	return hello
}

func (h parsedHello) extension(id uint16) []byte {
	for _, ext := range h.extensions {
		if ext.id == id {
			return ext.body
		}
	}
	return nil
}

// uint16List decodes a length-prefixed list of uint16 (groups, signature schemes), GREASE normalized.
func uint16List(body []byte, prefix int) []uint16 {
	var values []uint16
	for i := prefix; i+1 < len(body); i += 2 {
		values = append(values, normalizeGREASE(binary.BigEndian.Uint16(body[i:])))
	}
	return values
}

type keyShareShape struct {
	group  uint16
	length int
}

func keyShareShapes(body []byte) []keyShareShape {
	var shapes []keyShareShape
	for i := 2; i < len(body); {
		group := binary.BigEndian.Uint16(body[i:])
		length := int(binary.BigEndian.Uint16(body[i+2:]))
		shapes = append(shapes, keyShareShape{normalizeGREASE(group), length})
		i += 4 + length
	}
	return shapes
}

func buildTestHello(t *testing.T, id utls.ClientHelloID) (*utls.UConn, parsedHello) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	uConn, err := newUClient(client, &utls.Config{ServerName: "www.example.com"}, id)
	require.NoError(t, err)
	require.NoError(t, uConn.BuildHandshakeState())
	return uConn, parseHelloForTest(t, uConn.HandshakeState.Hello.Raw)
}

func TestChrome155MatchesBrowserCapture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/chrome155_clienthello.hex")
	require.NoError(t, err)
	captureRaw, err := hex.DecodeString(strings.TrimSpace(strings.ReplaceAll(string(data), ":", "")))
	require.NoError(t, err)
	capture := parseHelloForTest(t, captureRaw)

	for range 20 { // extension order and GREASE values are random: check several hellos
		_, ours := buildTestHello(t, helloChrome155)
		require.Equal(t, capture.ciphers, ours.ciphers, "cipher suites")

		// GREASE extensions stay first and last, the rest are shuffled like Chrome does.
		require.Equal(t, uint16(0x0a0a), ours.extensions[0].id)
		require.Equal(t, uint16(0x0a0a), ours.extensions[len(ours.extensions)-1].id)
		ids := func(h parsedHello) []uint16 {
			var list []uint16
			for _, ext := range h.extensions {
				list = append(list, ext.id)
			}
			slices.Sort(list)
			return list
		}
		require.Equal(t, ids(capture), ids(ours), "extension set")

		require.Equal(t, uint16List(capture.extension(0x000a), 2), uint16List(ours.extension(0x000a), 2), "supported_groups")
		require.Equal(t, uint16List(capture.extension(0x000d), 2), uint16List(ours.extension(0x000d), 2), "signature_algorithms")
		require.Equal(t, uint16List(capture.extension(0x002b), 1), uint16List(ours.extension(0x002b), 1), "supported_versions")
		require.Equal(t, keyShareShapes(capture.extension(0x0033)), keyShareShapes(ours.extension(0x0033)), "key_share")
		// Bodies that carry no randomness must match the browser byte for byte.
		for _, id := range []uint16{0x0000, 0x0005, 0x000b, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002d, 0x44cd, 0xca34, 0xff01} {
			require.True(t, bytes.Equal(capture.extension(id), ours.extension(id)), "extension %#04x body", id)
		}
		require.NotEmpty(t, ours.extension(0xfe0d), "GREASE ECH")

		// The GREASE value in signature_algorithms is a real GREASE codepoint, not the placeholder constant.
		require.True(t, isGREASEValue(binary.BigEndian.Uint16(ours.extension(0x000d)[2:])))
	}
}

func TestChrome155GREASESignatureVaries(t *testing.T) {
	t.Parallel()
	seen := make(map[utls.SignatureScheme]bool)
	for range 200 {
		seen[greaseSignatureScheme()] = true
	}
	require.Greater(t, len(seen), 8, "GREASE signature scheme should be random")
	for scheme := range seen {
		require.True(t, isGREASEValue(uint16(scheme)))
	}
}

func TestUTLSFingerprintNames(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]utls.ClientHelloID{
		"":                 helloChrome155,
		"chrome":           helloChrome155,
		"Chrome":           helloChrome155,
		"chrome133":        utls.HelloChrome_133,
		"hellochrome_133":  utls.HelloChrome_133,
		"firefox":          utls.HelloFirefox_148,
		"hellofirefox_148": utls.HelloFirefox_148,
		"safari":           utls.HelloSafari_26_3,
		"hellosafari_26_3": utls.HelloSafari_26_3,
		"edge":             utls.HelloEdge_Auto,
		"ios":              utls.HelloIOS_Auto,
	} {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err, name)
		require.Equal(t, want, id, name)
	}
	_, err := uTLSClientHelloID("netscape")
	require.Error(t, err)
}
