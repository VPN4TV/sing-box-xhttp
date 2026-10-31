//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

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

func TestChrome155ExtensionShuffleIsUniform(t *testing.T) {
	t.Parallel()
	name := func(extension utls.TLSExtension) string {
		if generic, isGeneric := extension.(*utls.GenericExtension); isGeneric {
			return fmt.Sprintf("generic %#04x", generic.Id)
		}
		return fmt.Sprintf("%T", extension)
	}
	template := chrome155Extensions()
	const samples = 6000
	inPlace := make([]int, len(template))
	var total int
	for range samples {
		shuffled := shuffleChromeExtensions(chrome155Extensions())
		require.IsType(t, &utls.UtlsGREASEExtension{}, shuffled[0])
		require.IsType(t, &utls.UtlsGREASEExtension{}, shuffled[len(shuffled)-1])
		for i := 1; i < len(template)-1; i++ {
			if name(shuffled[i]) == name(template[i]) {
				inPlace[i]++
				total++
			}
		}
	}
	// A uniform permutation leaves one extension in its template position on average, like BoringSSL does;
	// utls.ShuffleChromeTLSExtensions leaves 17/9.
	require.InDelta(t, 1, float64(total)/samples, 0.1, "extensions in place per ClientHello")
	for i := 1; i < len(template)-1; i++ {
		require.InDelta(t, 1/float64(len(template)-2), float64(inPlace[i])/samples, 0.02, "%s in place", name(template[i]))
	}
}

func TestChrome155TrustAnchorCertificates(t *testing.T) {
	t.Parallel()
	// SHA-256 of the certificates of chrome155TrustAnchorIDs, in the same order (Chrome root_store.textproto).
	want := []string{
		"96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6", // 44947.2.1 ISRG Root X1
		"69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470", // 44947.2.6 ISRG Root X2
		"54715420224c5b65beed018dc3940d7338c577e322d5488f633d8c6a8fed61b2", // 44947.2.13 E7
		"ac1274542267f17b525535b5563bf731febb182533b46a82dc869cb64eb528c0", // 44947.2.14 E8
		"4185df97806c2ba76f1d79823f112ffa639a49ccdc990908102067ab6412b886", // 44947.2.15 E9
		"131fce7784016899a5a00203a9efc80f18ebbd75580717edc1553580930836ec", // 44947.2.18 R12
		"d3b128216a843f8ef1321501f5df52a5df52939ee2c19297712cd3de4d419354", // 44947.2.19 R13
		"24d45aa9b8d6053d281f3842c8cc0c6c1af7ccdfd42dd5c12f6a74fa9323f7a2", // 44947.2.20 R14
		"8fe4fb0af93a4d0d67db0bebb23e37c71bf325dcbcdd240ea04daf58b47e1840", // 52580.200109.1.7 QuoVadis Root CA 2 G3
		"88ef81de202eb018452e43f864725cea5fbd1fc2d9d205730709c5d8b8690f46", // 52580.200109.1.8 QuoVadis Root CA 3 G3
		"cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f", // 52580.200109.1.9 DigiCert Global Root G2
		"31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0", // 52580.200109.1.10 DigiCert Global Root G3
		"552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988", // 52580.200109.1.11 DigiCert Trusted Root G4
		"7d05ebb682339f8c9451ee094eebfefa7953a114edb2f44949452fab7d2fc185", // 52580.200109.1.12 DigiCert Assured ID Root G2
		"7e37cb8b4c47090cab36551ba6f45db840680fba166a952db100717f43053fc2", // 52580.200109.1.13 DigiCert Assured ID Root G3
		"371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75", // 52580.200109.1.18 DigiCert TLS RSA4096 Root G5
		"018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05", // 52580.200109.1.19 DigiCert TLS ECC P384 Root G5
		"d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf", // 11129.9.1 GTS Root R1
		"349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d", // 11129.9.4 GTS Root R4
		"b10b6f00e609509e8700f6d34687a2bfce38ea05a8fdf1cdc40c3a2a0d0d0e45", // 11129.9.5 WR1
		"e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4", // 11129.9.6 WR2
		"2fe357db13751ff9160e87354975b3407498f41c9bd16a48657866e6e5a9b4c7", // 11129.9.7 WR3
		"dc9416c2f855126d6de977677538f2f967ff4998e90dfa435a17219be077fc06", // 11129.9.8 WR4
		"1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96", // 11129.9.10 WE1
		"9c3f2fd11c57d7c649ad5a0932c0f0d29756f6a0a1c74c43e1e89a62d64cd320", // 11129.9.11 WE2
		"9f819a4c876e12dc84e6fe0e37c1a69b137094b453fa98449398f4b71f4d0092", // 11129.9.12 WE3
		"d0c97e56c7b0ba812d944ad771f7799b5d4144a2327a4e416554f7ee2aa0aeae", // 11129.9.13 WE4
		"812c212e9e45dc5005c7f47411183f5fb2ff1baee184d3354b2e93d78c280164", // 11129.9.15 AE1
	}
	certificates := chrome155AnchorCertificates()
	require.Len(t, want, len(chrome155TrustAnchorIDs))
	require.Len(t, certificates, len(want))
	for i, certificate := range certificates {
		sum := sha256.Sum256(certificate.Raw)
		require.Equal(t, want[i], hex.EncodeToString(sum[:]), certificate.Subject.String())
	}
}

func TestChrome155RootCAs(t *testing.T) {
	t.Parallel()
	rootCAs := func(fingerprint string, certificate []string) *x509.CertPool {
		config, err := newUTLSClient(context.Background(), nil, "www.example.com", option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "www.example.com",
			Certificate: certificate,
			UTLS:        &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		}, false)
		require.NoError(t, err)
		return config.(*UTLSClientConfig).config.RootCAs
	}
	if platformVerifiesSystemPool {
		require.Nil(t, rootCAs("chrome", nil), "the platform verifier keeps the system roots")
	} else {
		//nolint:staticcheck // Subjects lists the certificates added to a pool, which is what is checked here
		require.GreaterOrEqual(t, len(rootCAs("chrome", nil).Subjects()), len(chrome155TrustAnchorIDs))
	}
	require.Nil(t, rootCAs("firefox", nil), "other profiles keep the system roots")
	// The user's own certificate replaces the roots, and nothing is added to it.
	block, _ := pem.Decode(chrome155AnchorsPEM)
	userPool := rootCAs("chrome", []string{string(pem.EncodeToMemory(block))})
	//nolint:staticcheck
	require.Len(t, userPool.Subjects(), 1)
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
