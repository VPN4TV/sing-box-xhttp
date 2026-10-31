//go:build with_utls

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"net"

	utls "github.com/metacubex/utls"
)

// helloChrome155 is Chrome 155.0.8059.40, ported from refraction-networking/utls 6ebdceb2607e
// ("Add Chrome 155 fingerprint verified against a fresh browser capture"). metacubex/utls has no
// such ClientHelloID yet, so the ClientHello is applied from chrome155Spec as a custom preset.
var helloChrome155 = utls.ClientHelloID{Client: "Chrome", Version: "155"}

const (
	extensionTrustAnchors uint16 = 0xca34 // draft-ietf-tls-trust-anchor-ids

	signatureMLDSA44 utls.SignatureScheme = 0x0904
	signatureMLDSA65 utls.SignatureScheme = 0x0905
	signatureMLDSA87 utls.SignatureScheme = 0x0906
)

// Chrome Root Store trust anchor IDs advertised by Chrome 155, in Chrome's (lexicographic) order.
var chrome155TrustAnchorIDs = [][]byte{
	{0x82, 0xdf, 0x13, 0x02, 0x01},
	{0x82, 0xdf, 0x13, 0x02, 0x06},
	{0x82, 0xdf, 0x13, 0x02, 0x0d},
	{0x82, 0xdf, 0x13, 0x02, 0x0e},
	{0x82, 0xdf, 0x13, 0x02, 0x0f},
	{0x82, 0xdf, 0x13, 0x02, 0x12},
	{0x82, 0xdf, 0x13, 0x02, 0x13},
	{0x82, 0xdf, 0x13, 0x02, 0x14},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
	{0xd6, 0x79, 0x09, 0x01},
	{0xd6, 0x79, 0x09, 0x04},
	{0xd6, 0x79, 0x09, 0x05},
	{0xd6, 0x79, 0x09, 0x06},
	{0xd6, 0x79, 0x09, 0x07},
	{0xd6, 0x79, 0x09, 0x08},
	{0xd6, 0x79, 0x09, 0x0a},
	{0xd6, 0x79, 0x09, 0x0b},
	{0xd6, 0x79, 0x09, 0x0c},
	{0xd6, 0x79, 0x09, 0x0d},
	{0xd6, 0x79, 0x09, 0x0f},
}

func newUClient(conn net.Conn, config *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	if id != helloChrome155 {
		return utls.UClient(conn, config, id), nil
	}
	uConn := utls.UClient(conn, config, utls.HelloCustom)
	err := uConn.ApplyPreset(chrome155Spec())
	if err != nil {
		return nil, err
	}
	return uConn, nil
}

// chrome155Spec returns a fresh spec on every call: ClientHelloSpec is mutated by ApplyPreset.
func chrome155Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: shuffleChromeExtensions(chrome155Extensions()),
	}
}

// chrome155Extensions returns the extensions of Chrome 155 in template order.
func chrome155Extensions() []utls.TLSExtension {
	return []utls.TLSExtension{
		&utls.UtlsGREASEExtension{},
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			utls.GREASE_PLACEHOLDER,
			utls.X25519MLKEM768,
			utls.X25519,
			utls.CurveP256,
			utls.CurveP384,
		}},
		&utls.SupportedPointsExtension{SupportedPoints: []byte{
			0x00, // pointFormatUncompressed
		}},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
			greaseSignatureScheme(),
			signatureMLDSA44,
			signatureMLDSA65,
			signatureMLDSA87,
			utls.ECDSAWithP256AndSHA256,
			utls.PSSWithSHA256,
			utls.PKCS1WithSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.PSSWithSHA384,
			utls.PKCS1WithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA512,
		}},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
			{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: utls.X25519MLKEM768},
			{Group: utls.X25519},
		}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
			utls.PskModeDHE,
		}},
		&utls.SupportedVersionsExtension{Versions: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.VersionTLS13,
			utls.VersionTLS12,
		}},
		&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
			utls.CertCompressionBrotli,
		}},
		&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
		&utls.GenericExtension{Id: extensionTrustAnchors, Data: chrome155TrustAnchors()},
		utls.BoringGREASEECH(),
		&utls.UtlsGREASEExtension{},
	}
}

// shuffleChromeExtensions permutes every extension but GREASE, padding and pre_shared_key uniformly, as
// BoringSSL does (ssl_setup_extension_permutation). utls.ShuffleChromeTLSExtensions skips the swaps that
// involve such an extension instead, so each extension stays in its template position twice as often as
// in Chrome, which an observer who knows the template can count.
func shuffleChromeExtensions(extensions []utls.TLSExtension) []utls.TLSExtension {
	var positions []int
	for i, extension := range extensions {
		switch extension.(type) {
		case *utls.UtlsGREASEExtension, *utls.UtlsPaddingExtension, utls.PreSharedKeyExtension:
		default:
			positions = append(positions, i)
		}
	}
	for i := len(positions) - 1; i > 0; i-- {
		j := randomIndex(i + 1)
		extensions[positions[i]], extensions[positions[j]] = extensions[positions[j]], extensions[positions[i]]
	}
	return extensions
}

// randomIndex returns a uniform random number in [0, n) from crypto/rand.
func randomIndex(n int) int {
	var data [8]byte
	_, _ = rand.Read(data[:])
	return int(binary.BigEndian.Uint64(data[:]) % uint64(n))
}

// greaseSignatureScheme picks a random GREASE value for signature_algorithms, as BoringSSL does per
// connection: metacubex/utls substitutes GREASE placeholders in other extensions, but not in this one.
func greaseSignatureScheme() utls.SignatureScheme {
	var seed [1]byte
	_, _ = rand.Read(seed[:])
	value := uint16(seed[0]&0xf0 | 0x0a)
	return utls.SignatureScheme(value<<8 | value)
}

func chrome155TrustAnchors() []byte {
	data := make([]byte, 2, 256)
	for _, id := range chrome155TrustAnchorIDs {
		data = append(data, byte(len(id)))
		data = append(data, id...)
	}
	binary.BigEndian.PutUint16(data, uint16(len(data)-2))
	return data
}
