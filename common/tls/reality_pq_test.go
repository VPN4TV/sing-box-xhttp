//go:build with_utls

package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// xrayAcceptsKeyShares mirrors the check of XTLS/REALITY 8cdf7bf (Xray v26.9.9 and later): the key shares
// must contain exactly one X25519MLKEM768 share placed before the optional X25519 share.
func xrayAcceptsKeyShares(shapes []keyShareShape) bool {
	var hybrid bool
	for _, share := range shapes {
		if share.group == uint16(utls.X25519MLKEM768) && share.length == x25519MLKEM768ShareSize {
			if hybrid {
				return false
			}
			hybrid = true
			continue
		}
		if share.group == uint16(utls.X25519) && share.length == 32 {
			break
		}
	}
	return hybrid
}

func TestRealityPostQuantumProfiles(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"chrome":    true,
		"chrome133": true,
		"firefox":   true,
		"safari":    true,
		"edge":      false,
		"ios":       false,
		"android":   false,
		"qq":        false,
		"360":       false,
	} {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err)
		uConn, hello := buildTestHello(t, id)
		require.Equal(t, want, realityHasPostQuantumShare(uConn), name)
		if !want {
			continue
		}
		shapes := keyShareShapes(hello.extension(0x0033))
		require.True(t, xrayAcceptsKeyShares(shapes), "%s: new REALITY servers must accept the hello", name)
		// The REALITY server authenticates with the standalone X25519 share: the auth key must be its key.
		key, err := realityECDHEKey(uConn)
		require.NoError(t, err, name)
		require.Equal(t, uConn.HandshakeState.State13.KeyShareKeys.Ecdhe, key, name)
		var standalone []byte
		for _, ks := range uConn.Extensions {
			if keyShare, ok := ks.(*utls.KeyShareExtension); ok {
				for _, share := range keyShare.KeyShares {
					if share.Group == utls.X25519 {
						standalone = share.Data
					}
				}
			}
		}
		require.Equal(t, key.PublicKey().Bytes(), standalone, name)
	}
}

func TestRealityPQStateSwitching(t *testing.T) {
	t.Parallel()
	var s realityPQState
	require.False(t, s.stripping(), "send X25519MLKEM768 by default")

	// A server that never accepted us: one rejection switches the mode.
	require.True(t, s.report(false, false))
	require.True(t, s.stripping())
	// A late result of a handshake started in the old mode changes nothing.
	require.False(t, s.report(false, false))
	require.True(t, s.stripping())

	// Once the mode works, it takes three rejections in a row to switch back.
	require.False(t, s.report(true, true))
	require.False(t, s.report(true, false))
	require.False(t, s.report(true, false))
	require.False(t, s.report(true, true))
	require.False(t, s.report(true, false))
	require.False(t, s.report(true, false))
	require.True(t, s.report(true, false))
	require.False(t, s.stripping())
}
