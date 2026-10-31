//go:build with_utls

package tls

import (
	"context"
	"sync"
	"testing"
	"time"

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

func TestRealityRandomProfilesCarryPostQuantumShare(t *testing.T) {
	t.Parallel()
	for _, id := range append(randomFingerprints, randomizedFingerprint) {
		uConn, _ := buildTestHello(t, id)
		require.True(t, realityHasPostQuantumShare(uConn), id.Str())
	}
	for _, name := range []string{"random", "randomized"} {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err)
		uConn, _ := buildTestHello(t, id)
		require.True(t, realityHasPostQuantumShare(uConn), name)
	}
}

// pqStep runs one handshake through the state: the mode it got and what the switch logged.
func pqStep(t *testing.T, s *realityPQState, outcome realityPQOutcome, group utls.CurveID, now time.Time) (strip bool, switched string, warning string) {
	t.Helper()
	ticket, err := s.begin(context.Background())
	require.NoError(t, err)
	switched, warning = s.end(ticket, outcome, group, now)
	return ticket.strip, switched, warning
}

func TestRealityPQStateOldServer(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// The target of a server older than Xray v25.5.16 picks X25519MLKEM768: switch at once.
	strip, switched, warning := pqStep(t, &s, realityPQRejected, utls.X25519MLKEM768, now)
	require.False(t, strip, "send X25519MLKEM768 by default")
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	strip, switched, _ = pqStep(t, &s, realityPQVerified, 0, now)
	require.True(t, strip)
	require.Empty(t, switched)
	// The working mode without the share survives two rejections and a success between them...
	for _, outcome := range []realityPQOutcome{realityPQRejected, realityPQRejected, realityPQVerified, realityPQRejected, realityPQRejected} {
		strip, switched, _ = pqStep(t, &s, outcome, utls.X25519, now)
		require.True(t, strip)
		require.Empty(t, switched)
	}
	// ...and goes back after three in a row (the server was updated to Xray v26.9.9 or later).
	_, switched, warning = pqStep(t, &s, realityPQRejected, utls.X25519, now)
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	strip, _, _ = pqStep(t, &s, realityPQVerified, 0, now)
	require.False(t, strip)
}

func TestRealityPQStateRejectionsOfOtherGroups(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// A rejection with any group but X25519MLKEM768 (wrong keys, a target that wants P-256) is not about the share.
	for _, group := range []utls.CurveID{utls.X25519, utls.CurveP256, 0} {
		strip, switched, _ := pqStep(t, &s, realityPQRejected, group, now)
		require.False(t, strip)
		require.Empty(t, switched)
	}
	// Even a mode that works switches when its target turns out to pick X25519MLKEM768 for some connections.
	pqStep(t, &s, realityPQVerified, 0, now)
	_, switched, _ := pqStep(t, &s, realityPQRejected, utls.X25519MLKEM768, now)
	require.NotEmpty(t, switched)
}

func TestRealityPQStateBothRejected(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	_, switched, _ := pqStep(t, &s, realityPQRejected, utls.X25519MLKEM768, now)
	require.NotEmpty(t, switched)
	// The ClientHello without the share is rejected too: the configuration is wrong, not the share.
	strip, switched, warning := pqStep(t, &s, realityPQRejected, utls.X25519, now)
	require.True(t, strip)
	require.NotEmpty(t, switched)
	require.NotEmpty(t, warning)
	// The default mode stays for realityPQHold, without switching on every connection.
	for range 5 {
		strip, switched, warning = pqStep(t, &s, realityPQRejected, utls.X25519MLKEM768, now.Add(time.Minute))
		require.False(t, strip)
		require.Empty(t, switched)
		require.Empty(t, warning)
	}
	_, switched, _ = pqStep(t, &s, realityPQRejected, utls.X25519MLKEM768, now.Add(realityPQHold+time.Second))
	require.NotEmpty(t, switched, "after the hold the server gets another chance")
}

func TestRealityPQStateSilentFailures(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// Handshakes with the share that never get an answer: try without it after realityPQSilentLimit.
	for range realityPQSilentLimit - 1 {
		_, switched, _ := pqStep(t, &s, realityPQSilent, 0, now)
		require.Empty(t, switched)
	}
	_, switched, _ := pqStep(t, &s, realityPQSilent, 0, now)
	require.NotEmpty(t, switched)
	// Without the share it is no better: go back to the default.
	for range realityStripSilentLimit - 1 {
		strip, switched, _ := pqStep(t, &s, realityPQSilent, 0, now)
		require.True(t, strip)
		require.Empty(t, switched)
	}
	_, switched, warning := pqStep(t, &s, realityPQSilent, 0, now)
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	// Once the default works, silence does not switch it.
	pqStep(t, &s, realityPQVerified, 0, now)
	for range 2 * realityPQSilentLimit {
		strip, switched, _ := pqStep(t, &s, realityPQSilent, 0, now)
		require.False(t, strip)
		require.Empty(t, switched)
	}
}

func TestRealityPQStateNewServerAfterSilence(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	for range realityPQSilentLimit {
		pqStep(t, &s, realityPQSilent, 0, now)
	}
	// Xray v26.9.9 or later rejects the ClientHello without the share: back to the default, and no more tries
	// without it for realityPQHold. There is no warning: the share itself was not rejected.
	strip, switched, warning := pqStep(t, &s, realityPQRejected, utls.X25519, now)
	require.True(t, strip)
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	for range 2 * realityPQSilentLimit {
		strip, switched, _ = pqStep(t, &s, realityPQSilent, 0, now.Add(time.Minute))
		require.False(t, strip)
		require.Empty(t, switched)
	}
}

func TestRealityPQStateLateAndCanceled(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// The first handshake probes, the second one waits for it: start them in order, finish the probe last.
	probe, err := s.begin(context.Background())
	require.NoError(t, err)
	require.True(t, probe.probe)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = s.begin(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded, "a handshake waits while the probe runs")
	// A canceled probe tells nothing: the next handshake probes again.
	s.end(probe, realityPQCanceled, 0, now)
	probe, err = s.begin(context.Background())
	require.NoError(t, err)
	require.True(t, probe.probe)
	switched, _ := s.end(probe, realityPQRejected, utls.X25519MLKEM768, now)
	require.NotEmpty(t, switched)
	// A result of a handshake started before the switch changes nothing.
	stale := realityPQTicket{generation: probe.generation, strip: false}
	switched, _ = s.end(stale, realityPQRejected, utls.X25519MLKEM768, now)
	require.Empty(t, switched)
	ticket, err := s.begin(context.Background())
	require.NoError(t, err)
	require.True(t, ticket.strip)
	s.end(ticket, realityPQVerified, 0, now)
}

func TestRealityPQStateProbeBurst(t *testing.T) {
	t.Parallel()
	var s realityPQState
	// A burst of handshakes to a server older than Xray v25.5.16 right after a start: only the probe is sent
	// with the share and fails, the others wait for it and go without the share.
	const burst = 20
	var (
		access   sync.Mutex
		rejected int
		wg       sync.WaitGroup
	)
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, err := s.begin(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			time.Sleep(5 * time.Millisecond)
			outcome := realityPQVerified
			if !ticket.strip {
				outcome = realityPQRejected
				access.Lock()
				rejected++
				access.Unlock()
			}
			s.end(ticket, outcome, utls.X25519MLKEM768, time.Now())
		}()
	}
	wg.Wait()
	require.Equal(t, 1, rejected)
	require.True(t, s.strip)
	require.True(t, s.confirmed)
}

func TestRealityPQStatesShared(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	var shortID, otherShortID [8]byte
	otherShortID[0] = 1
	a := realityPQStateFor("pq-test.example", "www.example.com", key, shortID)
	require.Same(t, a, realityPQStateFor("pq-test.example", "www.example.com", key, shortID), "outbounds re-created on reload share the state")
	require.NotSame(t, a, realityPQStateFor("pq-test.example", "www.example.com", key, otherShortID))
	require.NotSame(t, a, realityPQStateFor("pq-test.example", "www.example.org", key, shortID))
	require.NotSame(t, a, realityPQStateFor("other.example", "www.example.com", key, shortID))
}
