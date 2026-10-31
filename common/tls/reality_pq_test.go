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
func pqStep(t *testing.T, s *realityPQState, result realityPQResult, now time.Time) (ticket realityPQTicket, switched string, warning string) {
	t.Helper()
	ticket, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	switched, warning = s.end(ticket, result, now)
	return ticket, switched, warning
}

var (
	pqVerified       = realityPQResult{outcome: realityPQVerified}
	pqSilent         = realityPQResult{outcome: realityPQSilent}
	pqRejectedTarget = realityPQResult{outcome: realityPQRejected, group: utls.X25519MLKEM768, valid: true}
	pqRejectedOther  = realityPQResult{outcome: realityPQRejected, group: utls.X25519, valid: true}
	pqIntercepted    = realityPQResult{outcome: realityPQRejected, group: utls.X25519MLKEM768}
)

func TestRealityPQStateOldServer(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// The target of a server older than Xray v25.5.16 picks X25519MLKEM768: switch at once.
	ticket, switched, warning := pqStep(t, &s, pqRejectedTarget, now)
	require.False(t, ticket.strip, "send X25519MLKEM768 by default")
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	ticket, switched, _ = pqStep(t, &s, pqVerified, now)
	require.True(t, ticket.strip)
	require.Empty(t, switched)
	// A genuine rejection is not doubted: the share is not tried again later.
	ticket, _, _ = pqStep(t, &s, pqVerified, now.Add(24*time.Hour))
	require.True(t, ticket.strip)
	require.False(t, ticket.retry)
	// The working mode without the share survives two rejections and a success between them...
	for _, result := range []realityPQResult{pqRejectedOther, pqRejectedOther, pqVerified, pqRejectedOther, pqRejectedOther} {
		ticket, switched, _ = pqStep(t, &s, result, now)
		require.True(t, ticket.strip)
		require.Empty(t, switched)
	}
	// ...and goes back after three in a row (the server was updated to Xray v26.9.9 or later).
	_, switched, warning = pqStep(t, &s, pqRejectedOther, now)
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	ticket, _, _ = pqStep(t, &s, pqVerified, now)
	require.False(t, ticket.strip)
}

func TestRealityPQStateRejectionsOfOtherGroups(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// A rejection with any group but X25519MLKEM768 (wrong keys, a target that wants P-256) is not about the share.
	for _, group := range []utls.CurveID{utls.X25519, utls.CurveP256, 0} {
		ticket, switched, _ := pqStep(t, &s, realityPQResult{outcome: realityPQRejected, group: group, valid: true}, now)
		require.False(t, ticket.strip)
		require.Empty(t, switched)
	}
	// Even a mode that works switches when the genuine target turns out to pick X25519MLKEM768 at times.
	pqStep(t, &s, pqVerified, now)
	_, switched, _ := pqStep(t, &s, pqRejectedTarget, now)
	require.NotEmpty(t, switched)
}

func TestRealityPQStateSilenceKeepsTheShare(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	// Handshakes that get no answer say nothing about the share, before and after it worked.
	for range 10 {
		ticket, switched, _ := pqStep(t, &s, pqSilent, now)
		require.False(t, ticket.strip)
		require.Empty(t, switched)
	}
	pqStep(t, &s, pqVerified, now)
	for range 10 {
		ticket, switched, _ := pqStep(t, &s, pqSilent, now)
		require.False(t, ticket.strip)
		require.Empty(t, switched)
	}
	// Without the share it is different: two unanswered handshakes before it worked go back to the default.
	var strip realityPQState
	pqStep(t, &strip, pqRejectedTarget, now)
	ticket, switched, _ := pqStep(t, &strip, pqSilent, now)
	require.True(t, ticket.strip)
	require.Empty(t, switched)
	_, switched, warning := pqStep(t, &strip, pqSilent, now)
	require.NotEmpty(t, switched)
	require.Empty(t, warning)
	ticket, _, _ = pqStep(t, &strip, pqVerified, now)
	require.False(t, ticket.strip)
}

func TestRealityPQStateInterception(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// A certificate that is not valid for the server name does not overrule a mode that worked (a captive portal).
	var s realityPQState
	pqStep(t, &s, pqVerified, now)
	for range 3 {
		ticket, switched, _ := pqStep(t, &s, pqIntercepted, now)
		require.False(t, ticket.strip)
		require.Empty(t, switched)
	}
	// Before anything worked it may be an old server whose target has no valid certificate: go without the share,
	// but try the share again after realityPQRetryMin, then less and less often.
	var d realityPQState
	_, switched, _ := pqStep(t, &d, pqIntercepted, now)
	require.NotEmpty(t, switched)
	ticket, _, _ := pqStep(t, &d, pqVerified, now)
	require.True(t, ticket.strip)
	ticket, _, _ = pqStep(t, &d, pqVerified, now.Add(realityPQRetryMin-time.Second))
	require.True(t, ticket.strip)
	require.False(t, ticket.retry)
	at := now.Add(realityPQRetryMin)
	ticket, switched, _ = pqStep(t, &d, pqIntercepted, at)
	require.True(t, ticket.retry)
	require.False(t, ticket.strip, "the retry sends the share")
	require.Empty(t, switched)
	ticket, _, _ = pqStep(t, &d, pqVerified, at.Add(2*realityPQRetryMin-time.Second))
	require.True(t, ticket.strip, "the next retry waits twice as long")
	require.False(t, ticket.retry)
	at = at.Add(2 * realityPQRetryMin)
	ticket, switched, _ = pqStep(t, &d, pqVerified, at)
	require.True(t, ticket.retry)
	require.NotEmpty(t, switched, "the server takes the share again")
	ticket, _, _ = pqStep(t, &d, pqVerified, at)
	require.False(t, ticket.strip)
	require.False(t, ticket.retry)
}

func TestRealityPQStateRetryAloneAndCanceled(t *testing.T) {
	t.Parallel()
	now := time.Now()
	var s realityPQState
	pqStep(t, &s, pqIntercepted, now)
	pqStep(t, &s, pqVerified, now)
	at := now.Add(realityPQRetryMin)
	retry, err := s.begin(context.Background(), at)
	require.NoError(t, err)
	require.True(t, retry.retry)
	// One retry at a time: the others keep going without the share.
	other, err := s.begin(context.Background(), at)
	require.NoError(t, err)
	require.True(t, other.strip)
	require.False(t, other.retry)
	s.end(other, pqVerified, at)
	// A canceled retry tells nothing: the next handshake tries again.
	s.end(retry, realityPQResult{outcome: realityPQCanceled}, at)
	retry, err = s.begin(context.Background(), at)
	require.NoError(t, err)
	require.True(t, retry.retry)
	s.end(retry, pqVerified, at)
}

func TestRealityPQStateBothRejected(t *testing.T) {
	t.Parallel()
	var s realityPQState
	now := time.Now()
	_, switched, _ := pqStep(t, &s, pqRejectedTarget, now)
	require.NotEmpty(t, switched)
	// The ClientHello without the share is rejected too: the configuration is wrong, not the share.
	ticket, switched, warning := pqStep(t, &s, pqRejectedOther, now)
	require.True(t, ticket.strip)
	require.NotEmpty(t, switched)
	require.Contains(t, warning, "public_key")
	// The default mode stays for realityPQHoldMin, without switching on every connection...
	for range 5 {
		ticket, switched, warning = pqStep(t, &s, pqRejectedTarget, now.Add(realityPQHoldMin-time.Second))
		require.False(t, ticket.strip)
		require.Empty(t, switched)
		require.Empty(t, warning)
	}
	// ...then the server gets another chance, and the next hold is twice as long, up to realityPQHoldMax.
	at := now.Add(realityPQHoldMin)
	for _, hold := range []time.Duration{2 * realityPQHoldMin, 4 * realityPQHoldMin, 8 * realityPQHoldMin, 16 * realityPQHoldMin, realityPQHoldMax, realityPQHoldMax} {
		_, switched, _ = pqStep(t, &s, pqRejectedTarget, at)
		require.NotEmpty(t, switched)
		_, _, warning = pqStep(t, &s, pqRejectedOther, at)
		require.NotEmpty(t, warning)
		_, switched, _ = pqStep(t, &s, pqRejectedTarget, at.Add(hold-time.Second))
		require.Empty(t, switched, "held for %s", hold)
		at = at.Add(hold)
	}
	// A success ends the doubling: the old server works again after a transient failure of both.
	_, switched, _ = pqStep(t, &s, pqRejectedTarget, at)
	require.NotEmpty(t, switched)
	pqStep(t, &s, pqVerified, at)
	// Both answered by an interceptor: the warning points at the network, and the hold stays short.
	var portal realityPQState
	for range 3 {
		_, switched, _ = pqStep(t, &portal, pqIntercepted, at)
		require.NotEmpty(t, switched)
		_, _, warning = pqStep(t, &portal, pqIntercepted, at)
		require.Contains(t, warning, "intercept")
		_, switched, _ = pqStep(t, &portal, pqIntercepted, at.Add(realityPQHoldMin-time.Second))
		require.Empty(t, switched, "the interceptor is held")
		at = at.Add(realityPQHoldMin)
	}
	_, switched, _ = pqStep(t, &portal, pqRejectedTarget, at)
	require.NotEmpty(t, switched, "the old server works once the interceptor is gone")
	// The target's own answer does not wait for a hold that an interceptor caused.
	var after realityPQState
	pqStep(t, &after, pqIntercepted, now)
	pqStep(t, &after, pqIntercepted, now)
	_, switched, _ = pqStep(t, &after, pqIntercepted, now.Add(time.Second))
	require.Empty(t, switched, "the interceptor itself is held")
	_, switched, _ = pqStep(t, &after, pqRejectedTarget, now.Add(time.Second))
	require.NotEmpty(t, switched)
	ticket, _, _ = pqStep(t, &after, pqVerified, now.Add(time.Second))
	require.True(t, ticket.strip)
}

func TestRealityPQStateLateAndCanceled(t *testing.T) {
	t.Parallel()
	s := realityPQState{probeWait: 30 * time.Millisecond}
	now := time.Now()
	// The first handshake probes; the next one waits for it, but not longer than probeWait.
	probe, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, probe.probe)
	start := time.Now()
	waited, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.Nil(t, waited.probe)
	require.GreaterOrEqual(t, time.Since(start), 25*time.Millisecond)
	s.end(waited, realityPQResult{outcome: realityPQCanceled}, now)
	// A handshake whose own deadline is near does not spend more than half of it on waiting.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	short, err := s.begin(ctx, now)
	cancel()
	require.NoError(t, err)
	require.Nil(t, short.probe)
	s.end(short, realityPQResult{outcome: realityPQCanceled}, now)
	// A canceled probe tells nothing: the next handshake probes again.
	s.end(probe, realityPQResult{outcome: realityPQCanceled}, now)
	probe, err = s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, probe.probe)
	switched, _ := s.end(probe, pqRejectedTarget, now)
	require.NotEmpty(t, switched)
	// A result of a handshake started before the switch changes nothing.
	stale := realityPQTicket{generation: probe.generation}
	switched, _ = s.end(stale, pqRejectedTarget, now)
	require.Empty(t, switched)
	ticket, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.True(t, ticket.strip)
	s.end(ticket, pqVerified, now)
}

func TestRealityPQStateSwitchDuringProbe(t *testing.T) {
	t.Parallel()
	s := realityPQState{probeWait: 20 * time.Millisecond}
	now := time.Now()
	hung, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, hung.probe)
	// The probe hangs; another handshake goes on after probeWait and is rejected by an old server.
	other, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	switched, _ := s.end(other, pqRejectedTarget, now)
	require.NotEmpty(t, switched)
	// The new mode gets its own probe at once instead of waiting for the old one.
	start := time.Now()
	fresh, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, fresh.probe)
	require.True(t, fresh.strip)
	require.Less(t, time.Since(start), 15*time.Millisecond)
	// The old probe ends late: it closes its own channel and changes nothing.
	switched, _ = s.end(hung, pqRejectedTarget, now)
	require.Empty(t, switched)
	s.end(fresh, pqVerified, now)
	ticket, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.True(t, ticket.strip)
	require.Nil(t, ticket.probe)
	s.end(ticket, pqVerified, now)
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
			ticket, err := s.begin(context.Background(), time.Now())
			if err != nil {
				t.Error(err)
				return
			}
			time.Sleep(5 * time.Millisecond)
			result := pqVerified
			if !ticket.strip {
				result = pqRejectedTarget
				access.Lock()
				rejected++
				access.Unlock()
			}
			s.end(ticket, result, time.Now())
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
