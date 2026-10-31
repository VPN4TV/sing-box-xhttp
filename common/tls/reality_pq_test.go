//go:build with_utls

package tls

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
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
	// A certificate that is not valid for the server name does not overrule a mode that worked at once (a captive
	// portal)...
	var s realityPQState
	pqStep(t, &s, pqVerified, now)
	for range realityStripRejectLimit - 1 {
		ticket, switched, _ := pqStep(t, &s, pqIntercepted, now)
		require.False(t, ticket.strip)
		require.Empty(t, switched)
		pqStep(t, &s, pqVerified, now)
	}
	// ...but it does when it keeps coming, successes between them or not: an old server whose target started to
	// pick X25519MLKEM768 behind a certificate the device cannot verify. The mode without the share is doubtful.
	_, switched, _ := pqStep(t, &s, pqIntercepted, now)
	require.Contains(t, switched, "not valid")
	ticket, _, _ := pqStep(t, &s, pqVerified, now)
	require.True(t, ticket.strip)
	ticket, _, _ = pqStep(t, &s, pqVerified, now.Add(realityPQRetryMin))
	require.True(t, ticket.retry)
	// Before anything worked it may be an old server whose target has no valid certificate: go without the share,
	// but try the share again after realityPQRetryMin, then less and less often.
	var d realityPQState
	_, switched, _ = pqStep(t, &d, pqIntercepted, now)
	require.NotEmpty(t, switched)
	ticket, _, _ = pqStep(t, &d, pqVerified, now)
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
	// The first handshake probes; the next one waits for it, but not longer than probeWait, and then probes in
	// its place.
	probe, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, probe.probe)
	start := time.Now()
	waited, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, waited.probe)
	require.GreaterOrEqual(t, time.Since(start), 25*time.Millisecond)
	// A handshake whose own deadline is near does not spend more than half of it on waiting.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	short, err := s.begin(ctx, now)
	cancel()
	require.NoError(t, err)
	require.Nil(t, short.probe, "nor does it take over a probe")
	s.end(short, realityPQResult{outcome: realityPQCanceled}, now)
	s.end(waited, realityPQResult{outcome: realityPQCanceled}, now)
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
	// The probe hangs; another handshake takes it over after probeWait and is rejected by an old server.
	other, err := s.begin(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, other.probe)
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

func TestRealityPQStateRetryAnsweredByTarget(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// Entered on a doubtful certificate (the clock of the device was wrong at the start), the share is tried again...
	var s realityPQState
	pqStep(t, &s, pqIntercepted, now)
	pqStep(t, &s, pqVerified, now)
	at := now.Add(realityPQRetryMin)
	ticket, switched, _ := pqStep(t, &s, pqRejectedTarget, at)
	require.True(t, ticket.retry)
	require.Contains(t, switched, "not tried any more")
	// ...and the target's own answer settles it: a server older than Xray v25.5.16, no more retries.
	for _, later := range []time.Duration{2 * realityPQRetryMin, realityPQRetryMax, 24 * time.Hour} {
		ticket, _, _ = pqStep(t, &s, pqVerified, at.Add(later))
		require.True(t, ticket.strip)
		require.False(t, ticket.retry, "retried %s after the target's own answer", later)
	}
	// A retry without an answer says nothing about the share: the next one comes after the same delay.
	var q realityPQState
	pqStep(t, &q, pqIntercepted, now)
	pqStep(t, &q, pqVerified, now)
	ticket, _, _ = pqStep(t, &q, pqSilent, at)
	require.True(t, ticket.retry)
	ticket, _, _ = pqStep(t, &q, pqVerified, at.Add(realityPQRetryMin-time.Second))
	require.False(t, ticket.retry)
	ticket, _, _ = pqStep(t, &q, pqVerified, at.Add(realityPQRetryMin))
	require.True(t, ticket.retry, "an unanswered retry does not double the delay")
}

func TestRealityPQStateClockFixed(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// The clock of the device is off: a server that takes both ClientHellos rejects both with its target's
	// certificate, and the target picks X25519MLKEM768.
	var s realityPQState
	pqStep(t, &s, pqRejectedTarget, now)
	_, _, warning := pqStep(t, &s, pqRejectedOther, now)
	require.Contains(t, warning, "clock")
	// The share is rejected again after the hold. While the server keeps rejecting both, that may be the clock:
	// the mode without the share is doubtful.
	at := now.Add(realityPQHoldMin)
	_, switched, _ := pqStep(t, &s, pqRejectedTarget, at)
	require.NotEmpty(t, switched)
	// The clock is fixed: the ClientHello without the share works, and the share is tried again later.
	ticket, _, _ := pqStep(t, &s, pqVerified, at)
	require.True(t, ticket.strip)
	at = at.Add(realityPQRetryMin)
	ticket, switched, _ = pqStep(t, &s, pqVerified, at)
	require.True(t, ticket.retry)
	require.NotEmpty(t, switched, "the server takes the share again")
	ticket, _, _ = pqStep(t, &s, pqVerified, at)
	require.False(t, ticket.strip)
	// A server older than Xray v25.5.16 costs one more rejection: the retry is answered by the target itself.
	var old realityPQState
	pqStep(t, &old, pqRejectedTarget, now)
	pqStep(t, &old, pqRejectedOther, now)
	at = now.Add(realityPQHoldMin)
	pqStep(t, &old, pqRejectedTarget, at)
	pqStep(t, &old, pqVerified, at)
	at = at.Add(realityPQRetryMin)
	ticket, _, _ = pqStep(t, &old, pqRejectedTarget, at)
	require.True(t, ticket.retry)
	ticket, _, _ = pqStep(t, &old, pqVerified, at.Add(24*time.Hour))
	require.True(t, ticket.strip)
	require.False(t, ticket.retry)
}

func TestRealityPQStateRetriesAfterTheShareCameBack(t *testing.T) {
	t.Parallel()
	now := time.Now()
	intercepted := func(s *realityPQState, at time.Time) {
		for range realityStripRejectLimit {
			pqStep(t, s, pqIntercepted, at)
		}
	}
	var s realityPQState
	pqStep(t, &s, pqVerified, now)
	intercepted(&s, now)
	ticket, _, _ := pqStep(t, &s, pqVerified, now)
	require.True(t, ticket.strip)
	at := now.Add(realityPQRetryMin)
	_, switched, _ := pqStep(t, &s, pqVerified, at)
	require.NotEmpty(t, switched)
	// The target picks X25519MLKEM768 again soon after the share came back, so it picks it at times: the share is
	// tried twice as late as before...
	at = at.Add(time.Minute)
	intercepted(&s, at)
	pqStep(t, &s, pqVerified, at)
	ticket, _, _ = pqStep(t, &s, pqVerified, at.Add(2*realityPQRetryMin-time.Second))
	require.False(t, ticket.retry)
	at = at.Add(2 * realityPQRetryMin)
	ticket, _, _ = pqStep(t, &s, pqVerified, at)
	require.True(t, ticket.retry)
	// ...while after a share that lasted realityPQRetryCalm (another portal, days later) the retries start over.
	at = at.Add(realityPQRetryCalm)
	intercepted(&s, at)
	pqStep(t, &s, pqVerified, at)
	ticket, _, _ = pqStep(t, &s, pqVerified, at.Add(realityPQRetryMin))
	require.True(t, ticket.retry)
}

func TestRealityPQStateProbeTakenOver(t *testing.T) {
	t.Parallel()
	// The probe to a server older than Xray v25.5.16 hangs, and a burst of handshakes waits for it. One of them
	// takes it over after probeWait: only it is sent with the share and fails, the others go without the share.
	s := realityPQState{probeWait: 50 * time.Millisecond}
	hung, err := s.begin(context.Background(), time.Now())
	require.NoError(t, err)
	const burst = 19
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
	s.end(hung, pqSilent, time.Now())
	require.Equal(t, 1, rejected)
	require.True(t, s.strip)
	require.True(t, s.confirmed)
}

func TestRealityPQStateLateProbe(t *testing.T) {
	t.Parallel()
	takeOver := func(s *realityPQState) (first realityPQTicket, second realityPQTicket, waiter chan realityPQTicket) {
		first, err := s.begin(context.Background(), time.Now())
		require.NoError(t, err)
		second, err = s.begin(context.Background(), time.Now())
		require.NoError(t, err)
		require.NotNil(t, second.probe, "the handshake that waited too long probes in place of the first")
		waiter = make(chan realityPQTicket, 1)
		go func() {
			ticket, err := s.begin(context.Background(), time.Now())
			require.NoError(t, err)
			waiter <- ticket
		}()
		time.Sleep(10 * time.Millisecond)
		return first, second, waiter
	}
	// The probe that was taken over ends without an answer: the others keep waiting for the one that took it
	// over, and go once it confirms the mode.
	s := realityPQState{probeWait: 200 * time.Millisecond}
	first, second, waiter := takeOver(&s)
	s.end(first, pqSilent, time.Now())
	select {
	case <-waiter:
		t.Fatal("a probe that was taken over ended the wait")
	case <-time.After(50 * time.Millisecond):
	}
	s.end(second, pqVerified, time.Now())
	select {
	case ticket := <-waiter:
		require.Nil(t, ticket.probe)
		s.end(ticket, pqVerified, time.Now())
	case <-time.After(time.Second):
		t.Fatal("the waiter was not woken")
	}
	// The probe that was taken over gets through first: the others go at once.
	l := realityPQState{probeWait: 200 * time.Millisecond}
	first, second, waiter = takeOver(&l)
	start := time.Now()
	l.end(first, pqVerified, time.Now())
	select {
	case ticket := <-waiter:
		require.Less(t, time.Since(start), 100*time.Millisecond)
		require.Nil(t, ticket.probe)
		require.False(t, ticket.strip)
		l.end(ticket, pqVerified, time.Now())
	case <-time.After(time.Second):
		t.Fatal("the waiter was not woken")
	}
	l.end(second, pqVerified, time.Now())
}

func TestRealityPQStateStress(t *testing.T) {
	t.Parallel()
	// Random outcomes, cancellations, short deadlines and slow probes: nothing panics (a channel closed twice) or
	// hangs, one retry runs at a time, and no more than two probes of one mode: the one taken over and the one
	// that took it over.
	s := realityPQState{probeWait: 2 * time.Millisecond}
	var (
		retries, maxRetries atomic.Int32
		probes              sync.Map // generation -> *atomic.Int32 probes in flight
		maxProbes           atomic.Int32
		wg                  sync.WaitGroup
	)
	raise := func(peak *atomic.Int32, n int32) {
		for m := peak.Load(); n > m && !peak.CompareAndSwap(m, n); m = peak.Load() {
		}
	}
	deadline := time.Now().Add(time.Second)
	base := time.Now()
	for g := range 64 {
		wg.Add(1)
		go func(rng *rand.Rand) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				var (
					ctx    context.Context
					cancel context.CancelFunc
				)
				switch rng.IntN(3) {
				case 0:
					ctx, cancel = context.WithCancel(context.Background())
					go func(d time.Duration) { time.Sleep(d); cancel() }(time.Duration(rng.IntN(3000)) * time.Microsecond)
				case 1:
					ctx, cancel = context.WithTimeout(context.Background(), time.Duration(rng.IntN(5000))*time.Microsecond)
				default:
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				}
				clock := base.Add(time.Duration(rng.IntN(600)) * time.Minute)
				ticket, err := s.begin(ctx, clock)
				if err != nil {
					cancel()
					continue
				}
				var inFlight *atomic.Int32
				if ticket.probe != nil {
					v, _ := probes.LoadOrStore(ticket.generation, new(atomic.Int32))
					inFlight = v.(*atomic.Int32)
					raise(&maxProbes, inFlight.Add(1))
				}
				if ticket.retry {
					raise(&maxRetries, retries.Add(1))
				}
				sleep := time.Duration(rng.IntN(300)) * time.Microsecond
				if ticket.probe != nil && rng.IntN(4) == 0 {
					sleep = time.Duration(rng.IntN(8)) * time.Millisecond // a slow or hung probe
				}
				time.Sleep(sleep)
				result := realityPQResult{
					outcome: realityPQOutcome(rng.IntN(4)),
					group:   []utls.CurveID{utls.X25519MLKEM768, utls.X25519, 0}[rng.IntN(3)],
					valid:   rng.IntN(2) == 0,
				}
				if inFlight != nil {
					inFlight.Add(-1)
				}
				if ticket.retry {
					retries.Add(-1)
				}
				s.end(ticket, result, clock)
				cancel()
			}
		}(rand.New(rand.NewPCG(uint64(g), 0)))
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("handshakes stuck")
	}
	require.LessOrEqual(t, maxRetries.Load(), int32(1))
	require.LessOrEqual(t, maxProbes.Load(), int32(2))
	s.access.Lock()
	defer s.access.Unlock()
	require.False(t, s.retrying)
	require.Nil(t, s.probe)
	require.Nil(t, s.late)
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

func TestRealityPQStateNoTakeOverAfterSwitch(t *testing.T) {
	t.Parallel()
	// Handshakes take a bit less than probeWait, and a burst waits for the probe with the share, which is rejected:
	// when the wait of the others is over, the probe of the new mode has only begun.
	const wait = 400 * time.Millisecond
	handshake := 4 * wait / 5
	burst := func(first realityPQResult, answer func(ticket realityPQTicket) realityPQResult) (probes int, longest time.Duration, rejected int, stripped int) {
		s := realityPQState{probeWait: wait}
		probe, err := s.begin(context.Background(), time.Now())
		require.NoError(t, err)
		var (
			access sync.Mutex
			wg     sync.WaitGroup
		)
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				ticket, err := s.begin(context.Background(), time.Now())
				if err != nil {
					t.Error(err)
					return
				}
				access.Lock()
				if ticket.probe != nil {
					probes++
				} else {
					longest = max(longest, time.Since(start))
					if ticket.strip {
						stripped++
					}
				}
				access.Unlock()
				time.Sleep(handshake)
				result := answer(ticket)
				if result.outcome == realityPQRejected {
					access.Lock()
					rejected++
					access.Unlock()
				}
				s.end(ticket, result, time.Now())
			}()
		}
		time.Sleep(handshake)
		switched, _ := s.end(probe, first, time.Now())
		require.NotEmpty(t, switched)
		wg.Wait()
		return
	}
	// A server older than Xray v25.5.16: the target answered the share, so the others go without it when their own
	// wait is over, and the probe without the share is not taken over.
	probes, longest, rejected, _ := burst(pqRejectedTarget, func(ticket realityPQTicket) realityPQResult {
		if ticket.strip {
			return pqVerified
		}
		return pqRejectedTarget
	})
	require.Equal(t, 1, probes, "one probe without the share")
	require.Less(t, longest, wait+wait/3, "the others go when their own wait is over")
	require.Zero(t, rejected)
	// A portal answered the probe, and the server behind it is new: the doubtful mode is still waited for, so the
	// others go with the share once the server rejected the ClientHello without it.
	_, _, rejected, stripped := burst(pqIntercepted, func(ticket realityPQTicket) realityPQResult {
		if ticket.strip {
			return pqRejectedOther
		}
		return pqVerified
	})
	require.Zero(t, stripped, "a handshake went without the share before the server rejected it")
	require.Equal(t, 2, rejected, "the probe without the share and the one that took it over")
	// A handshake that began in the new mode still takes over its probe when that takes too long.
	s := realityPQState{probeWait: wait / 4}
	probe, err := s.begin(context.Background(), time.Now())
	require.NoError(t, err)
	switched, _ := s.end(probe, pqRejectedTarget, time.Now())
	require.NotEmpty(t, switched)
	hung, err := s.begin(context.Background(), time.Now())
	require.NoError(t, err)
	other, err := s.begin(context.Background(), time.Now())
	require.NoError(t, err)
	require.NotNil(t, other.probe)
	require.True(t, other.strip)
	s.end(other, pqVerified, time.Now())
	s.end(hung, pqSilent, time.Now())
}

func TestRealityPQStatePortalComesBack(t *testing.T) {
	t.Parallel()
	// A captive portal answers both ClientHellos with its own certificate whenever the session is over, and the
	// session ends again within realityPQRetryCalm of the share coming back. Unlike a target that picks
	// X25519MLKEM768 at times, it answers the ClientHello without the share too: after every login the share is
	// tried again after realityPQRetryMin, not later and later.
	pqInterceptedOther := realityPQResult{outcome: realityPQRejected, group: utls.X25519}
	now := time.Now()
	var s realityPQState
	pqStep(t, &s, pqVerified, now)
	for session := range 5 {
		for range realityStripRejectLimit {
			pqStep(t, &s, pqIntercepted, now)
		}
		ticket, _, warning := pqStep(t, &s, pqInterceptedOther, now)
		require.True(t, ticket.strip)
		require.Contains(t, warning, "intercept")
		now = now.Add(realityPQHoldMin)
		ticket, switched, _ := pqStep(t, &s, pqIntercepted, now)
		require.False(t, ticket.strip)
		require.NotEmpty(t, switched)
		// The user logs in while the ClientHello without the share is sent.
		now = now.Add(time.Minute)
		ticket, _, _ = pqStep(t, &s, pqVerified, now)
		require.True(t, ticket.strip)
		ticket, _, _ = pqStep(t, &s, pqVerified, now.Add(realityPQRetryMin-time.Second))
		require.False(t, ticket.retry)
		now = now.Add(realityPQRetryMin)
		ticket, switched, _ = pqStep(t, &s, pqVerified, now)
		require.True(t, ticket.retry, "session %d: the share is not tried again after realityPQRetryMin", session)
		require.NotEmpty(t, switched)
		now = now.Add(30 * time.Minute)
	}
}

func TestRealityPQStateNeedsShareKeepsItBehindPortals(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// A server that needs the share (Xray v26.9.9+) behind a portal: the first portal costs one rejection of the
	// ClientHello without the share by the server; after that portals do not take the share away.
	var s realityPQState
	pqStep(t, &s, pqVerified, now)
	for range realityStripRejectLimit {
		pqStep(t, &s, pqIntercepted, now)
	}
	ticket, switched, _ := pqStep(t, &s, pqRejectedOther, now)
	require.True(t, ticket.strip)
	require.NotEmpty(t, switched)
	ticket, _, _ = pqStep(t, &s, pqVerified, now)
	require.False(t, ticket.strip)
	for episode := range 5 {
		for range 10 {
			ticket, switched, _ = pqStep(t, &s, pqIntercepted, now.Add(time.Duration(episode)*time.Hour))
			require.False(t, ticket.strip)
			require.Empty(t, switched)
		}
		ticket, _, _ = pqStep(t, &s, pqVerified, now.Add(time.Duration(episode)*time.Hour))
		require.False(t, ticket.strip)
	}
	// A server older than Xray v25.5.16 whose target the device cannot verify still leaves the share: it never
	// rejects the ClientHello without it.
	var old realityPQState
	pqStep(t, &old, pqVerified, now)
	for range realityStripRejectLimit {
		pqStep(t, &old, pqIntercepted, now)
	}
	ticket, _, _ = pqStep(t, &old, pqVerified, now)
	require.True(t, ticket.strip)
}

// The memory that a server needs the share keeps the share behind portals, and only a rejection of the ClientHello
// without the share by the target itself, followed by the share working, sets it.
func TestRealityPQStateNeedsShareOnlyAfterTheTargetAnsweredWithoutIt(t *testing.T) {
	t.Parallel()
	now := time.Now()
	portalStrip := realityPQResult{outcome: realityPQRejected, group: pqRejectedOther.group} // the portal, without the share
	// A server that needs the share: the first portal still costs one rejection of the ClientHello without it.
	var s realityPQState
	pqStep(t, &s, pqVerified, now)
	for range realityStripRejectLimit {
		pqStep(t, &s, pqIntercepted, now)
	}
	ticket, _, warning := pqStep(t, &s, pqRejectedOther, now.Add(time.Minute))
	require.True(t, ticket.strip)
	require.Contains(t, warning, "intercept")
	pqStep(t, &s, pqVerified, now.Add(time.Minute))
	// Later portals of any length and pace leave the share alone, also after the hold of that rejection.
	at := now.Add(time.Hour)
	for _, portal := range []int{3, 4, 5, 12} {
		for _, gap := range []time.Duration{time.Second, time.Minute} {
			for range portal {
				ticket, switched, warning := pqStep(t, &s, pqIntercepted, at)
				require.False(t, ticket.strip)
				require.Empty(t, switched)
				require.Empty(t, warning)
				at = at.Add(gap)
			}
			ticket, _, _ := pqStep(t, &s, pqVerified, at)
			require.False(t, ticket.strip)
			at = at.Add(time.Hour)
		}
	}
	// The target of an old server answering the share itself still switches at once.
	_, switched, _ := pqStep(t, &s, pqRejectedTarget, at)
	require.NotEmpty(t, switched)

	// Portal answers alone, before anything worked, do not make the server one that needs the share.
	var p realityPQState
	for range 4 {
		pqStep(t, &p, pqIntercepted, now)
		pqStep(t, &p, portalStrip, now)
		now = now.Add(realityPQHoldMin)
	}
	pqStep(t, &p, pqVerified, now)
	for range realityStripRejectLimit {
		pqStep(t, &p, pqIntercepted, now)
	}
	ticket, _, _ = pqStep(t, &p, pqVerified, now)
	require.True(t, ticket.strip, "without a rejection by the target the third doubtful rejection still leaves the share")
}

func TestRealityPQStateNewServerBehindInterceptor(t *testing.T) {
	t.Parallel()
	// A server that needs the share (Xray v26.9.9+) behind a network that hands some connections to an interceptor
	// (its own certificate, X25519MLKEM768 when offered), a connection every 15 s for 24 h: the ClientHello without
	// the share goes out once at most. The server rejects it with its target's certificate, and after that the
	// interceptor's answers do not take the share away again.
	start := time.Unix(1_900_000_000, 0)
	for seed := range uint64(5) {
		r := rand.New(rand.NewPCG(seed, 2))
		var s realityPQState
		var rejected int
		for i := range 24 * 240 {
			now := start.Add(time.Duration(i) * 15 * time.Second)
			ticket, err := s.begin(context.Background(), now)
			require.NoError(t, err)
			result := pqVerified
			switch {
			case r.Float64() < 0.05:
				result = pqIntercepted
				if ticket.strip {
					result.group = utls.X25519
				}
			case ticket.strip:
				result = pqRejectedOther // the server passes the ClientHello without the share on to its target
				rejected++
			}
			s.end(ticket, result, now)
		}
		require.LessOrEqual(t, rejected, 1, "seed %d", seed)
	}
	// A server older than Xray v25.5.16 never rejects the ClientHello without the share: three doubtful rejections
	// still leave the share there (its target picks X25519MLKEM768 behind a certificate the device cannot verify).
	var old realityPQState
	now := time.Now()
	pqStep(t, &old, pqVerified, now)
	for range realityStripRejectLimit {
		pqStep(t, &old, pqVerified, now)
		pqStep(t, &old, pqIntercepted, now)
	}
	ticket, _, _ := pqStep(t, &old, pqVerified, now)
	require.True(t, ticket.strip)
}

func TestRealityPQStateNeedsShareNotFromTheClock(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// The clock of the device is off, and the server rejects both ClientHellos with its target's certificate: that
	// is not a server that needs the share. Once the clock is right, a target that starts to pick X25519MLKEM768
	// behind a certificate the device cannot verify still takes the share away from a server older than Xray v25.5.16.
	var s realityPQState
	pqStep(t, &s, pqRejectedTarget, now)
	pqStep(t, &s, pqRejectedOther, now)
	at := now.Add(realityPQHoldMin)
	pqStep(t, &s, pqRejectedTarget, at)
	pqStep(t, &s, pqRejectedOther, at)
	at = at.Add(2 * realityPQHoldMin)
	ticket, _, _ := pqStep(t, &s, pqVerified, at)
	require.False(t, ticket.strip)
	require.False(t, s.needsShare)
	for range realityStripRejectLimit {
		pqStep(t, &s, pqIntercepted, at)
	}
	ticket, _, _ = pqStep(t, &s, pqVerified, at)
	require.True(t, ticket.strip)
	// A server that needs the share and then takes the ClientHello without it (rolled back to an old version) is
	// one like any other again.
	var n realityPQState
	pqStep(t, &n, pqVerified, now)
	for range realityStripRejectLimit {
		pqStep(t, &n, pqIntercepted, now)
	}
	pqStep(t, &n, pqRejectedOther, now)
	pqStep(t, &n, pqVerified, now)
	require.True(t, n.needsShare)
	at = now.Add(time.Hour)
	_, switched, _ := pqStep(t, &n, pqRejectedTarget, at)
	require.NotEmpty(t, switched)
	ticket, _, _ = pqStep(t, &n, pqVerified, at)
	require.True(t, ticket.strip)
	require.False(t, n.needsShare)
}
