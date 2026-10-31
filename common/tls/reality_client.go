//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

type RealityClientConfig struct {
	ctx       context.Context
	logger    logger.ContextLogger
	uClient   *UTLSClientConfig
	publicKey []byte
	shortID   [8]byte
	pq        *realityPQState
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newRealityClient(ctx, logger, serverAddress, options, false)
}

func newRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}
	if options.Spoof != "" || options.SpoofMethod != "" {
		return nil, E.New("spoof is unsupported in reality")
	}

	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}

	var config Config = &RealityClientConfig{
		ctx:       ctx,
		logger:    logger,
		uClient:   uClient.(*UTLSClientConfig),
		publicKey: publicKey,
		shortID:   shortID,
		pq:        realityPQStateFor(serverAddress, uClient.ServerName(), publicKey, shortID),
	}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) HandshakeTimeout() time.Duration {
	return e.uClient.HandshakeTimeout()
}

func (e *RealityClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	e.uClient.SetHandshakeTimeout(timeout)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	verifier := &realityVerifier{
		serverName: e.uClient.ServerName(),
		roots:      e.uClient.config.RootCAs,
		now:        e.uClient.config.Time,
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	uConn, err := newUClient(conn, uConfig, e.uClient.id)
	if err != nil {
		return nil, err
	}
	verifier.UConn = uConn
	err = uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	// Profiles that carry the X25519MLKEM768 share send it as the browser does, unless this server has shown
	// that it needs the ClientHello without it (see realityPQState). Other profiles are left as they are.
	postQuantum := realityHasPostQuantumShare(uConn)
	strip := !postQuantum
	var (
		ticket realityPQTicket
		result realityPQResult
	)
	if postQuantum {
		ticket, err = e.pq.begin(ctx, time.Now())
		if err != nil {
			return nil, err
		}
		defer func() {
			switched, warning := e.pq.end(ticket, result, time.Now())
			if e.logger == nil {
				return
			}
			if switched != "" {
				e.logger.InfoContext(ctx, "reality: ", switched)
			}
			if warning != "" {
				e.logger.WarnContext(ctx, "reality: ", warning)
			}
		}()
		strip = ticket.strip
	}
	if strip {
		for _, extension := range uConn.Extensions {
			if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
				ce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
					return curveID != utls.X25519MLKEM768
				})
			}
			if ks, ok := extension.(*utls.KeyShareExtension); ok {
				ks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
					return share.Group != utls.X25519MLKEM768
				})
			}
		}
		err = uConn.BuildHandshakeState()
		if err != nil {
			return nil, err
		}
	}

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	ecdheKey, err := realityECDHEKey(uConn)
	if err != nil {
		return nil, err
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err == nil {
		if debug.Enabled {
			fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
		}
		if !verifier.verified {
			go realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)
			err = E.New("reality verification failed")
		}
	}
	switch {
	case verifier.verified:
		result.outcome = realityPQVerified
	case verifier.rejected:
		result = realityPQResult{outcome: realityPQRejected, valid: verifier.targetValid}
		if serverHello := uConn.HandshakeState.ServerHello; serverHello != nil {
			result.group = serverHello.ServerShare.Group
		}
	case errors.Is(err, context.Canceled):
		result.outcome = realityPQCanceled
	default:
		result.outcome = realityPQSilent
	}
	if err != nil {
		return nil, err
	}
	return &realityClientConnWrapper{uConn}, nil
}

// x25519MLKEM768ShareSize is the client key share of X25519MLKEM768: an ML-KEM-768 encapsulation key
// followed by an X25519 public key.
const x25519MLKEM768ShareSize = 1184 + 32

// realityHasPostQuantumShare reports whether the ClientHello offers X25519MLKEM768 both as a group and as
// a key share placed before the X25519 share, which is what Xray since v26.9.9 requires.
func realityHasPostQuantumShare(uConn *utls.UConn) bool {
	var group, share bool
	for _, extension := range uConn.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			group = slices.Contains(ext.Curves, utls.X25519MLKEM768)
		case *utls.KeyShareExtension:
			for _, keyShare := range ext.KeyShares {
				if keyShare.Group == utls.X25519 {
					break
				}
				if keyShare.Group == utls.X25519MLKEM768 && len(keyShare.Data) == x25519MLKEM768ShareSize {
					share = true
					break
				}
			}
		}
	}
	return group && share
}

// realityECDHEKey returns the private key of the share the REALITY server authenticates with: the
// standalone X25519 share when there is one, otherwise the X25519 half of the X25519MLKEM768 share.
func realityECDHEKey(uConn *utls.UConn) (*ecdh.PrivateKey, error) {
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	var standalone, hybrid bool
	for _, extension := range uConn.Extensions {
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			for _, keyShare := range ks.KeyShares {
				switch {
				case keyShare.Group == utls.X25519 && len(keyShare.Data) == 32:
					standalone = true
				case keyShare.Group == utls.X25519MLKEM768 && len(keyShare.Data) == x25519MLKEM768ShareSize:
					hybrid = true
				}
			}
		}
	}
	switch {
	case standalone:
		// uTLS keeps the key of the first classical share only.
		if keyShareKeys.Ecdhe == nil || keyShareKeys.Ecdhe.Curve() != ecdh.X25519() {
			return nil, E.New("missing X25519 key share key")
		}
		return keyShareKeys.Ecdhe, nil
	case hybrid && keyShareKeys.MlkemEcdhe != nil:
		return keyShareKeys.MlkemEcdhe, nil
	default:
		return nil, E.New("nil ecdheKey")
	}
}

// realityPQStates holds a realityPQState per REALITY server for the whole process: outbounds are created
// anew on every reload, and what a server needs does not change with them.
var realityPQStates sync.Map

func realityPQStateFor(serverAddress string, serverName string, publicKey []byte, shortID [8]byte) *realityPQState {
	key := strings.Join([]string{serverAddress, serverName, string(publicKey), string(shortID[:])}, "\x00")
	state, _ := realityPQStates.LoadOrStore(key, &realityPQState{})
	return state.(*realityPQState)
}

const (
	realityPQProbeWait      = 2 * time.Second  // the longest the other handshakes wait for the probe
	realityStripSilentLimit = 2                // unanswered handshakes without the share, before it ever worked, that go back
	realityStripRejectLimit = 3                // rejections in a row that make a working mode without the share go back
	realityPQHoldMin        = 30 * time.Second // after both ClientHellos were rejected; doubles while that repeats
	realityPQHoldMax        = 10 * time.Minute
	realityPQRetryMin       = 10 * time.Minute // a doubtful mode without the share tries the share again; doubles
	realityPQRetryMax       = 3 * time.Hour
)

type realityPQOutcome uint8

const (
	realityPQCanceled realityPQOutcome = iota // the caller gave up: nothing is known about the server
	realityPQVerified
	realityPQRejected // the server answered with a certificate that is not its own
	realityPQSilent   // the handshake ended before the server's certificate
)

// realityPQResult is how a handshake ended.
type realityPQResult struct {
	outcome realityPQOutcome
	group   utls.CurveID // the group of the ServerHello of a rejection
	valid   bool         // the certificate of a rejection is valid for the server name: the target answered
}

// realityPQState remembers whether a REALITY server takes the X25519MLKEM768 key share. Xray since v26.9.9
// (XTLS/REALITY 8cdf7bf) rejects a ClientHello without it. REALITY servers older than Xray v25.5.16, and
// sing-box up to 1.11, pass on the ServerHello of their target when the target picks X25519MLKEM768, so the
// handshake ends with the target's certificate. The ClientHello with the share, as the browser sends it, is
// the default, and nothing but such a rejection leaves it: a handshake that gets no answer says nothing
// about the share.
//
//   - With the share, a rejection in which the target picked X25519MLKEM768 switches to the ClientHello
//     without it at once. A rejection with any other group has nothing to do with the share. A certificate
//     that is not valid for the server name may come from an interceptor (a captive portal): it does not
//     overrule a mode that worked, and a mode without the share entered on it tries the share again after
//     realityPQRetryMin, then less and less often.
//   - Without the share, a rejection switches back while this mode has never worked, three in a row once it
//     has. Two handshakes in a row without an answer also switch back while it has never worked.
//   - When the server rejects both ClientHellos one after the other, the configuration is wrong (or the
//     network intercepts TLS) rather than the share: the default mode stays for realityPQHoldMin, and a
//     warning says what to check. A server that keeps rejecting both with its target's certificate is held
//     twice as long each time, up to realityPQHoldMax.
//
// While a mode has not worked yet, its first handshake runs alone and the others wait for it, up to
// realityPQProbeWait, so the connections that start together after a start or a reload do not all fail.
type realityPQState struct {
	access     sync.Mutex
	generation uint64        // results of handshakes started before the last switch are ignored
	strip      bool          // send the ClientHello without X25519MLKEM768
	confirmed  bool          // a handshake in the current mode got through
	probed     bool          // the first handshake in the current mode has ended
	probe      chan struct{} // closed when the probe of the current mode ends
	probeWait  time.Duration // realityPQProbeWait unless a test sets it
	rejections int
	silent     int
	doubtful   bool // the mode without the share was entered on a certificate not valid for the server name
	retryAt    time.Time
	retryDelay time.Duration
	retrying   bool
	heldUntil  time.Time
	heldValid  bool // the hold came from a server that rejected both with its target's certificate
	holds      int  // times in a row a server rejected both with its target's certificate
}

type realityPQTicket struct {
	generation uint64
	strip      bool
	probe      chan struct{} // set for the probe: closed by end
	retry      bool          // the share is tried again in a doubtful mode without it
}

// begin returns the mode for a new handshake. Every ticket must be passed to end.
func (s *realityPQState) begin(ctx context.Context, now time.Time) (realityPQTicket, error) {
	wait := s.probeWait
	if wait == 0 {
		wait = realityPQProbeWait
	}
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		wait = min(wait, time.Until(deadline)/2)
	}
	stop := time.Now().Add(wait)
	for {
		s.access.Lock()
		ticket := realityPQTicket{generation: s.generation, strip: s.strip}
		if !s.confirmed && !s.probed {
			if s.probe == nil {
				s.probe = make(chan struct{})
				ticket.probe = s.probe
				s.access.Unlock()
				return ticket, nil
			}
			probe := s.probe
			s.access.Unlock()
			remaining := time.Until(stop)
			if remaining <= 0 {
				return ticket, nil // the probe takes too long: go on in the current mode
			}
			timer := time.NewTimer(remaining)
			select {
			case <-probe:
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return realityPQTicket{}, ctx.Err()
			}
			timer.Stop()
			continue
		}
		if s.strip && s.confirmed && s.doubtful && !s.retrying && !now.Before(s.retryAt) {
			s.retrying = true
			ticket.strip = false
			ticket.retry = true
		}
		s.access.Unlock()
		return ticket, nil
	}
}

// end records how a handshake ended and returns what to log about a switch of the mode.
func (s *realityPQState) end(ticket realityPQTicket, result realityPQResult, now time.Time) (switched string, warning string) {
	s.access.Lock()
	defer s.access.Unlock()
	if ticket.probe != nil {
		close(ticket.probe)
		if s.probe == ticket.probe {
			s.probe = nil
		}
	}
	if ticket.retry {
		s.retrying = false
	}
	if ticket.generation != s.generation {
		return
	}
	if ticket.retry {
		switch result.outcome {
		case realityPQVerified:
			s.switchTo(false, false)
			s.confirmed = true
			s.holds = 0
			return "the server takes the ClientHello with X25519MLKEM768 again; sending it", ""
		case realityPQCanceled:
		default:
			s.retryDelay = min(2*s.retryDelay, realityPQRetryMax)
			s.retryAt = now.Add(s.retryDelay)
		}
		return
	}
	if ticket.probe != nil && result.outcome != realityPQCanceled {
		s.probed = true
	}
	switch result.outcome {
	case realityPQVerified:
		if s.strip && s.doubtful && !s.confirmed {
			s.retryDelay = realityPQRetryMin
			s.retryAt = now.Add(realityPQRetryMin)
		}
		s.confirmed = true
		s.rejections = 0
		s.silent = 0
		s.holds = 0
	case realityPQRejected:
		s.silent = 0
		if !s.strip {
			if result.group != utls.X25519MLKEM768 || s.confirmed && !result.valid {
				return
			}
			// A hold after an interceptor answered both does not stop the target's own answer.
			if now.Before(s.heldUntil) && (s.heldValid || !result.valid) {
				return
			}
			s.switchTo(true, !result.valid)
			return "the server answered with the certificate of its target, which chose X25519MLKEM768; sending the ClientHello without it", ""
		}
		s.rejections++
		if s.confirmed && s.rejections < realityStripRejectLimit {
			return
		}
		if !s.confirmed {
			// An interceptor goes away by itself: only a server that keeps rejecting both is held longer each time.
			hold := realityPQHoldMin
			if result.valid {
				hold = min(realityPQHoldMin<<min(s.holds, 5), realityPQHoldMax)
				s.holds++
				warning = "the server rejected the ClientHello both with and without X25519MLKEM768: check public_key, short_id, server_name and the clock of the device"
			} else {
				warning = "the server answered both ClientHellos with a certificate that is not valid for the server name: the network may intercept TLS"
			}
			s.heldUntil = now.Add(hold)
			s.heldValid = result.valid
		}
		s.switchTo(false, false)
		return "the server answered the ClientHello without X25519MLKEM768 with the certificate of its target; sending it again", warning
	case realityPQSilent:
		if !s.strip || s.confirmed {
			return
		}
		s.silent++
		if s.silent >= realityStripSilentLimit {
			s.switchTo(false, false)
			return "handshakes without X25519MLKEM768 got no answer; sending it again", ""
		}
	}
	return
}

func (s *realityPQState) switchTo(strip bool, doubtful bool) {
	s.generation++
	s.strip = strip
	s.doubtful = doubtful
	s.confirmed = false
	s.probed = false
	s.probe = nil // a probe of the old mode still running closes its own channel
	s.rejections = 0
	s.silent = 0
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	request, _ := http.NewRequest("GET", "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		ctx:       e.ctx,
		logger:    e.logger,
		uClient:   e.uClient.Clone().(*UTLSClientConfig),
		publicKey: e.publicKey,
		shortID:   e.shortID,
		pq:        e.pq,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName  string
	roots       *x509.CertPool // the certificate store of the outbound; nil: the system roots
	now         func() time.Time
	authKey     []byte
	verified    bool
	rejected    bool // the server answered with a certificate that is not its own: it did not authenticate us
	targetValid bool // that certificate is valid for the server name: the target answered, not an interceptor
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	c.rejected = true
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Roots:         c.roots,
		Intermediates: x509.NewCertPool(),
	}
	if c.now != nil {
		opts.CurrentTime = c.now()
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	c.targetValid = true
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return true
}
