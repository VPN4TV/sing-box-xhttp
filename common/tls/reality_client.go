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
		ticket   realityPQTicket
		outcome  realityPQOutcome
		selected utls.CurveID
	)
	if postQuantum {
		ticket, err = e.pq.begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() {
			switched, warning := e.pq.end(ticket, outcome, selected, time.Now())
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
		outcome = realityPQVerified
	case verifier.rejected:
		outcome = realityPQRejected
		if serverHello := uConn.HandshakeState.ServerHello; serverHello != nil {
			selected = serverHello.ServerShare.Group
		}
	case errors.Is(err, context.Canceled):
		outcome = realityPQCanceled
	default:
		outcome = realityPQSilent
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
	realityPQSilentLimit    = 3                // unanswered handshakes with X25519MLKEM768 before trying without it
	realityStripSilentLimit = 2                // unanswered handshakes without X25519MLKEM768 before going back
	realityStripRejectLimit = 3                // rejections in a row that make a working mode without it go back
	realityPQHold           = 10 * time.Minute // after the server rejected both ClientHellos
)

type realityPQOutcome uint8

const (
	realityPQCanceled realityPQOutcome = iota // the caller gave up: nothing is known about the server
	realityPQVerified
	realityPQRejected // the server answered with the certificate of its target
	realityPQSilent   // the handshake ended before the server's certificate
)

// realityPQState remembers whether a REALITY server takes the X25519MLKEM768 key share. Xray since v26.9.9
// (XTLS/REALITY 8cdf7bf) rejects a ClientHello without it. REALITY servers older than Xray v25.5.16, and
// sing-box up to 1.11, pass on the ServerHello of their target when the target picks X25519MLKEM768, so the
// handshake ends with the target's certificate. The ClientHello with the share, as the browser sends it, is
// the default.
//
//   - With the share, a rejection in which the target picked X25519MLKEM768 switches to the ClientHello
//     without it at once. A rejection with any other group has nothing to do with the share and changes
//     nothing. While this mode has never worked, three handshakes in a row that end before the server's
//     certificate also switch: some middleboxes drop a ClientHello that spans two packets.
//   - Without the share, a rejection switches back while this mode has never worked, three in a row once it
//     has. Two unanswered handshakes in a row also switch back while it has never worked.
//   - When a mode without the share that has never worked is rejected, the server needs the share, or rejects
//     us for another reason: for realityPQHold the default mode stays whatever happens. If the share had been
//     rejected just before, the configuration is wrong rather than the share, and a warning says so.
//
// While a mode has not worked yet, its first handshake runs alone and the others wait for its result, so the
// connections that start together after a start or a reload do not all fail.
type realityPQState struct {
	access      sync.Mutex
	generation  uint64 // results of handshakes started before the last switch are ignored
	strip       bool   // send the ClientHello without X25519MLKEM768
	confirmed   bool   // a handshake in the current mode got through
	probed      bool   // the first handshake in the current mode has ended
	probe       chan struct{}
	rejections  int
	silent      int
	afterReject bool // the current mode without the share was entered after the share was rejected
	heldUntil   time.Time
}

type realityPQTicket struct {
	generation uint64
	strip      bool
	probe      bool
}

// begin returns the mode for a new handshake. Every ticket must be passed to end.
func (s *realityPQState) begin(ctx context.Context) (realityPQTicket, error) {
	for {
		s.access.Lock()
		if s.confirmed || s.probed || s.probe == nil {
			ticket := realityPQTicket{generation: s.generation, strip: s.strip}
			if !s.confirmed && !s.probed {
				s.probe = make(chan struct{})
				ticket.probe = true
			}
			s.access.Unlock()
			return ticket, nil
		}
		probe := s.probe
		s.access.Unlock()
		select {
		case <-probe:
		case <-ctx.Done():
			return realityPQTicket{}, ctx.Err()
		}
	}
}

// end records how a handshake ended and returns what to log about a switch of the mode.
func (s *realityPQState) end(ticket realityPQTicket, outcome realityPQOutcome, group utls.CurveID, now time.Time) (switched string, warning string) {
	s.access.Lock()
	defer s.access.Unlock()
	if ticket.probe {
		close(s.probe)
		s.probe = nil
	}
	if ticket.generation != s.generation {
		return
	}
	if ticket.probe && outcome != realityPQCanceled {
		s.probed = true
	}
	switch outcome {
	case realityPQVerified:
		s.confirmed = true
		s.rejections = 0
		s.silent = 0
	case realityPQRejected:
		s.silent = 0
		if !s.strip {
			if group != utls.X25519MLKEM768 || now.Before(s.heldUntil) {
				return
			}
			s.switchTo(true, true)
			return "the server answered with the certificate of its target, which chose X25519MLKEM768; sending the ClientHello without it", ""
		}
		s.rejections++
		if s.confirmed && s.rejections < realityStripRejectLimit {
			return
		}
		if !s.confirmed {
			s.heldUntil = now.Add(realityPQHold)
			if s.afterReject {
				warning = "the server rejected the ClientHello both with and without X25519MLKEM768: check public_key, short_id, server_name and the clock of the device"
			}
		}
		s.switchTo(false, false)
		return "the server answered the ClientHello without X25519MLKEM768 with the certificate of its target; sending it again", warning
	case realityPQSilent:
		if s.confirmed {
			return
		}
		s.silent++
		if s.strip && s.silent >= realityStripSilentLimit {
			s.switchTo(false, false)
			return "handshakes without X25519MLKEM768 got no answer either; sending it again", ""
		}
		if !s.strip && s.silent >= realityPQSilentLimit && !now.Before(s.heldUntil) {
			s.switchTo(true, false)
			return "handshakes with X25519MLKEM768 got no answer; trying the ClientHello without it", ""
		}
	}
	return
}

func (s *realityPQState) switchTo(strip bool, afterReject bool) {
	s.generation++
	s.strip = strip
	s.afterReject = afterReject
	s.confirmed = false
	s.probed = false
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
	serverName string
	authKey    []byte
	verified   bool
	rejected   bool // the server answered with a certificate of its target: it did not authenticate us
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
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
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
