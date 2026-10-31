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
		pq:        &realityPQState{},
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
	// Xray since v26.9.9 (XTLS/REALITY 8cdf7bf) rejects a ClientHello without an X25519MLKEM768 key share,
	// while REALITY servers older than Xray v25.5.16 fail when their target picks X25519MLKEM768. Profiles
	// that carry the hybrid share send it as the browser does; a server that rejects us switches this
	// outbound to the other mode for the next connections. Other profiles are left as they are.
	postQuantum := realityHasPostQuantumShare(uConn)
	strip := !postQuantum || e.pq.stripping()
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
	if postQuantum && (err == nil || verifier.rejected) {
		if e.pq.report(strip, err == nil) && e.logger != nil {
			if strip {
				e.logger.InfoContext(ctx, "reality: server rejected the ClientHello without X25519MLKEM768, sending it from now on")
			} else {
				e.logger.InfoContext(ctx, "reality: server rejected the ClientHello with X25519MLKEM768, no longer sending it")
			}
		}
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

// realityPQState remembers for one outbound whether its server takes the X25519MLKEM768 key share.
// The mode switches after a single rejection while it has never worked with this server, and after
// three rejections in a row once it has, so a flaky network does not flip a working server.
type realityPQState struct {
	access    sync.Mutex
	strip     bool
	confirmed bool
	failures  int
}

func (s *realityPQState) stripping() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.strip
}

// report records the result of a handshake made in the given mode and returns true if the mode switched.
func (s *realityPQState) report(strip bool, verified bool) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if strip != s.strip {
		// started before the last switch
		return false
	}
	if verified {
		s.confirmed = true
		s.failures = 0
		return false
	}
	s.failures++
	limit := 1
	if s.confirmed {
		limit = 3
	}
	if s.failures < limit {
		return false
	}
	s.strip = !s.strip
	s.confirmed = false
	s.failures = 0
	return true
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
