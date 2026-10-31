//go:build with_utls

package tls

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

// Chrome 155 advertises trust anchor IDs of CAs it trusts (chrome155TrustAnchorIDs), 15 of them intermediates
// that Chrome keeps as anchors. A server that supports the extension may then send a chain that ends below
// them, down to the leaf alone when it elides the intermediate. Verification must trust what the ClientHello
// claims, so the certificates of these IDs are added to the roots of Chrome 155 handshakes.
//
//go:embed utls_chrome155_anchors.pem
var chrome155AnchorsPEM []byte

var chrome155AnchorCertificates = sync.OnceValue(func() []*x509.Certificate {
	var certificates []*x509.Certificate
	for rest := chrome155AnchorsPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certificates
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certificates = append(certificates, certificate)
		}
	}
})

// chrome155RootCAs returns pool with the certificates of the advertised trust anchor IDs added. It leaves a
// store with its own exclusive set of anchors (mozilla, none) as it is: that choice is the user's.
func chrome155RootCAs(ctx context.Context, pool *x509.CertPool) *x509.CertPool {
	if store := service.FromContext[adapter.CertificateStore](ctx); store != nil && store.ExclusiveAnchors() {
		if kind, isKind := store.(interface{ StoreKind() string }); !isKind || kind.StoreKind() != C.CertificateStoreChrome {
			return pool
		}
	}
	if pool == nil {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			return nil
		}
		pool = systemPool
	} else {
		pool = pool.Clone()
	}
	for _, certificate := range chrome155AnchorCertificates() {
		pool.AddCert(certificate)
	}
	return pool
}
