package libbox

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// VPN4TV: the local SOCKS5 inbound shared by the outline and wireproxy bridges
// (olcrtc, TrustTunnel and xray have their own servers).
//
// The bridges listen on loopback, and on Android the loopback is shared by
// every app on the device. Without a password any app — one the user excluded
// from the VPN included — can connect to a bridge, go out through our server
// and learn its address: the "local proxy" leak, runetfreedom 2026-04. The
// mobile apps now give every bridge inbound a random username/password and put
// the same pair on the sing-box socks outbounds that reach it.
//
// The credentials are optional: an endpoint without them keeps the historical
// no-auth inbound byte for byte, so configs that do not carry them (the desktop
// daemon, older profiles) behave exactly as before.

// bridgeSocksAuth is the optional username/password (RFC 1929) of an inbound.
type bridgeSocksAuth struct {
	username []byte
	password []byte
}

func newBridgeSocksAuth(username, password string) *bridgeSocksAuth {
	if username == "" && password == "" {
		return nil
	}
	return &bridgeSocksAuth{username: []byte(username), password: []byte(password)}
}

const (
	socks5Version         = 0x05
	socks5MethodNoAuth    = 0x00
	socks5MethodUserPass  = 0x02
	socks5MethodNoneFound = 0xFF
	socks5UserPassVersion = 0x01
	socks5CommandConnect  = 0x01
	socks5ReplyNoCommand  = 0x07
	// A client that connects and then says nothing must not hold a goroutine
	// forever; sing-box sends the whole handshake at once.
	socks5HandshakeTimeout = 10 * time.Second
)

// socks5Handshake runs the greeting, the optional username/password
// subnegotiation and reads the request, returning the requested destination
// "host:port". Only CONNECT is served: the outline and wireproxy bridges carry
// TCP alone, and BIND / UDP ASSOCIATE used to be misread as CONNECT.
//
// It does not send the success reply — the caller does, after it has dialled.
func socks5Handshake(c net.Conn, auth *bridgeSocksAuth) (string, error) {
	_ = c.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	buf := make([]byte, 262)
	// Greeting: VER(1) NMETHODS(1) METHODS(NMETHODS)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", errors.New("not socks5")
	}
	methods := buf[2 : 2+int(buf[1])]
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	if auth == nil {
		// Historical behaviour, unchanged: no authentication, whatever the
		// client offered.
		if _, err := c.Write([]byte{socks5Version, socks5MethodNoAuth}); err != nil {
			return "", err
		}
	} else {
		if bytes.IndexByte(methods, socks5MethodUserPass) < 0 {
			_, _ = c.Write([]byte{socks5Version, socks5MethodNoneFound})
			return "", errors.New("client did not offer username/password authentication")
		}
		if _, err := c.Write([]byte{socks5Version, socks5MethodUserPass}); err != nil {
			return "", err
		}
		if err := socks5Authenticate(c, auth); err != nil {
			return "", err
		}
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", errors.New("not socks5")
	}
	if buf[1] != socks5CommandConnect {
		_, _ = c.Write([]byte{socks5Version, socks5ReplyNoCommand, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported command %d", buf[1])
	}
	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		length := int(buf[0])
		if _, err := io.ReadFull(c, buf[:length]); err != nil {
			return "", err
		}
		host = string(buf[:length])
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", errors.New("unknown ATYP")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	port := int(buf[0])<<8 | int(buf[1])
	// JoinHostPort wraps IPv6 addresses in brackets.
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// socks5Authenticate reads an RFC 1929 request and checks it. Both halves are
// always compared so the timing does not tell which one was wrong.
func socks5Authenticate(c net.Conn, auth *bridgeSocksAuth) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	if header[0] != socks5UserPassVersion {
		_, _ = c.Write([]byte{socks5UserPassVersion, 0x01})
		return errors.New("wrong username/password version")
	}
	username := make([]byte, header[1])
	if _, err := io.ReadFull(c, username); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, header[:1]); err != nil {
		return err
	}
	password := make([]byte, header[0])
	if _, err := io.ReadFull(c, password); err != nil {
		return err
	}
	usernameOK := subtle.ConstantTimeCompare(username, auth.username) == 1
	passwordOK := subtle.ConstantTimeCompare(password, auth.password) == 1
	if !usernameOK || !passwordOK {
		_, _ = c.Write([]byte{socks5UserPassVersion, 0x01})
		return errors.New("wrong username or password")
	}
	_, err := c.Write([]byte{socks5UserPassVersion, 0x00})
	return err
}
