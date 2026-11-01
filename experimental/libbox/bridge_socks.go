package libbox

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	M "github.com/sagernet/sing/common/metadata"
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
//
// UDP reaches the bridges two ways, both only after the same greeting and
// password check (see bridge_udp.go): sing-box's UDP over TCP inside an
// ordinary CONNECT, which is what the apps use, and a standard UDP ASSOCIATE
// whose relay takes datagrams from one source only.

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
	socks5Version             = 0x05
	socks5MethodNoAuth        = 0x00
	socks5MethodUserPass      = 0x02
	socks5MethodNoneFound     = 0xFF
	socks5UserPassVersion     = 0x01
	socks5CommandConnect      = 0x01
	socks5CommandUDPAssociate = 0x03
	socks5ReplySucceeded      = 0x00
	socks5ReplyGeneralFailure = 0x01
	socks5ReplyNoCommand      = 0x07
	// A client that connects and then says nothing must not hold a goroutine
	// forever; sing-box sends the whole handshake at once.
	socks5HandshakeTimeout = 10 * time.Second
)

// socks5Request is what the client asked for once it was let in.
type socks5Request struct {
	command byte
	// host is the address as the client sent it: an IP literal or a name.
	host string
	port uint16
}

// dest is the request address as "host:port" (IPv6 in brackets).
func (r socks5Request) dest() string {
	return net.JoinHostPort(r.host, strconv.Itoa(int(r.port)))
}

// addr is the request address, an IP when host is a literal.
func (r socks5Request) addr() M.Socksaddr {
	return M.ParseSocksaddrHostPort(r.host, r.port).Unwrap()
}

// socks5Handshake runs the greeting, the optional username/password
// subnegotiation and reads the request. CONNECT is always served, UDP ASSOCIATE
// only when udp is set (the bridge has a packet path); BIND never — and
// neither of the others is misread as CONNECT any more.
//
// It does not send the success reply — the caller does, once it has dialled.
func socks5Handshake(c net.Conn, auth *bridgeSocksAuth, udp bool) (socks5Request, error) {
	_ = c.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	buf := make([]byte, 262)
	// Greeting: VER(1) NMETHODS(1) METHODS(NMETHODS)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return socks5Request{}, err
	}
	if buf[0] != socks5Version {
		return socks5Request{}, errors.New("not socks5")
	}
	methods := buf[2 : 2+int(buf[1])]
	if _, err := io.ReadFull(c, methods); err != nil {
		return socks5Request{}, err
	}
	if auth == nil {
		// Historical behaviour, unchanged: no authentication, whatever the
		// client offered.
		if _, err := c.Write([]byte{socks5Version, socks5MethodNoAuth}); err != nil {
			return socks5Request{}, err
		}
	} else {
		if bytes.IndexByte(methods, socks5MethodUserPass) < 0 {
			_, _ = c.Write([]byte{socks5Version, socks5MethodNoneFound})
			return socks5Request{}, errors.New("client did not offer username/password authentication")
		}
		if _, err := c.Write([]byte{socks5Version, socks5MethodUserPass}); err != nil {
			return socks5Request{}, err
		}
		if err := socks5Authenticate(c, auth); err != nil {
			return socks5Request{}, err
		}
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return socks5Request{}, err
	}
	if buf[0] != socks5Version {
		return socks5Request{}, errors.New("not socks5")
	}
	request := socks5Request{command: buf[1]}
	if request.command != socks5CommandConnect && (request.command != socks5CommandUDPAssociate || !udp) {
		_, _ = c.Write([]byte{socks5Version, socks5ReplyNoCommand, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return socks5Request{}, fmt.Errorf("unsupported command %d", request.command)
	}
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return socks5Request{}, err
		}
		request.host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return socks5Request{}, err
		}
		length := int(buf[0])
		if _, err := io.ReadFull(c, buf[:length]); err != nil {
			return socks5Request{}, err
		}
		request.host = string(buf[:length])
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return socks5Request{}, err
		}
		request.host = net.IP(buf[:16]).String()
	default:
		return socks5Request{}, errors.New("unknown ATYP")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return socks5Request{}, err
	}
	request.port = uint16(buf[0])<<8 | uint16(buf[1])
	return request, nil
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
