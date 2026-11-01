package libbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// VPN4TV: how the outline and wireproxy bridges find their own servers.
//
// A bridge given its server by name used to ask the system resolver: outline
// on every connection and UDP session, wireproxy for every [Peer] Endpoint
// when it starts. On Android that is the cgo resolver, which asks the DNS of
// the VPN network — our own TUN. In a profile made only of bridges the query
// then went hijack-dns → dns-remote → select → the very bridge that needed the
// answer: a loop.
//
// Given DNS servers in its config ("dns", see bridgeDNSServers), a bridge now
// asks them itself, over sockets that stay out of the tunnel (bridgeControl),
// the way olcrtc does with olcrtcResolver. Without servers it keeps the system
// resolver, exactly as before.
//
// Answers are kept (bridgeDNSCache): a name is asked again after
// bridgeDNSFresh, in the background, while the old answer stays in use — and
// stays in use when the servers stop answering. A bridge whose DNS goes dark
// keeps reaching an address it already knew.

const (
	// bridgeDNSTimeout bounds one lookup, every server included.
	bridgeDNSTimeout = 5 * time.Second
	// bridgeDNSStagger: a server that has not answered within this long gets
	// company — the next one is asked too, and the first answer wins.
	bridgeDNSStagger = time.Second
	// bridgeDNSCacheSize bounds the names kept; a few bridges have a few.
	bridgeDNSCacheSize = 128
	// bridgeDialAttempt bounds a TCP connection to one address of a server
	// when more addresses are left to try.
	bridgeDialAttempt = 5 * time.Second
)

// Package variables so tests can shorten them.
var (
	bridgeDNSFresh    = 5 * time.Minute
	bridgeDNSNegative = 10 * time.Second
)

// bridgeDNSServers is the "dns" field of a bridge config or endpoint: a list
// of servers, or one server as a plain string (olcrtc's form). Each is an IP
// address with an optional port (53 when absent) — a server given by name
// would need the very resolver this replaces.
type bridgeDNSServers []string

// UnmarshalJSON takes a string or a list of strings. Anything else is kept as
// its JSON text, which newBridgeResolver rejects with a line in the bridge log:
// a malformed field must not cost the bridge its start.
func (s *bridgeDNSServers) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = nil
		if one != "" {
			*s = bridgeDNSServers{one}
		}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*s = list
		return nil
	}
	*s = bridgeDNSServers{string(data)}
	return nil
}

// pickBridgeDNS: an endpoint's own list replaces the bridge-wide one.
func pickBridgeDNS(endpoint, bridge bridgeDNSServers) bridgeDNSServers {
	if len(endpoint) > 0 {
		return endpoint
	}
	return bridge
}

// parseBridgeDNSServer reads "1.2.3.4", "1.2.3.4:53", "2001:db8::1" or
// "[2001:db8::1]:53".
func parseBridgeDNSServer(value string) (netip.AddrPort, error) {
	value = strings.TrimSpace(value)
	var server netip.AddrPort
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		server = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
	} else if addr, err := netip.ParseAddr(value); err == nil {
		server = netip.AddrPortFrom(addr.Unmap(), 53)
	} else {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IP address", value)
	}
	if server.Port() == 0 || server.Addr().IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("%q is not a usable server", value)
	}
	return server, nil
}

// bridgeResolver asks a bridge's DNS servers for the names of its servers.
type bridgeResolver struct {
	servers []netip.AddrPort
	logf    func(string, ...any)
	// control keeps every DNS socket out of the tunnel; bridgeControl, but
	// tests watch it.
	control func(network, address string, conn syscall.RawConn) error
}

// newBridgeResolver returns nil — the system resolver, as before — when the
// list holds no usable server.
func newBridgeResolver(values bridgeDNSServers, logf func(string, ...any)) *bridgeResolver {
	var servers []netip.AddrPort
	for _, value := range values {
		server, err := parseBridgeDNSServer(value)
		if err != nil {
			logf("dns: %v, skipped", err)
			continue
		}
		if !slices.Contains(servers, server) {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		if len(values) > 0 {
			logf("dns: no usable server, names go to the system resolver")
		}
		return nil
	}
	return &bridgeResolver{servers: servers, logf: logf, control: bridgeControl}
}

func (r *bridgeResolver) String() string {
	names := make([]string, len(r.servers))
	for i, server := range r.servers {
		names[i] = server.String()
	}
	return strings.Join(names, ", ")
}

// netResolver is Go's resolver pointed at one server only.
func (r *bridgeResolver) netResolver(server netip.AddrPort) *net.Resolver {
	dialer := net.Dialer{Timeout: bridgeDNSTimeout, Control: r.control}
	address := server.String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

// query asks the servers for host: the first at once, each next one when the
// previous failed or has been silent for bridgeDNSStagger. The first answer
// with addresses wins.
func (r *bridgeResolver) query(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bridgeDNSTimeout)
	defer cancel()
	type answer struct {
		addrs []netip.Addr
		err   error
	}
	// Room for every answer: a late one never blocks its goroutine.
	answers := make(chan answer, len(r.servers))
	next := 0
	ask := func() {
		server := r.servers[next]
		next++
		go func() {
			addrs, err := r.netResolver(server).LookupNetIP(ctx, "ip", host)
			// Go names the server of the system's own configuration, which
			// nobody asked; name the one that was.
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				named := *dnsErr
				named.Server = server.String()
				err = &named
			} else if err != nil {
				err = fmt.Errorf("%s: %w", server, err)
			}
			answers <- answer{addrs, err}
		}()
	}
	ask()
	stagger := time.NewTimer(bridgeDNSStagger)
	defer stagger.Stop()
	var lastErr error
	for pending := 1; pending > 0; {
		select {
		case a := <-answers:
			pending--
			if a.err == nil && len(a.addrs) > 0 {
				addrs := make([]netip.Addr, 0, len(a.addrs))
				for _, addr := range a.addrs {
					addrs = append(addrs, addr.Unmap())
				}
				return addrs, nil
			}
			lastErr = a.err
			if lastErr == nil {
				lastErr = errors.New("no address")
			}
			if next < len(r.servers) {
				ask()
				pending++
				stagger.Reset(bridgeDNSStagger)
			}
		case <-stagger.C:
			if next < len(r.servers) {
				ask()
				pending++
				stagger.Reset(bridgeDNSStagger)
			}
		}
	}
	return nil, lastErr
}

// bridgeDNSEntry is what is known about one name.
type bridgeDNSEntry struct {
	addrs   []netip.Addr
	fetched time.Time // when addrs came
	err     error     // the last failure, while there are no addrs
	failed  time.Time
	pending chan struct{} // closed when the running query ends; nil when none
}

// bridgeDNSCache holds the answers of every bridge, across restarts of the
// bridges (a reload restarts them) — keyed by name only: whichever servers
// answered, the name is the same server.
var bridgeDNSCache = struct {
	sync.Mutex
	entries map[string]*bridgeDNSEntry
}{entries: make(map[string]*bridgeDNSEntry)}

// lookup returns the addresses of host: from the cache when it has them
// (refreshing them in the background once they are older than
// bridgeDNSFresh), otherwise from a query shared with every other caller
// waiting for the same name.
func (r *bridgeResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	key := strings.ToLower(strings.TrimSuffix(host, "."))
	cache := &bridgeDNSCache
	cache.Lock()
	entry := cache.entries[key]
	if entry == nil {
		entry = &bridgeDNSEntry{}
		storeBridgeDNSLocked(key, entry)
	}
	if len(entry.addrs) > 0 {
		addrs := entry.addrs
		if time.Since(entry.fetched) >= bridgeDNSFresh && entry.pending == nil {
			r.startQueryLocked(key, entry)
		}
		cache.Unlock()
		return addrs, nil
	}
	if entry.pending == nil {
		if entry.err != nil && time.Since(entry.failed) < bridgeDNSNegative {
			err := entry.err
			cache.Unlock()
			return nil, err
		}
		r.startQueryLocked(key, entry)
	}
	pending := entry.pending
	cache.Unlock()
	select {
	case <-pending:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	cache.Lock()
	addrs, err := entry.addrs, entry.err
	cache.Unlock()
	if len(addrs) > 0 {
		return addrs, nil
	}
	if err == nil {
		err = errors.New("no address")
	}
	return nil, err
}

// storeBridgeDNSLocked adds an entry, making room by dropping the one fetched
// longest ago that no query is running for.
func storeBridgeDNSLocked(key string, entry *bridgeDNSEntry) {
	entries := bridgeDNSCache.entries
	if len(entries) >= bridgeDNSCacheSize {
		var oldestKey string
		var oldest *bridgeDNSEntry
		for k, e := range entries {
			if e.pending == nil && (oldest == nil || e.fetched.Before(oldest.fetched)) {
				oldestKey, oldest = k, e
			}
		}
		if oldest != nil {
			delete(entries, oldestKey)
		}
	}
	entries[key] = entry
}

// startQueryLocked runs a query for entry in the background. A failure keeps
// the addresses the entry already had.
func (r *bridgeResolver) startQueryLocked(key string, entry *bridgeDNSEntry) {
	done := make(chan struct{})
	entry.pending = done
	go func() {
		addrs, err := r.query(key)
		cache := &bridgeDNSCache
		cache.Lock()
		stale := entry.addrs
		if err == nil {
			entry.addrs, entry.fetched, entry.err = addrs, time.Now(), nil
		} else if len(stale) == 0 {
			entry.err, entry.failed = err, time.Now()
		}
		entry.pending = nil
		cache.Unlock()
		close(done)
		switch {
		case err == nil:
			r.logf("dns: %s is %s", key, joinAddrs(addrs))
		case len(stale) > 0:
			r.logf("dns: %s: %v; keeping %s", key, err, joinAddrs(stale))
		default:
			r.logf("dns: %s: %v", key, err)
		}
	}()
}

func joinAddrs(addrs []netip.Addr) string {
	names := make([]string, len(addrs))
	for i, addr := range addrs {
		names[i] = addr.String()
	}
	return strings.Join(names, ", ")
}

// orderAddrs puts IPv4 first, keeping the order within each family: most
// servers and networks carry IPv4, and the system resolver picked it first
// too.
func orderAddrs(addrs []netip.Addr) []netip.Addr {
	ordered := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Is4() {
			ordered = append(ordered, addr)
		}
	}
	for _, addr := range addrs {
		if !addr.Is4() {
			ordered = append(ordered, addr)
		}
	}
	return ordered
}

// dial connects to address ("host:port"); a name goes to lookup, then its
// addresses are tried in turn (IPv4 first). An address literal is dialled as
// it is.
func (r *bridgeResolver) dial(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return dialer.DialContext(ctx, network, address)
	}
	addrs, err := r.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	addrs = orderAddrs(addrs)
	var firstErr error
	for i, addr := range addrs {
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		// UDP "connects" at once; a TCP address that does not answer must
		// not hold up the next one for the system's whole connect timeout.
		if i < len(addrs)-1 && strings.HasPrefix(network, "tcp") {
			attemptCtx, cancel = context.WithTimeout(ctx, bridgeDialAttempt)
		}
		conn, err := dialer.DialContext(attemptCtx, network, net.JoinHostPort(addr.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}
