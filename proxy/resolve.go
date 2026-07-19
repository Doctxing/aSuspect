package proxy

// DNS resolver — two-layer resolution, no system DNS fallback.
//
//	1. Static hosts (server-pushed domain→IP mappings).
//	2. aTrust DNS server (UDP query via gVisor stack → L3 tunnel).
//	3. Error — caller decides next step.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"aSuspect/l3tun"
	"aSuspect/shared"

	"github.com/patrickmn/go-cache"
)

// resolver resolves domain names through the VPN DNS pipeline.
type resolver struct {
	state    *shared.SharedState
	gstack   l3tun.Stack
	cache    *cache.Cache
	cacheTTL time.Duration
}

func newResolver(
	state *shared.SharedState,
	gs l3tun.Stack,
	ttl uint64,
) *resolver {
	if ttl == 0 {
		ttl = 3600
	}
	return &resolver{
		state:    state,
		gstack:   gs,
		cache:    cache.New(time.Duration(ttl)*time.Second, time.Duration(ttl)*2*time.Second),
		cacheTTL: time.Duration(ttl) * time.Second,
	}
}

func (r *resolver) resolve(domain string) (net.IP, error) {
	// 0. Cache check.
	if ip, found := r.cache.Get(domain); found {
		return ip.(net.IP), nil
	}

	snap := r.state.Snapshot()

	// 1. Static hosts (server-pushed, most authoritative).
	if ip := snap.FindStaticHost(domain); ip != nil {
		r.cache.Set(domain, ip, r.cacheTTL)
		return ip, nil
	}

	// 2. aTrust DNS via gVisor stack → L3 tunnel.
	if ip, err := r.resolveViaGVisor(domain, snap.DNSServer); err == nil {
		r.cache.Set(domain, ip, r.cacheTTL)
		return ip, nil
	}

	// 3. Give up.
	return nil, fmt.Errorf("dns: %s: no static record, aTrust DNS failed", domain)
}

func (r *resolver) resolveViaGVisor(domain string, dnsServer net.IP) (net.IP, error) {
	if dnsServer == nil {
		return nil, fmt.Errorf("no DNS server configured")
	}

	query := buildDNSQuery(domain)

	// Dial UDP to DNS server through gVisor stack.
	// gVisor handles UDP source port allocation and packet framing.
	conn, err := r.gstack.DialUDP(
		nil, // let gVisor pick source
		&net.UDPAddr{IP: dnsServer, Port: 53},
	)
	if err != nil {
		return nil, fmt.Errorf("DNS dial: %w", err)
	}
	defer conn.Close()

	// Send DNS query.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("DNS write: %w", err)
	}

	// Read DNS response.
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("DNS read: %w", err)
	}

	ip := parseDNSResponse(buf[:n])
	if ip == nil {
		return nil, fmt.Errorf("DNS response has no A record")
	}
	return ip, nil
}

// ── DNS wire format ────────────────────────────────────────────────────

func buildDNSQuery(domain string) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], uint16(rand.Intn(65536))) // ID
	buf[2] = 0x01                                                  // recursion desired
	buf[5] = 0x01                                                  // 1 question

	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)       // terminator
	buf = append(buf, 0x00, 0x01) // type A
	buf = append(buf, 0x00, 0x01) // class IN
	return buf
}

func parseDNSResponse(data []byte) net.IP {
	if len(data) < 12 {
		return nil
	}
	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil
	}

	pos := 12
	qdcount := binary.BigEndian.Uint16(data[4:6])
	for i := 0; i < int(qdcount); i++ {
		pos = skipName(data, pos)
		pos += 4
	}

	for i := 0; i < int(ancount); i++ {
		pos = skipName(data, pos)
		if pos+10 > len(data) {
			return nil
		}
		atype := binary.BigEndian.Uint16(data[pos : pos+2])
		rdlen := binary.BigEndian.Uint16(data[pos+8 : pos+10])
		pos += 10

		if atype == 1 && rdlen == 4 && pos+4 <= len(data) {
			return net.IPv4(data[pos], data[pos+1], data[pos+2], data[pos+3])
		}
		pos += int(rdlen)
	}
	return nil
}

func skipName(data []byte, pos int) int {
	for pos < len(data) {
		b := data[pos]
		if b == 0 {
			return pos + 1
		}
		if b&0xC0 == 0xC0 {
			return pos + 2
		}
		pos += int(b) + 1
	}
	return pos
}
