package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"aSuspect/l3tun"
	"aSuspect/l4fast"
	"aSuspect/shared"
)

// router makes routing decisions for each SOCKS5 request.
type router struct {
	state   *shared.SharedState
	l4T     *l4fast.Tunnel
	gstack  l3tun.Stack
	tcpMode string // "l4" or "l3"
}

func newRouter(
	state *shared.SharedState,
	l4t *l4fast.Tunnel,
	gs l3tun.Stack,
	tcpMode string,
) *router {
	return &router{
		state:   state,
		l4T:     l4t,
		gstack:  gs,
		tcpMode: tcpMode,
	}
}

// dial dispatches to dialTCP or dialUDP based on the network parameter.
// This is the unified entry point for go-socks5, which uses the same
// dial function for both TCP CONNECT and UDP ASSOCIATE.
func (r *router) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		return r.dialTCP(ctx, addr)
	case "udp":
		return r.dialUDP(addr)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// dialTCP routes a TCP connection.
//
// Decision:
//
//  1. Match domain/IP resources → VPN
//  2. No match → drop
//  3. VPN + tcpMode=l4 → L4 TCP Tunnel (dedicated TLS per connection)
//  4. VPN + tcpMode=l3 → gVisor stack → L3 Tunnel
func (r *router) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(host)
	domain, _ := ctx.Value(ctxKeyResolveHost).(string)
	if domain == "" && targetIP == nil {
		domain = host
	}
	snap := r.state.Snapshot()

	// ── Resource matching ────────────────────────────────────────────
	var appID, ngID string
	matched := false
	if domain != "" {
		if res := snap.FindDomainResource(domain, shared.ProtoTCP, port); res != nil {
			appID, ngID, matched = res.AppID, res.NodeGroupID, true
		}
	}

	if !matched && targetIP != nil {
		if res := snap.FindIPResource(targetIP, shared.ProtoTCP, port); res != nil {
			appID, ngID, matched = res.AppID, res.NodeGroupID, true
		}
	}

	// ── No resource match → drop ──────────────────────────────────
	if !matched {
		return nil, fmt.Errorf("route: %s:%d does not match any aTrust resource — dropped", host, port)
	}

	// ── VPN: resolve app and node group ─────────────────────────────
	nodeAddrs := snap.NodeCandidates(ngID)
	if len(nodeAddrs) == 0 {
		return nil, fmt.Errorf("no available node for group %q", ngID)
	}

	// ── Route to tunnel ─────────────────────────────────────────────
	switch r.tcpMode {
	case "l3":
		// TCP via gVisor stack → L3 tunnel.
		if targetIP == nil {
			return nil, fmt.Errorf("L3 TCP requires resolved IP address for %s", host)
		}
		return r.gstack.DialTCP(&net.TCPAddr{IP: targetIP, Port: port}, appID, ngID)
	default:
		// TCP via L4 dedicated tunnel.
		tunnelDomain := domain
		if targetIP != nil {
			tunnelDomain = ""
		}
		var lastErr error
		for _, nodeAddr := range nodeAddrs {
			conn, err := r.l4T.Dial(nodeAddr, targetIP, port, tunnelDomain, appID)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("L4 dial via nodes: %w", lastErr)
	}
}

// dialUDP creates a UDP connection through gVisor stack → L3 tunnel.
func (r *router) dialUDP(addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		return nil, fmt.Errorf("UDP requires resolved IP address")
	}

	// Match resource for routing.
	snap := r.state.Snapshot()
	if snap.FindIPResource(targetIP, shared.ProtoUDP, port) != nil {
		return r.gstack.DialUDP(
			nil,
			&net.UDPAddr{IP: targetIP, Port: port},
		)
	}

	return nil, fmt.Errorf("route: %s:%d does not match any aTrust resource", targetIP, port)
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}
