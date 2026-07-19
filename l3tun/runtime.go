package l3tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"aSuspect/shared"
)

// Runtime owns the L3 tunnel, gVisor stack, and packet bridge.
type Runtime struct {
	state  *shared.SharedState
	stack  *gvisorStack
	tunnel *tunnel
}

// NewRuntime initializes L3, obtains the real VIP, and creates the gVisor stack.
func NewRuntime(state *shared.SharedState, spaExt []byte) (*Runtime, error) {
	tunnel, err := newTunnel(
		state.SID,
		state.DeviceID,
		state.ConnectionID,
		state.Username,
		state.SignKey,
	)
	if err != nil {
		return nil, fmt.Errorf("L3 tunnel: %w", err)
	}
	tunnel.SpaExt = spaExt

	if err := assignVIP(state, tunnel); err != nil {
		tunnel.Close()
		return nil, err
	}

	stack, err := newGvisorStack(state.VirtualIP)
	if err != nil {
		tunnel.Close()
		return nil, fmt.Errorf("gVisor stack: %w", err)
	}

	r := &Runtime{
		state:  state,
		stack:  stack,
		tunnel: tunnel,
	}

	// Wire synchronous egress — gVisor WritePackets calls this directly,
	// avoiding the extra goroutine/channel hop that can lose or delay packets.
	// This matches zju-connect's architecture: processIPV4 is called directly
	// from the endpoint's Write path.
	stack.OnEgress = func(rawPkt []byte) error {
		parsed, err := parseIPv4Packet(rawPkt)
		if err != nil {
			return err
		}
		return r.writeEgressPacket(rawPkt, parsed)
	}

	return r, nil
}

// Stack returns the L3 userspace stack used by DNS and L3 TCP/UDP routing.
func (r *Runtime) Stack() Stack {
	return r.stack
}

// Run bridges inbound packets from the L3 tunnel into gVisor.
// Outbound packets are handled synchronously by OnEgress, set in NewRuntime.
func (r *Runtime) Run(ctx context.Context) {
	r.runIngress(ctx)
}

// Close shuts down the L3 runtime.
func (r *Runtime) Close() {
	if r.stack != nil {
		r.stack.Close()
	}
	if r.tunnel != nil {
		r.tunnel.Close()
	}
}

func assignVIP(state *shared.SharedState, tunnel *tunnel) error {
	var vipOnce sync.Once
	vipDone := make(chan struct{})
	tunnel.OnVIP = func(ips []net.IP) {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				vipOnce.Do(func() {
					state.VirtualIP = v4
					log.Printf("L3 VIP: %s", ip)
					close(vipDone)
				})
				return
			}
		}
	}

	nodeAddrs := state.NodeCandidates(state.MajorGroupID)
	if len(nodeAddrs) > 0 {
		go func() {
			for _, nodeAddr := range nodeAddrs {
				if _, err := tunnel.EnsureConn(nodeAddr); err != nil {
					log.Printf("L3 initial connect %s: %s", nodeAddr, err)
					continue
				}
				vipOnce.Do(func() { close(vipDone) })
				return
			}
			vipOnce.Do(func() { close(vipDone) })
		}()
		<-vipDone
	}
	if state.VirtualIP == nil {
		return fmt.Errorf("L3 VIP was not assigned by the tunnel handshake")
	}
	return nil
}

// writeEgressPacket parses a raw IPv4 packet, matches it against resources,
// and sends it through the L3 tunnel with per-flow authentication.
// Returns an error if the packet doesn't match any resource or sending fails.
// This mirrors zju-connect's processIPV4 → writePacket path.
func (r *Runtime) writeEgressPacket(rawPkt []byte, parsed parsedPacket) error {
	snap := r.state.Snapshot()

	proto := l3ResourceProto(parsed.Proto)
	var res *shared.IPResource
	if route, ok := r.stack.findFlowRoute(parsed); ok {
		res = &shared.IPResource{
			IPMin: parsed.DstIP, IPMax: parsed.DstIP,
			PortMin: int(parsed.DstPort), PortMax: int(parsed.DstPort), Protocol: proto,
			AppID: route.appID, NodeGroupID: route.nodeGroupID,
		}
	} else {
		res = snap.FindIPResource(parsed.DstIP, proto, int(parsed.DstPort))
	}
	if res == nil && proto == shared.ProtoUDP && parsed.DstPort == 53 && parsed.DstIP.Equal(snap.DNSServer) {
		res = &shared.IPResource{
			IPMin: parsed.DstIP, IPMax: parsed.DstIP,
			PortMin: 53, PortMax: 53, Protocol: shared.ProtoUDP,
			NodeGroupID: snap.MajorGroupID,
		}
	}
	if res == nil {
		return fmt.Errorf("resource not found for %s:%d proto=%s",
			parsed.DstIP, parsed.DstPort, proto)
	}

	nodeAddrs := snap.NodeCandidates(res.NodeGroupID)
	if len(nodeAddrs) == 0 {
		return fmt.Errorf("no nodes for group %q", res.NodeGroupID)
	}

	for _, nodeAddr := range nodeAddrs {
		conn, err := r.tunnel.EnsureConn(nodeAddr)
		if err != nil {
			log.Printf("L3 egress bridge connect %s: %s", nodeAddr, err)
			continue
		}

		err = r.tunnel.WritePacket(conn, parsed.SrcIP, parsed.SrcPort,
			parsed.DstIP, parsed.DstPort, parsed.Proto, res.AppID, rawPkt)
		if err == nil {
			return nil
		}
		log.Printf("L3 egress bridge write %s: %s", nodeAddr, err)
	}
	return fmt.Errorf("failed to send packet through any L3 node")
}

func (r *Runtime) runIngress(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case rawPkt, ok := <-r.tunnel.Incoming:
			if !ok {
				return
			}
			r.stack.DeliverInbound(rawPkt)
		}
	}
}

func l3ResourceProto(proto uint8) shared.Protocol {
	switch proto {
	case 17:
		return shared.ProtoUDP
	case 1:
		return shared.ProtoICMP
	default:
		return shared.ProtoTCP
	}
}
