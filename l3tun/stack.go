package l3tun

// gVisor netstack integration — replaces the hand-rolled MiniStack.
//
// GVisor provides a full userspace TCP/IP stack: TCP (CUBIC/Reno),
// UDP, ICMP, ARP.  The stack runs on a virtual NIC with a /32 VIP.
//
// Architecture:
//
//	Outbound: socket dial → gonet.DialTCP/DialUDP → gVisor stack
//	          → Endpoint.WritePackets → L3 tunnel → aTrust node
//
//	Inbound:  L3 tunnel → raw IP packet → Endpoint.DeliverNetworkPacket
//	          → gVisor stack → gonet socket readable

import (
	"fmt"
	"net"

	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
)

const (
	nicID     tcpip.NICID = 1
	gvisorMTU uint32      = 1400
)

// gvisorStack wraps gVisor's userspace TCP/IP stack.
type gvisorStack struct {
	gs       *stack.Stack
	endpoint *endpoint

	// OnEgress is called synchronously from gVisor's WritePackets for each
	// outbound raw IPv4 packet. Set by the L3 Runtime at initialization.
	OnEgress func([]byte) error
}

// Stack is the L3 userspace network stack surface needed by upper layers.
type Stack interface {
	DialTCP(addr *net.TCPAddr) (net.Conn, error)
	DialUDP(laddr, raddr *net.UDPAddr) (net.Conn, error)
}

// endpoint is the virtual NIC that bridges gVisor ↔ L3 tunnel.
type endpoint struct {
	onEgress func([]byte) error

	dispatcher stack.NetworkDispatcher
}

// newGvisorStack creates a gVisor stack bound to virtualIP.
func newGvisorStack(virtualIP net.IP) (*gvisorStack, error) {
	s := &gvisorStack{}

	s.endpoint = &endpoint{}
	s.endpoint.onEgress = func(raw []byte) error {
		if s.OnEgress != nil {
			return s.OnEgress(raw)
		}
		return nil
	}

	// Create gVisor stack with IPv4, TCP, UDP.
	s.gs = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})

	// Create NIC with our custom endpoint.
	if tcpErr := s.gs.CreateNIC(nicID, s.endpoint); tcpErr != nil {
		return nil, fmt.Errorf("CreateNIC: %s", tcpErr)
	}

	// Assign /32 virtual IP.
	addr := tcpip.AddrFrom4Slice(virtualIP.To4())
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
		Protocol: ipv4.ProtocolNumber,
	}
	if tcpErr := s.gs.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); tcpErr != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %s", tcpErr)
	}

	// TCP tuning.
	sopt := tcpip.TCPSACKEnabled(true)
	s.gs.SetTransportProtocolOption(tcp.ProtocolNumber, &sopt)
	copt := tcpip.CongestionControlOption("cubic")
	s.gs.SetTransportProtocolOption(tcp.ProtocolNumber, &copt)

	// Default route — all traffic goes through the L3 NIC.
	s.gs.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})

	return s, nil
}

// DialTCP creates a TCP connection through the gVisor stack → L3 tunnel.
func (s *gvisorStack) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	return gonet.DialTCP(s.gs, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4Slice(addr.IP.To4()),
		Port: uint16(addr.Port),
	}, ipv4.ProtocolNumber)
}

// DialUDP creates a UDP socket through the gVisor stack → L3 tunnel.
func (s *gvisorStack) DialUDP(laddr *net.UDPAddr, raddr *net.UDPAddr) (net.Conn, error) {
	var local *tcpip.FullAddress
	if laddr != nil {
		local = &tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFrom4Slice(laddr.IP.To4()),
			Port: uint16(laddr.Port),
		}
	}
	remote := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4Slice(raddr.IP.To4()),
		Port: uint16(raddr.Port),
	}
	return gonet.DialUDP(s.gs, local, &remote, ipv4.ProtocolNumber)
}

// DeliverInbound feeds a raw IPv4 packet from the L3 tunnel into gVisor.
func (s *gvisorStack) DeliverInbound(data []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
	})
	s.endpoint.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// Close shuts down the gVisor stack.
func (s *gvisorStack) Close() {
	s.gs.Close()
}

// ── endpoint implements stack.LinkEndpoint ──────────────────────────────

func (e *endpoint) MTU() uint32                                  { return gvisorMTU }
func (e *endpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *endpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (e *endpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *endpoint) SetMTU(uint32)                                {}
func (e *endpoint) Wait()                                        {}
func (e *endpoint) Close()                                       {}
func (e *endpoint) SetOnCloseAction(func())                      {}
func (e *endpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *endpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// WritePackets is called by gVisor when it produces outbound IP packets.
// Packets are processed synchronously via the onEgress callback, which
// parses the packet, matches it against resources, and sends it through
// the L3 tunnel with proper per-flow authentication — matching zju-connect.
func (e *endpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range list.AsSlice() {
		var buf []byte
		for _, slice := range pkt.AsSlices() {
			buf = append(buf, slice...)
		}
		if len(buf) > 0 && e.onEgress != nil {
			e.onEgress(buf)
		}
	}
	return list.Len(), nil
}
