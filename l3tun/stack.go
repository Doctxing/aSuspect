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
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/noisysockets/netstack/pkg/waiter"
)

const (
	nicID     tcpip.NICID = 1
	gvisorMTU uint32      = 1400
)

// gvisorStack wraps gVisor's userspace TCP/IP stack.
type gvisorStack struct {
	gs       *stack.Stack
	endpoint *endpoint
	flows    sync.Map

	// OnEgress is called synchronously from gVisor's WritePackets for each
	// outbound raw IPv4 packet. Set by the L3 Runtime at initialization.
	OnEgress func([]byte) error
}

// Stack is the L3 userspace network stack surface needed by upper layers.
type Stack interface {
	DialTCP(addr *net.TCPAddr, appID, nodeGroupID string) (net.Conn, error)
	DialUDP(laddr, raddr *net.UDPAddr) (net.Conn, error)
}

type flowRoute struct {
	appID, nodeGroupID string
}

type flowRouteKey struct {
	proto            uint8
	srcPort, dstPort uint16
	dstIP            [4]byte
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

// DialTCP binds the route before Connect emits the SYN, preserving the AppID
// selected from the original SOCKS domain for L3 per-flow authentication.
func (s *gvisorStack) DialTCP(addr *net.TCPAddr, appID, nodeGroupID string) (net.Conn, error) {
	remote := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4Slice(addr.IP.To4()),
		Port: uint16(addr.Port),
	}

	var wq waiter.Queue
	ep, tcpErr := s.gs.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}
	if tcpErr = ep.Bind(tcpip.FullAddress{NIC: nicID}); tcpErr != nil {
		ep.Close()
		return nil, fmt.Errorf("bind L3 TCP endpoint: %s", tcpErr)
	}
	local, tcpErr := ep.GetLocalAddress()
	if tcpErr != nil {
		ep.Close()
		return nil, fmt.Errorf("get L3 TCP address: %s", tcpErr)
	}

	key, ok := makeFlowRouteKey(6, local.Port, addr.IP, uint16(addr.Port))
	if !ok {
		ep.Close()
		return nil, fmt.Errorf("L3 TCP requires IPv4 destination: %s", addr.IP)
	}
	s.flows.Store(key, flowRoute{appID: appID, nodeGroupID: nodeGroupID})
	cleanup := func() { s.flows.Delete(key) }

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	tcpErr = ep.Connect(remote)
	if _, started := tcpErr.(*tcpip.ErrConnectStarted); started {
		<-notifyCh
		tcpErr = ep.LastError()
	}
	if tcpErr != nil {
		cleanup()
		ep.Close()
		return nil, &net.OpError{Op: "connect", Net: "tcp", Addr: addr, Err: errors.New(tcpErr.String())}
	}

	return &routedTCPConn{TCPConn: gonet.NewTCPConn(&wq, ep), cleanup: cleanup}, nil
}

type routedTCPConn struct {
	*gonet.TCPConn
	cleanup func()
	once    sync.Once
}

func (c *routedTCPConn) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(c.cleanup)
	return err
}

func (s *gvisorStack) findFlowRoute(packet parsedPacket) (flowRoute, bool) {
	key, ok := makeFlowRouteKey(packet.Proto, packet.SrcPort, packet.DstIP, packet.DstPort)
	if !ok {
		return flowRoute{}, false
	}
	value, ok := s.flows.Load(key)
	if !ok {
		return flowRoute{}, false
	}
	return value.(flowRoute), true
}

func makeFlowRouteKey(proto uint8, srcPort uint16, dstIP net.IP, dstPort uint16) (flowRouteKey, bool) {
	ip4 := dstIP.To4()
	if ip4 == nil {
		return flowRouteKey{}, false
	}
	return flowRouteKey{
		proto: proto, srcPort: srcPort, dstPort: dstPort,
		dstIP: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]},
	}, true
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
