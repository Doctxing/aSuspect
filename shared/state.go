package shared

import (
	"net"
	"sync"
)

// ── Shared state ─────────────────────────────────────────────────────────────

// SharedState holds all VPN session data, shared across modules.
// Protected by RWMutex for hot-reload (node refresh).
type SharedState struct {
	SID          string
	DeviceID     string
	SignKey      string
	ConnectionID string
	Username     string

	VirtualIP net.IP

	IPResources     []IPResource
	DomainResources map[string]DomainResource // suffix → resource
	StaticHosts     map[string]net.IP         // domain → IP (server-pushed)

	DNSServer net.IP

	NodePool     map[string][]string // groupID → addresses, in server order
	MajorGroupID string

	// SPA anti-MITM data from authConfig.
	AntiMITM *AntiMITMData

	mu sync.RWMutex
}

// NewSharedState creates an empty SharedState.
func NewSharedState() *SharedState {
	return &SharedState{
		DomainResources: make(map[string]DomainResource),
		StaticHosts:     make(map[string]net.IP),
		NodePool:        make(map[string][]string),
	}
}

// FindIPResource returns the first IPResource matching the given IP, protocol, and port.
// Returns nil if no resource matches.
func (s *SharedState) FindIPResource(ip net.IP, proto Protocol, port int) *IPResource {
	for i := range s.IPResources {
		if s.IPResources[i].ContainsIP(ip) && s.IPResources[i].Matches(proto, port) {
			return &s.IPResources[i]
		}
	}
	return nil
}

// NodeCandidates returns node addresses for groupID in server order,
// falling back to the major group if the group has no nodes.
func (s *SharedState) NodeCandidates(groupID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nodes := s.NodePool[groupID]; len(nodes) > 0 {
		return append([]string(nil), nodes...)
	}
	if groupID != s.MajorGroupID {
		if nodes := s.NodePool[s.MajorGroupID]; len(nodes) > 0 {
			return append([]string(nil), nodes...)
		}
	}
	return nil
}

// Snapshot returns a shallow copy for read-heavy paths.
func (s *SharedState) Snapshot() SharedState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SharedState{
		SID: s.SID, DeviceID: s.DeviceID, SignKey: s.SignKey,
		ConnectionID: s.ConnectionID, Username: s.Username,
		VirtualIP:   copyIP(s.VirtualIP),
		IPResources: s.IPResources, DomainResources: s.DomainResources,
		StaticHosts: s.StaticHosts, DNSServer: copyIP(s.DNSServer),
		NodePool:     s.NodePool,
		MajorGroupID: s.MajorGroupID,
		AntiMITM:     s.AntiMITM,
	}
}
