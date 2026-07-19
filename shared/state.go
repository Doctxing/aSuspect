package shared

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
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
	DomainResources map[string][]DomainResource // exact domain or leading-dot wildcard → policies
	StaticHosts     map[string][]net.IP         // exact domain → server-pushed IPs
	ipIndex         *ipResourceIndex

	DNSServer net.IP

	NodePool     map[string][]string // groupID → addresses, in server order
	MajorGroupID string

	// SPA anti-MITM data from authConfig.
	AntiMITM *AntiMITMData

	mu sync.RWMutex
}

type ipResourceIndex struct {
	buckets [256][]IPResource
}

// NewSharedState creates an empty SharedState.
func NewSharedState() *SharedState {
	return &SharedState{
		DomainResources: make(map[string][]DomainResource),
		StaticHosts:     make(map[string][]net.IP),
		NodePool:        make(map[string][]string),
	}
}

// FinalizeResources deduplicates policies, safely merges compatible IP ranges,
// and builds the read-only /8 index used by the packet hot path.
func (s *SharedState) FinalizeResources() {
	s.IPResources = mergeIPResources(s.IPResources)
	for domain, policies := range s.DomainResources {
		s.DomainResources[domain] = dedupeDomainResources(policies)
	}
	for domain, ips := range s.StaticHosts {
		s.StaticHosts[domain] = dedupeIPs(ips)
	}

	index := &ipResourceIndex{}
	for _, resource := range s.IPResources {
		start := binary.BigEndian.Uint32(resource.IPMin.To4())
		end := binary.BigEndian.Uint32(resource.IPMax.To4())
		for bucket := start >> 24; bucket <= end>>24; bucket++ {
			bucketMin := bucket << 24
			bucketMax := bucketMin | 0x00ffffff
			part := resource
			part.IPMin = uint32ToIP(maxUint32(start, bucketMin))
			part.IPMax = uint32ToIP(minUint32(end, bucketMax))
			index.buckets[byte(bucket)] = append(index.buckets[byte(bucket)], part)
		}
	}
	for i := range index.buckets {
		sortIPResources(index.buckets[i])
	}
	s.ipIndex = index
}

// FindIPResource returns the most specific resource matching IP, protocol, and port.
func (s *SharedState) FindIPResource(ip net.IP, proto Protocol, port int) *IPResource {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	resources := s.IPResources
	if s.ipIndex != nil {
		resources = s.ipIndex.buckets[ip4[0]]
	}
	for i := range resources {
		if resources[i].ContainsIP(ip4) && resources[i].Matches(proto, port) {
			return &resources[i]
		}
	}
	return nil
}

// FindDomainResource checks an exact domain first, then explicit wildcard keys
// such as ".example.com", from the longest suffix to the shortest.
func (s *SharedState) FindDomainResource(domain string, proto Protocol, port int) *DomainResource {
	domain = normalizeDomain(domain)
	if resource := findDomainPolicy(s.DomainResources[domain], proto, port); resource != nil {
		return resource
	}
	for dot := strings.IndexByte(domain, '.'); dot >= 0; {
		if resource := findDomainPolicy(s.DomainResources[domain[dot:]], proto, port); resource != nil {
			return resource
		}
		next := strings.IndexByte(domain[dot+1:], '.')
		if next < 0 {
			break
		}
		dot += next + 1
	}
	return nil
}

// FindStaticHost returns the first exact server-pushed address for domain.
func (s *SharedState) FindStaticHost(domain string) net.IP {
	ips := s.StaticHosts[normalizeDomain(domain)]
	if len(ips) == 0 {
		return nil
	}
	return copyIP(ips[0])
}

// FindStaticHosts returns every exact server-pushed address for domain.
func (s *SharedState) FindStaticHosts(domain string) []net.IP {
	ips := s.StaticHosts[normalizeDomain(domain)]
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		result = append(result, copyIP(ip))
	}
	return result
}

// NodeCandidates returns a read-only node view in server order, falling back
// to the major group if the requested group has no nodes.
func (s *SharedState) NodeCandidates(groupID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nodes := s.NodePool[groupID]; len(nodes) > 0 {
		return nodes
	}
	if groupID != s.MajorGroupID {
		if nodes := s.NodePool[s.MajorGroupID]; len(nodes) > 0 {
			return nodes
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
		VirtualIP:   s.VirtualIP,
		IPResources: s.IPResources, DomainResources: s.DomainResources,
		StaticHosts: s.StaticHosts, DNSServer: s.DNSServer,
		ipIndex:      s.ipIndex,
		NodePool:     s.NodePool,
		MajorGroupID: s.MajorGroupID,
		AntiMITM:     s.AntiMITM,
	}
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func findDomainPolicy(policies []DomainResource, proto Protocol, port int) *DomainResource {
	var best *DomainResource
	for i := range policies {
		candidate := &policies[i]
		if !candidate.Matches(proto, port) {
			continue
		}
		if best == nil || domainPolicyLess(*candidate, *best) {
			best = candidate
		}
	}
	return best
}

func domainPolicyLess(a, b DomainResource) bool {
	if (a.Protocol == ProtoAll) != (b.Protocol == ProtoAll) {
		return a.Protocol != ProtoAll
	}
	return a.PortMax-a.PortMin < b.PortMax-b.PortMin
}

type ipResourceKey struct {
	portMin, portMax int
	protocol         Protocol
	appID, nodeID    string
}

func mergeIPResources(resources []IPResource) []IPResource {
	groups := make(map[ipResourceKey][]IPResource)
	for _, resource := range resources {
		if resource.IPMin.To4() == nil || resource.IPMax.To4() == nil {
			continue
		}
		key := ipResourceKey{
			portMin: resource.PortMin, portMax: resource.PortMax,
			protocol: resource.Protocol, appID: resource.AppID, nodeID: resource.NodeGroupID,
		}
		groups[key] = append(groups[key], resource)
	}

	merged := make([]IPResource, 0, len(resources))
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			return binary.BigEndian.Uint32(group[i].IPMin.To4()) < binary.BigEndian.Uint32(group[j].IPMin.To4())
		})
		groupMerged := make([]IPResource, 0, len(group))
		for _, resource := range group {
			start := binary.BigEndian.Uint32(resource.IPMin.To4())
			end := binary.BigEndian.Uint32(resource.IPMax.To4())
			if len(groupMerged) == 0 {
				groupMerged = append(groupMerged, resource)
				continue
			}
			last := &groupMerged[len(groupMerged)-1]
			lastEnd := binary.BigEndian.Uint32(last.IPMax.To4())
			if start <= lastEnd || (lastEnd != ^uint32(0) && start == lastEnd+1) {
				if end > lastEnd {
					last.IPMax = uint32ToIP(end)
				}
				continue
			}
			groupMerged = append(groupMerged, resource)
		}
		merged = append(merged, groupMerged...)
	}
	sortIPResources(merged)
	return merged
}

func sortIPResources(resources []IPResource) {
	sort.SliceStable(resources, func(i, j int) bool {
		iMin := binary.BigEndian.Uint32(resources[i].IPMin.To4())
		iMax := binary.BigEndian.Uint32(resources[i].IPMax.To4())
		jMin := binary.BigEndian.Uint32(resources[j].IPMin.To4())
		jMax := binary.BigEndian.Uint32(resources[j].IPMax.To4())
		if iMax-iMin != jMax-jMin {
			return iMax-iMin < jMax-jMin
		}
		if (resources[i].Protocol == ProtoAll) != (resources[j].Protocol == ProtoAll) {
			return resources[i].Protocol != ProtoAll
		}
		if resources[i].PortMax-resources[i].PortMin != resources[j].PortMax-resources[j].PortMin {
			return resources[i].PortMax-resources[i].PortMin < resources[j].PortMax-resources[j].PortMin
		}
		if iMin != jMin {
			return iMin < jMin
		}
		return resources[i].AppID < resources[j].AppID
	})
}

func dedupeDomainResources(resources []DomainResource) []DomainResource {
	type key struct {
		portMin, portMax int
		protocol         Protocol
		appID, nodeID    string
	}
	seen := make(map[key]struct{}, len(resources))
	result := make([]DomainResource, 0, len(resources))
	for _, resource := range resources {
		key := key{resource.PortMin, resource.PortMax, resource.Protocol, resource.AppID, resource.NodeGroupID}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, resource)
	}
	sort.SliceStable(result, func(i, j int) bool { return domainPolicyLess(result[i], result[j]) })
	return result
}

func dedupeIPs(ips []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(ips))
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		key := string(ip4)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, copyIP(ip4))
	}
	return result
}

func uint32ToIP(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
