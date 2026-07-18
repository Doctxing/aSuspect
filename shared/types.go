package shared

import (
	"net"
)

// UserAgent mimics the official aTrust client.
const UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.5.16.20 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"

// ── Protocol types ───────────────────────────────────────────────────────────

// Protocol is the IP protocol filter in resource policies.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoAll  Protocol = "all"
	ProtoICMP Protocol = "icmp"
)

// IPResource is an IP-range resource policy from aTrust.
type IPResource struct {
	IPMin       net.IP
	IPMax       net.IP
	PortMin     int
	PortMax     int
	Protocol    Protocol
	AppID       string
	NodeGroupID string
}

// ContainsIP checks whether ip falls within this resource's IP range.
func (r IPResource) ContainsIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return bytesCompare(ip4, r.IPMin) >= 0 && bytesCompare(ip4, r.IPMax) <= 0
}

// Matches checks whether (protocol, port) is allowed by this resource.
func (r IPResource) Matches(proto Protocol, port int) bool {
	if r.Protocol != proto && r.Protocol != ProtoAll {
		return false
	}
	return port >= r.PortMin && port <= r.PortMax
}

// DomainResource is a domain-suffix resource policy from aTrust.
type DomainResource struct {
	PortMin     int
	PortMax     int
	Protocol    Protocol
	AppID       string
	NodeGroupID string
}

// Matches checks whether (protocol, port) is allowed by this resource.
func (r DomainResource) Matches(proto Protocol, port int) bool {
	if r.Protocol != proto && r.Protocol != ProtoAll {
		return false
	}
	return port >= r.PortMin && port <= r.PortMax
}

// ── Cookie JSON ──────────────────────────────────────────────────────────────

// CookieJSON is used for serializing HTTP cookies.
type CookieJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ── Anti-MITM ────────────────────────────────────────────────────────────────

// AntiMITMData holds SPA knocking parameters from authConfig.
type AntiMITMData struct {
	Enable             int    `json:"enable"`
	AntiMITMRequest    bool   `json:"antiMITMRequest"`
	Challenge          string `json:"challenge"`
	EncryptedChallenge string `json:"encryptedChallenge"`
	DevicePubKeyMod    string `json:"devicePubKeyMod"`
	DevicePubKeyExp    string `json:"devicePubKeyExp"`
}

// NeedsSPA reports whether SPA knocking is required.
func (a *AntiMITMData) NeedsSPA() bool {
	return a != nil && a.Enable == 1 && a.AntiMITMRequest
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func bytesCompare(a, b net.IP) int {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return 0
	}
	for i := 0; i < 4; i++ {
		if a4[i] < b4[i] {
			return -1
		}
		if a4[i] > b4[i] {
			return 1
		}
	}
	return 0
}

func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
