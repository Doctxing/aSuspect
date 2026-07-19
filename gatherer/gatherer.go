// Package gatherer aggregates VPN session state from the aTrust server.
// It is protocol-agnostic — it only depends on AuthSession, not on any
// specific authentication method.
package gatherer

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"aSuspect/shared"
)

// InfoGatherer collects all VPN state from the aTrust server.
type InfoGatherer struct {
	Server  string
	Port    int
	Session *SessionStore
	Client  *http.Client // live client from auth; takes precedence over Session.CookieJar
}

// Gather fetches clientResource and builds SharedState.
// On success the session is saved back to disk (cookies may have been refreshed).
func (g *InfoGatherer) Gather() (*shared.SharedState, error) {
	resourceJSON, err := g.fetchClientResource()
	if err != nil {
		return nil, fmt.Errorf("fetch clientResource: %w", err)
	}

	connectionID := buildConnectionID(g.Session.DeviceID)

	state := shared.NewSharedState()
	state.SID = g.Session.SID
	state.DeviceID = g.Session.DeviceID
	state.SignKey = g.Session.SignKey
	state.ConnectionID = connectionID
	state.Username = g.Session.Username
	state.AntiMITM = g.Session.AntiMITM

	if err := g.parseResource(resourceJSON, state); err != nil {
		return nil, fmt.Errorf("parse clientResource: %w", err)
	}

	// Persist refreshed cookies.
	if jar, ok := g.Client.Jar.(*cookiejar.Jar); ok {
		g.Session.UpdateCookies(jar)
	}
	if err := g.Session.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	return state, nil
}

func (g *InfoGatherer) fetchClientResource() ([]byte, error) {
	q := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	host := g.Server
	if g.Port != 443 {
		host = fmt.Sprintf("%s:%d", g.Server, g.Port)
	}
	reqURL := fmt.Sprintf("https://%s/controller/v1/user/clientResource?%s", host, q.Encode())

	body, _ := json.Marshal(map[string]interface{}{
		"resourceType": map[string]interface{}{
			"sdpPolicy":       map[string]interface{}{},
			"appList":         map[string]interface{}{},
			"favoriteAppList": map[string]interface{}{},
			"featureCenter":   map[string]interface{}{},
			"uemSpace":        map[string]interface{}{"params": map[string]string{"action": "login"}},
		},
	})

	req, _ := http.NewRequest("POST", reqURL, strings.NewReader(string(body)))
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", g.Session.CSRFToken)
	req.Header.Set("x-sdp-traceid", shared.RandHex(8))

	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// ── JSON parsing ────────────────────────────────────────────────────────────

func (g *InfoGatherer) parseResource(raw []byte, state *shared.SharedState) error {
	var v clientResourceResponse
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}

	appListData := v.Data.AppList.Data
	for _, appGroup := range appListData.AppInfo {
		for _, app := range appGroup.Apps {
			parseAppResources(state, app)
		}
	}

	// Parse node groups.
	ngConf := appListData.Config.NodeGroupConf
	state.MajorGroupID = ngConf.MajorNodeGroup.ID
	for _, ng := range ngConf.NodeGroupList {
		var addrs []string
		for _, addressInfo := range ng.AddressInfo {
			if addressInfo.Type == "wan" {
				addr := addressInfo.Address
				addr = strings.Replace(addr, "{{sdpcHost}}", g.Server, 1)
				if !strings.Contains(addr, ":") {
					addr += ":441"
				}
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) > 0 {
			state.NodePool[ng.ID] = addrs
		}
	}

	// Parse DNS server.
	clientOpt := v.Data.SDPPolicy.Data.ClientOption
	if dns := clientOpt.DNSOption.FirstDNS; dns != "" {
		state.DNSServer = net.ParseIP(dns)
	}
	if state.DNSServer == nil && clientOpt.DNSOptionV2.FirstDNS != "" {
		state.DNSServer = net.ParseIP(clientOpt.DNSOptionV2.FirstDNS)
	}
	state.FinalizeResources()

	return nil
}

type clientResourceResponse struct {
	Data struct {
		AppList struct {
			Data clientResourceAppList `json:"data"`
		} `json:"appList"`
		SDPPolicy struct {
			Data struct {
				ClientOption struct {
					DNSOption struct {
						FirstDNS string `json:"firstDNS"`
					} `json:"dnsOption"`
					DNSOptionV2 struct {
						FirstDNS string `json:"firstDNS"`
					} `json:"dnsOptionV2"`
				} `json:"clientOption"`
			} `json:"data"`
		} `json:"sdpPolicy"`
	} `json:"data"`
}

type clientResourceAppList struct {
	AppInfo []struct {
		Apps []clientResourceApp `json:"apps"`
	} `json:"appInfo"`
	Config struct {
		NodeGroupConf struct {
			MajorNodeGroup struct {
				ID string `json:"id"`
			} `json:"majorNodeGroup"`
			NodeGroupList []struct {
				ID          string `json:"id"`
				AddressInfo []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addressInfo"`
			} `json:"nodeGroupList"`
		} `json:"nodeGroupConf"`
	} `json:"config"`
}

type clientResourceApp struct {
	ID                    string                  `json:"id"`
	NodeGroupID           string                  `json:"nodeGroupId"`
	AccessModel           string                  `json:"accessModel"`
	AccessAddress         string                  `json:"accessAddress"`
	AddrPretend           bool                    `json:"addrPretend"`
	AddressList           []clientResourceAddress `json:"addressList"`
	DomainList            []string                `json:"domainList"`
	WebRelativeDomainList []string                `json:"webRelativeDomainList"`
}

type clientResourceAddress struct {
	Protocol string   `json:"protocol"`
	Port     string   `json:"port"`
	Host     string   `json:"host"`
	IP       []string `json:"ip"`
}

type routeTemplate struct {
	protocol         shared.Protocol
	portMin, portMax int
}

func parseAppResources(state *shared.SharedState, app clientResourceApp) {
	if app.AccessModel != "" && app.AccessModel != "L3VPN" {
		return
	}

	templates := make([]routeTemplate, 0, len(app.AddressList))
	var exactIPs []net.IP
	for _, addr := range app.AddressList {
		template, ips, ok := parseResourceAddress(state, app, addr)
		if !ok {
			continue
		}
		templates = append(templates, template)
		exactIPs = append(exactIPs, ips...)
	}

	for _, rawDomain := range app.DomainList {
		if domain, ok := normalizeResourceDomain(rawDomain); ok {
			addDomainTemplates(state, domain, templates, app)
		}
	}

	entryDomains := parseEntryDomains(app.WebRelativeDomainList)
	if len(entryDomains) == 0 {
		entryDomains = parseEntryDomains([]string{app.AccessAddress})
	}
	for _, domain := range entryDomains {
		addDomainTemplates(state, domain, templates, app)
		if app.AddrPretend && len(state.StaticHosts[domain]) == 0 {
			for _, ip := range exactIPs {
				state.StaticHosts[domain] = append(state.StaticHosts[domain], copyIPv4(ip))
			}
		}
	}
}

func parseResourceAddress(
	state *shared.SharedState,
	app clientResourceApp,
	addr clientResourceAddress,
) (routeTemplate, []net.IP, bool) {
	if addr.Protocol != "tcp" && addr.Protocol != "udp" && addr.Protocol != "all" {
		return routeTemplate{}, nil, false
	}
	portMin, portMax, ok := parsePortRange(addr.Port)
	if !ok {
		return routeTemplate{}, nil, false
	}
	template := routeTemplate{shared.Protocol(addr.Protocol), portMin, portMax}
	host := strings.TrimSpace(addr.Host)

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addIPRange(state, ip4, ip4, template, app)
			return template, []net.IP{copyIPv4(ip4)}, true
		}
		return routeTemplate{}, nil, false
	}
	if _, ipNet, err := net.ParseCIDR(host); err == nil {
		addCIDR(state, ipNet, portMin, portMax, template.protocol, app.ID, app.NodeGroupID)
		return template, nil, true
	}
	if minIP, maxIP, ok := parseIPv4Range(host); ok {
		addIPRange(state, minIP, maxIP, template, app)
		return template, nil, true
	}

	domain, ok := normalizeResourceDomain(host)
	if !ok {
		return routeTemplate{}, nil, false
	}
	addDomainTemplates(state, domain, []routeTemplate{template}, app)

	staticIPs := make([]net.IP, 0, len(addr.IP))
	for _, rawIP := range addr.IP {
		ip := net.ParseIP(rawIP).To4()
		if ip == nil {
			continue
		}
		ip = copyIPv4(ip)
		state.StaticHosts[domain] = append(state.StaticHosts[domain], ip)
		addIPRange(state, ip, ip, template, app)
		staticIPs = append(staticIPs, ip)
	}
	return template, staticIPs, true
}

func addIPRange(state *shared.SharedState, minIP, maxIP net.IP, template routeTemplate, app clientResourceApp) {
	state.IPResources = append(state.IPResources, shared.IPResource{
		IPMin: copyIPv4(minIP), IPMax: copyIPv4(maxIP),
		PortMin: template.portMin, PortMax: template.portMax,
		Protocol: template.protocol, AppID: app.ID, NodeGroupID: app.NodeGroupID,
	})
}

func addDomainTemplates(state *shared.SharedState, domain string, templates []routeTemplate, app clientResourceApp) {
	for _, template := range templates {
		state.DomainResources[domain] = append(state.DomainResources[domain], shared.DomainResource{
			PortMin: template.portMin, PortMax: template.portMax,
			Protocol: template.protocol, AppID: app.ID, NodeGroupID: app.NodeGroupID,
		})
	}
}

func parseIPv4Range(host string) (net.IP, net.IP, bool) {
	parts := strings.Split(host, "-")
	if len(parts) != 2 {
		return nil, nil, false
	}
	minIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	maxIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if minIP == nil || maxIP == nil || bytesCompareIPv4(minIP, maxIP) > 0 {
		return nil, nil, false
	}
	return minIP, maxIP, true
}

func normalizeResourceDomain(raw string) (string, bool) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	wildcard := strings.HasPrefix(domain, "*.")
	if wildcard {
		domain = strings.TrimPrefix(domain, "*.")
	}
	if domain == "" || net.ParseIP(domain) != nil || !validDomain(domain) {
		return "", false
	}
	if wildcard {
		return "." + domain, true
	}
	return domain, true
}

func validDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
				return false
			}
		}
	}
	return true
}

func parseEntryDomains(values []string) []string {
	seen := make(map[string]struct{})
	var domains []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil {
			continue
		}
		domain, ok := normalizeResourceDomain(parsed.Hostname())
		if !ok {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains
}

func bytesCompareIPv4(a, b net.IP) int {
	for i := 0; i < net.IPv4len; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func copyIPv4(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func parsePortRange(spec string) (int, int, bool) {
	if parts := strings.SplitN(spec, "-", 2); len(parts) == 2 {
		min, minErr := strconv.Atoi(parts[0])
		max, maxErr := strconv.Atoi(parts[1])
		return min, max, minErr == nil && maxErr == nil && min >= 1 && max <= 65535 && min <= max
	}
	p, err := strconv.Atoi(spec)
	return p, p, err == nil && p >= 1 && p <= 65535
}

func buildConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}

func addCIDR(state *shared.SharedState, ipNet *net.IPNet, portMin, portMax int, proto shared.Protocol, appID, ngID string) {
	ipMin := ipNet.IP.To4()
	if ipMin == nil {
		return
	}
	ipMax := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ipMax[i] = ipMin[i] | ^ipNet.Mask[i]
	}
	state.IPResources = append(state.IPResources, shared.IPResource{
		IPMin: ipMin, IPMax: ipMax,
		PortMin: portMin, PortMax: portMax,
		Protocol:    proto,
		AppID:       appID,
		NodeGroupID: ngID,
	})
}
