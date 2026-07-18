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
			for _, addr := range app.AddressList {
				proto := addr.Protocol
				if proto != "tcp" && proto != "udp" && proto != "all" {
					continue
				}
				portMin, portMax, ok := parsePortRange(addr.Port)
				if !ok {
					continue
				}
				host := addr.Host

				if ip := net.ParseIP(host); ip != nil {
					if ip.To4() != nil {
						state.IPResources = append(state.IPResources, shared.IPResource{
							IPMin: ip, IPMax: ip,
							PortMin: portMin, PortMax: portMax,
							Protocol:    shared.Protocol(proto),
							AppID:       app.ID,
							NodeGroupID: app.NodeGroupID,
						})
					}
				} else if strings.Contains(host, "/") {
					_, ipNet, err := net.ParseCIDR(host)
					if err == nil {
						addCIDR(state, ipNet, portMin, portMax, shared.Protocol(proto), app.ID, app.NodeGroupID)
					}
				} else if strings.Contains(host, "-") {
					parts := strings.SplitN(host, "-", 2)
					minIP := net.ParseIP(parts[0])
					maxIP := net.ParseIP(parts[1])
					if minIP != nil && maxIP != nil && minIP.To4() != nil && maxIP.To4() != nil {
						state.IPResources = append(state.IPResources, shared.IPResource{
							IPMin: minIP, IPMax: maxIP,
							PortMin: portMin, PortMax: portMax,
							Protocol:    shared.Protocol(proto),
							AppID:       app.ID,
							NodeGroupID: app.NodeGroupID,
						})
					}
				} else {
					// Domain suffix.
					suffix := strings.ReplaceAll(host, "*", "")
					state.DomainResources[suffix] = shared.DomainResource{
						PortMin: portMin, PortMax: portMax,
						Protocol:    shared.Protocol(proto),
						AppID:       app.ID,
						NodeGroupID: app.NodeGroupID,
					}
					for _, ipStr := range addr.IP {
						if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
							state.StaticHosts[suffix] = ip
							break
						}
					}
				}
			}
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
		Apps []struct {
			ID          string `json:"id"`
			NodeGroupID string `json:"nodeGroupId"`
			AddressList []struct {
				Protocol string   `json:"protocol"`
				Port     string   `json:"port"`
				Host     string   `json:"host"`
				IP       []string `json:"IP"`
			} `json:"addressList"`
		} `json:"apps"`
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

// ── Helpers ──────────────────────────────────────────────────────────────────

func parsePortRange(spec string) (int, int, bool) {
	if parts := strings.SplitN(spec, "-", 2); len(parts) == 2 {
		min, _ := strconv.Atoi(parts[0])
		max, _ := strconv.Atoi(parts[1])
		return min, max, true
	}
	p, err := strconv.Atoi(spec)
	return p, p, err == nil
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
