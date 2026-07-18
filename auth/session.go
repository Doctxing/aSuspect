package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"

	"aSuspect/shared"
)

// ── Session ──────────────────────────────────────────────────────────────────

// Session holds all state during an authentication flow.
type Session struct {
	server string
	port   int
	client *http.Client

	// Server-provided auth parameters (from authConfig).
	csrfToken      string
	pubKey         string // RSA modulus, hex
	pubKeyExp      string // RSA exponent, decimal
	antiReplayRand string
	ticket         string

	// Client identity.
	deviceID string
	rid      string // base64(server)
	env      string // base64({"deviceId":"..."})

	// Cached auth config response for CAS/OAuth URLs.
	authConfigData *AuthConfigResponse
}

// AuthConfigResponse holds the parsed response from /passport/v1/public/authConfig.
type AuthConfigResponse struct {
	IsLogin            int          `json:"isLogin"`
	AuthServerInfoList []AuthMethod `json:"authServerInfoList"`
	FirstAuth          []string     `json:"firstAuth"`
	Security           struct {
		CSRFToken string `json:"csrfToken"`
	} `json:"security"`
	CSRFToken      string               `json:"csrfToken"` // flat (older servers)
	PubKey         string               `json:"pubKey"`
	PubKeyExp      string               `json:"pubKeyExp"`
	AntiReplayRand string               `json:"antiReplayRand"`
	Ticket         string               `json:"ticket"`
	AntiMITM       *shared.AntiMITMData `json:"antiMITMAttackData"`
}

func (d *AuthConfigResponse) csrf() string {
	if d.Security.CSRFToken != "" {
		return d.Security.CSRFToken
	}
	return d.CSRFToken
}

// Credentials is the result of a successful login, ready for persistence.
type Credentials struct {
	SID       string
	DeviceID  string
	SignKey   string
	Username  string
	CSRFToken string
	Cookies   []shared.CookieJSON
	AntiMITM  *shared.AntiMITMData
	Jar       *cookiejar.Jar // live cookie jar from the login session
}

// NewSession creates an auth session for the given server.
func NewSession(server string, port int, deviceID string) *Session {
	if deviceID == "" {
		deviceID = shared.RandHex(32)
	}

	jar, _ := cookiejar.New(nil)
	client := shared.NewHTTPClient(jar)

	rid := base64.StdEncoding.EncodeToString([]byte(server))
	env := base64.StdEncoding.EncodeToString([]byte(`{"deviceId":"` + deviceID + `"}`))

	return &Session{
		server:   server,
		port:     port,
		client:   client,
		deviceID: deviceID,
		rid:      rid,
		env:      env,
	}
}

// baseURL returns the server's base HTTPS URL.
func (s *Session) baseURL() string {
	return fmt.Sprintf("https://%s:%d", s.server, s.port)
}

func cookieURL(server string, port int) *url.URL {
	host := server
	if port != 443 {
		host = fmt.Sprintf("%s:%d", server, port)
	}
	return &url.URL{Scheme: "https", Host: host}
}

// ── Auth config ──────────────────────────────────────────────────────────────

// FetchAuthConfig calls /passport/v1/public/authConfig and populates session state.
func (s *Session) FetchAuthConfig() (*AuthConfigResponse, error) {
	q := sharedParams(url.Values{"needTicket": {"1"}})
	u := fmt.Sprintf("%s/passport/v1/public/authConfig?%s", s.baseURL(), q.Encode())

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", randSdpID())

	v, err := doAPI[AuthConfigResponse](s.client, req)
	if err != nil {
		return nil, fmt.Errorf("authConfig: %w", err)
	}
	if v.Code != 0 {
		return nil, fmt.Errorf("authConfig code=%d: %s", v.Code, v.Message)
	}

	d := &v.Data

	s.csrfToken = d.csrf()
	s.pubKey = d.PubKey
	s.pubKeyExp = d.PubKeyExp
	s.antiReplayRand = d.AntiReplayRand
	s.ticket = d.Ticket
	s.authConfigData = d

	return d, nil
}

// fetchAuthConfigMod calls authConfig with mod=1 to refresh CAS/OAuth state.
func (s *Session) fetchAuthConfigMod() error {
	q := sharedParams(url.Values{"mod": {"1"}})
	u := fmt.Sprintf("%s/passport/v1/public/authConfig?%s", s.baseURL(), q.Encode())

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", randSdpID())

	type responseData struct {
		AuthConfigResponse
		CSRFToken string `json:"csrfToken"`
	}
	v, err := doAPI[responseData](s.client, req)
	if err != nil {
		return fmt.Errorf("authConfigMod: %w", err)
	}
	if v.Code != 0 {
		return fmt.Errorf("code=%d: %s", v.Code, v.Message)
	}

	d := &v.Data
	s.csrfToken = d.csrf()
	if d.Ticket != "" {
		s.ticket = d.Ticket
	}
	s.authConfigData = &d.AuthConfigResponse
	return nil
}

// ── Report env ──────────────────────────────────────────────────────────────

// ReportEnv sends the device environment report.
func (s *Session) ReportEnv() error {
	data := map[string]interface{}{
		"ticket":   s.ticket,
		"deviceId": s.deviceID,
		"env": map[string]interface{}{
			"endpoint": map[string]interface{}{
				"device_id": s.deviceID,
				"device": map[string]string{
					"type": "browser",
				},
			},
		},
	}
	postBody, _ := json.Marshal(data)

	u := fmt.Sprintf("%s/controller/v1/public/reportEnv?%s", s.baseURL(), sharedParams(nil).Encode())
	req, _ := http.NewRequest("POST", u, strings.NewReader(string(postBody)))
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	v, err := doAPI[struct{}](s.client, req)
	if err != nil {
		return fmt.Errorf("reportEnv: %w", err)
	}
	if v.Code != 0 {
		return fmt.Errorf("reportEnv: code=%d %s", v.Code, v.Message)
	}
	return nil
}

// ── Auth check (secondary SMS) ───────────────────────────────────────────────

// AuthCheck returns an authId if secondary SMS auth is required.
func (s *Session) AuthCheck() (string, error) {
	u := fmt.Sprintf("%s/passport/v1/auth/authCheck?%s", s.baseURL(), sharedParams(nil).Encode())
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	type responseData struct {
		NextServiceList []struct {
			AuthID string `json:"authId"`
		} `json:"nextServiceList"`
	}
	v, err := doAPI[responseData](s.client, req)
	if err != nil {
		return "", err
	}
	if v.Code != 0 {
		return "", fmt.Errorf("authCheck: code=%d %s", v.Code, v.Message)
	}
	if len(v.Data.NextServiceList) > 0 {
		return v.Data.NextServiceList[0].AuthID, nil
	}
	return "", nil
}

// AuthSms triggers a secondary SMS to the user.
func (s *Session) AuthSms(authID string) error {
	q := sharedParams(url.Values{
		"action":       {"sendsms"},
		"isPrevEffect": {"0"},
		"taskId":       {""},
		"authId":       {authID},
	})
	u := fmt.Sprintf("%s/passport/v1/auth/sms?%s", s.baseURL(), q.Encode())
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	type responseData struct {
		Tips string `json:"tips"`
	}
	v, err := doAPI[responseData](s.client, req)
	if err != nil {
		return err
	}
	if v.Code != 0 && v.Code != 75500401 {
		return fmt.Errorf("send SMS: code=%d %s", v.Code, v.Message)
	}
	if v.Data.Tips != "" {
		log.Printf("SMS: %s", v.Data.Tips)
	}
	return nil
}

// SmsVerify verifies the secondary SMS code.
func (s *Session) SmsVerify(authID string) error {
	fmt.Print("Enter secondary SMS code: ")
	var code string
	fmt.Scanln(&code)

	body := map[string]interface{}{
		"isPrevEffect":      false,
		"code":              code,
		"skipSecondaryAuth": "0",
		"taskId":            "",
		"authId":            authID,
	}
	payload, _ := json.Marshal(body)

	q := sharedParams(url.Values{"action": {"checkcode"}})
	u := fmt.Sprintf("%s/passport/v1/auth/sms?%s", s.baseURL(), q.Encode())
	req, _ := http.NewRequest("POST", u, strings.NewReader(string(payload)))
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	v, err := doAPI[struct{}](s.client, req)
	if err != nil {
		return err
	}
	if v.Code != 0 {
		return fmt.Errorf("SMS verify failed: code=%d", v.Code)
	}
	return nil
}

// ── Online info ─────────────────────────────────────────────────────────────

// OnlineInfo returns the logged-in username.
func (s *Session) OnlineInfo() (string, error) {
	u := fmt.Sprintf("%s/passport/v1/user/onlineInfo?%s", s.baseURL(), sharedParams(nil).Encode())
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	type responseData struct {
		Username string `json:"username"`
	}
	v, err := doAPI[responseData](s.client, req)
	if err != nil {
		return "", err
	}
	if v.Code != 0 {
		return "", fmt.Errorf("onlineInfo: code=%d %s", v.Code, v.Message)
	}
	if v.Data.Username == "" {
		return "", fmt.Errorf("onlineInfo: empty username")
	}
	return v.Data.Username, nil
}

// ── Credential extraction ────────────────────────────────────────────────────

// antiMITM returns the anti-MITM data from auth config, if any.
func (s *Session) antiMITM() *shared.AntiMITMData {
	if s.authConfigData == nil {
		return nil
	}
	return s.authConfigData.AntiMITM
}

// Credentials extracts login result from the session cookie jar.
func (s *Session) Credentials() (*Credentials, error) {
	username, err := s.OnlineInfo()
	if err != nil {
		return nil, fmt.Errorf("onlineInfo: %w", err)
	}

	u := cookieURL(s.server, s.port)
	cookies := s.client.Jar.Cookies(u)

	var sid string
	out := make([]shared.CookieJSON, 0, len(cookies))
	for _, c := range cookies {
		if strings.EqualFold(c.Name, "sid") {
			sid = c.Value
		}
		out = append(out, shared.CookieJSON{
			Name:  c.Name,
			Value: c.Value,
		})
	}

	antiMITM := s.antiMITM()

	signKey := shared.RandHex(64)

	jar, ok := s.client.Jar.(*cookiejar.Jar)
	if !ok {
		return nil, fmt.Errorf("session cookie jar is not *cookiejar.Jar")
	}

	return &Credentials{
		SID:       sid,
		DeviceID:  s.deviceID,
		SignKey:   signKey,
		Username:  username,
		Cookies:   out,
		AntiMITM:  antiMITM,
		CSRFToken: s.csrfToken,
		Jar:       jar,
	}, nil
}

// ── Shared helpers ───────────────────────────────────────────────────────────

func sharedParams(extra url.Values) url.Values {
	v := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	for k, vals := range extra {
		for _, val := range vals {
			v.Set(k, val)
		}
	}
	return v
}

func randSdpID() string {
	return shared.RandHex(8)
}

// ── RSA helpers ──────────────────────────────────────────────────────────────

// EncryptPassword encrypts the password with the server's RSA public key.
func (s *Session) EncryptPassword(password string) (string, error) {
	N := new(big.Int)
	if _, ok := N.SetString(s.pubKey, 16); !ok || N.Sign() <= 0 {
		return "", fmt.Errorf("invalid RSA modulus")
	}

	E := 65537
	if s.pubKeyExp != "" {
		var err error
		E, err = strconv.Atoi(s.pubKeyExp)
		if err != nil || E < 2 {
			return "", fmt.Errorf("invalid RSA exponent %q", s.pubKeyExp)
		}
	}

	pub := &rsa.PublicKey{N: N, E: E}
	msg := []byte(password + "_" + s.antiReplayRand)
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt: %w", err)
	}
	return hex.EncodeToString(cipher), nil
}
