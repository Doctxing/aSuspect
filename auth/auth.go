// Package auth — authentication for aTrust VPN.
//
//	Session       — stateful auth flow (session.go)
//	PasswordAuth  — password login (psw.go)
//	SMSAuth       — SMS verification login (sms.go)
package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"aSuspect/shared"
)

// AuthMethod describes a server-supported authentication method.
type AuthMethod struct {
	AuthType    string `json:"authType"`
	AuthName    string `json:"authName"`
	LoginDomain string `json:"loginDomain"`
	LoginURL    string `json:"loginUrl"`
}

// Authenticator performs a login step on a Session.
type Authenticator interface {
	Login(s *Session) error
}

// FetchAuthMethods queries the server for supported auth methods.
func FetchAuthMethods(server string, port int) ([]AuthMethod, error) {
	client := shared.NewHTTPClient(nil)

	q := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
		"needTicket": {"1"},
	}
	u := fmt.Sprintf("https://%s:%d/passport/v1/public/authConfig?%s", server, port, q.Encode())

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-sdp-rid", base64.StdEncoding.EncodeToString([]byte(server)))

	type responseData struct {
		AuthServerInfoList []AuthMethod `json:"authServerInfoList"`
	}
	v, err := doAPI[responseData](client, req)
	if err != nil {
		return nil, err
	}
	if v.Code != 0 {
		return nil, fmt.Errorf("server returned code=%d: %s", v.Code, v.Message)
	}
	return v.Data.AuthServerInfoList, nil
}

// Login orchestrates the full auth flow and returns credentials.
func Login(server string, port int, method Authenticator, deviceID string) (*Credentials, error) {
	s := NewSession(server, port, deviceID)

	// 1. Fetch auth config.
	cfg, err := s.FetchAuthConfig()
	if err != nil {
		return nil, fmt.Errorf("auth config: %w", err)
	}
	if cfg.IsLogin == 1 {
		// Already logged in via existing cookies.
		return s.Credentials()
	}

	// 2. Execute the login method.
	if err := method.Login(s); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	// 3. Report environment.
	if err := s.ReportEnv(); err != nil {
		return nil, fmt.Errorf("reportEnv: %w", err)
	}

	// 4. Check for secondary auth (SMS 2FA).
	authID, err := s.AuthCheck()
	if err != nil {
		return nil, fmt.Errorf("authCheck: %w", err)
	}
	if authID != "" {
		if err := s.AuthSms(authID); err != nil {
			return nil, fmt.Errorf("secondary SMS: %w", err)
		}
		if err := s.SmsVerify(authID); err != nil {
			return nil, fmt.Errorf("secondary SMS verify: %w", err)
		}
	}

	// 5. Extract credentials.
	return s.Credentials()
}
