package gatherer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"

	"aSuspect/shared"
)

const sessionFileName = "aSuspect_session.json"

type SessionStore struct {
	SID       string               `json:"sid"`
	DeviceID  string               `json:"device_id"`
	SignKey   string               `json:"sign_key"`
	Username  string               `json:"username"`
	Server    string               `json:"server"`
	Cookies   []shared.CookieJSON  `json:"cookies"`
	AntiMITM  *shared.AntiMITMData `json:"anti_mitm,omitempty"`
	CSRFToken string               `json:"csrf_token,omitempty"`
	LiveJar   *cookiejar.Jar       `json:"-"`
}

func (s *SessionStore) LiveClient() *http.Client {
	return shared.NewHTTPClient(s.LiveJar)
}

func (s *SessionStore) NewClient() (*http.Client, error) {
	jar, err := s.CookieJar()
	if err != nil {
		return nil, err
	}
	return shared.NewHTTPClient(jar), nil
}

func (s *SessionStore) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := os.WriteFile(sessionFileName, data, 0600); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return nil
}

func LoadSession() (*SessionStore, error) {
	path := filepath.Join(workingDir(), sessionFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no session file (%s): run with -auth first, or place %s manually", path, sessionFileName)
	}

	var s SessionStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse session: %w", err)
	}
	if s.SID == "" {
		return nil, fmt.Errorf("session file is missing SID")
	}
	return &s, nil
}

func (s *SessionStore) serverURL() *url.URL {
	host := s.Server
	return &url.URL{Scheme: "https", Host: host}
}

func (s *SessionStore) CookieJar() (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	u := s.serverURL()
	for _, c := range s.Cookies {
		jar.SetCookies(u, []*http.Cookie{{
			Name:  c.Name,
			Value: c.Value,
		}})
	}
	return jar, nil
}

func (s *SessionStore) UpdateCookies(jar *cookiejar.Jar) {
	cookies := jar.Cookies(s.serverURL())
	s.Cookies = make([]shared.CookieJSON, len(cookies))
	for i, c := range cookies {
		s.Cookies[i] = shared.CookieJSON{
			Name: c.Name, Value: c.Value,
		}
	}
}

func workingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}
