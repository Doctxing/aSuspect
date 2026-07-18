package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"

	fakeproxy "github.com/doctxing/fakeProxy/core"

	"aSuspect/shared"
)

// RedirectAuth handles redirect-based SSO login (CAS, OAuth2, httpsOauth2).
type RedirectAuth struct{}

func (a RedirectAuth) Login(s *Session) error {
	loginURL, err := s.resolveRedirectAuth()
	if err != nil {
		return err
	}

	callbackURL, err := s.interactiveLogin(loginURL)
	if err != nil {
		return fmt.Errorf("interactive login: %w", err)
	}

	if err := s.completeRedirectAuth(callbackURL); err != nil {
		return fmt.Errorf("complete auth: %w", err)
	}

	if err := s.fetchAuthConfigMod(); err != nil {
		return fmt.Errorf("authConfigMod: %w", err)
	}

	return nil
}

func (s *Session) resolveRedirectAuth() (string, error) {
	if s.authConfigData == nil {
		return "", fmt.Errorf("no auth config data")
	}

	if len(s.authConfigData.FirstAuth) > 0 {
		return s.resolveURL(s.authConfigData.FirstAuth[0]), nil
	}

	for _, m := range s.authConfigData.AuthServerInfoList {
		if m.LoginURL != "" {
			return s.resolveURL(m.LoginURL), nil
		}
	}

	return "", fmt.Errorf("no redirect-based auth method found")
}

func (s *Session) resolveURL(raw string) string {
	if strings.HasPrefix(raw, "/") {
		return fmt.Sprintf("https://%s:%d%s", s.server, s.port, raw)
	}
	return raw
}

func (s *Session) interactiveLogin(loginURL string) (string, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	callbackCh := make(chan string, 1)

	proxy, err := fakeproxy.New(fakeproxy.Config{
		ResponseHook: func(fp *fakeproxy.Server, ev fakeproxy.ResponseEvent) bool {
			loc := ev.ResponseHeader.Get("Location")
			if loc == "" {
				return true
			}
			u, err := url.Parse(loc)
			if err != nil {
				return true
			}
			q := u.Query()
			if q.Get("ticket") == "" && q.Get("code") == "" {
				return true
			}
			callback := fmt.Sprintf("https://%s:%d%s?%s", s.server, s.port, u.Path, u.RawQuery)
			select {
			case callbackCh <- callback:
			default:
			}
			go fp.Close()
			return false
		},
	})
	if err != nil {
		return "", fmt.Errorf("create proxy: %w", err)
	}

	result, err := proxy.Start(ctx, loginURL)
	if err != nil {
		return "", fmt.Errorf("start proxy: %w", err)
	}

	fmt.Printf("\nOpen this URL in your browser:\n  %s\n\nWaiting for login...\n", result.EntryURL)

	select {
	case callback := <-callbackCh:
		return callback, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (s *Session) completeRedirectAuth(callbackURL string) error {
	originalCheckRedirect := s.client.CheckRedirect
	s.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { s.client.CheckRedirect = originalCheckRedirect }()

	req, err := http.NewRequest("GET", callbackURL, nil)
	if err != nil {
		return fmt.Errorf("create callback request: %w", err)
	}
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", randSdpID())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("read callback response: %w", err)
	}

	if resp.StatusCode != http.StatusFound {
		return fmt.Errorf("expected 302, got %d", resp.StatusCode)
	}

	ticket, err := parsePortalTicket(resp.Header.Get("Location"))
	if err != nil {
		return err
	}

	s.ticket = ticket
	return nil
}

func parsePortalTicket(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse location: %w", err)
	}

	data := u.Query().Get("data")
	if data == "" {
		return "", fmt.Errorf("redirect location has no data parameter")
	}

	var v struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		return "", fmt.Errorf("parse json: %w", err)
	}
	if v.Ticket == "" {
		return "", fmt.Errorf("redirect data contains an empty ticket")
	}

	return v.Ticket, nil
}
