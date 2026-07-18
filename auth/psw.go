package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"aSuspect/shared"
)

// PasswordAuth logs in with username and password.
// Credentials are prompted interactively.
type PasswordAuth struct{}

// Login prompts for credentials and performs the password auth step.
func (a PasswordAuth) Login(s *Session) error {
	// Find the password auth domain from server config.
	domain := "local"
	if s.authConfigData != nil {
		for _, m := range s.authConfigData.AuthServerInfoList {
			if m.AuthType == "auth/psw" && m.LoginDomain != "" {
				domain = m.LoginDomain
				break
			}
		}
	}

	var username, password string
	fmt.Print("Username: ")
	fmt.Scanln(&username)
	fmt.Print("Password: ")
	fmt.Scanln(&password)

	return withCaptcha(s, func(captchaCode string) (int, error) {
		return s.loginPsw(username, password, domain, captchaCode)
	})
}

// loginPsw POSTs encrypted credentials to /passport/v1/auth/psw.
func (s *Session) loginPsw(username, password, loginDomain, graphCheckCode string) (int, error) {
	encrypted, err := s.EncryptPassword(password)
	if err != nil {
		return 0, err
	}

	data := map[string]interface{}{
		"username":    username + "@" + loginDomain,
		"password":    encrypted,
		"rememberPwd": "0",
	}
	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}

	payload, _ := json.Marshal(data)

	q := sharedParams(nil)
	u := fmt.Sprintf("%s/passport/v1/auth/psw?%s", s.baseURL(), q.Encode())
	req, _ := http.NewRequest("POST", u, strings.NewReader(string(payload)))
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", randSdpID())

	type responseData struct {
		Ticket               string `json:"ticket"`
		GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
	}
	v, err := doAPI[responseData](s.client, req)
	if err != nil {
		return 0, err
	}
	if v.Code != 0 {
		return 0, fmt.Errorf("password login: code=%d %s", v.Code, v.Message)
	}

	if v.Data.Ticket != "" {
		s.ticket = v.Data.Ticket
	}
	return v.Data.GraphCheckCodeEnable, nil
}

// ── Captcha ──────────────────────────────────────────────────────────────────

// withCaptcha handles the captcha retry loop for a login operation.
func withCaptcha(s *Session, process func(captchaCode string) (int, error)) error {
	graphCheckCodeEnable, err := process("")
	if err != nil {
		return err
	}

	for attempt := 1; graphCheckCodeEnable == 1 && attempt <= 5; attempt++ {
		fmt.Printf("\nCaptcha required (attempt %d/5)\n", attempt)

		// Fetch captcha image.
		imgData, err := s.fetchCaptcha()
		if err != nil {
			return fmt.Errorf("fetch captcha: %w", err)
		}

		// Refresh auth config (server may have rotated CSRF/keys).
		if _, err := s.FetchAuthConfig(); err != nil {
			return fmt.Errorf("refresh auth config: %w", err)
		}

		// Save image.
		imgPath := fmt.Sprintf("captcha_%d.jpg", attempt)
		if err := os.WriteFile(imgPath, imgData, 0644); err != nil {
			return fmt.Errorf("save captcha: %w", err)
		}
		fmt.Printf("Captcha saved to %s\n", imgPath)

		// Prompt user.
		var rawInput string
		fmt.Print("Enter captcha JSON (coordinates format): ")
		fmt.Scanln(&rawInput)

		captchaCode, err := canonicalCaptcha(rawInput, imgData)
		if err != nil {
			return fmt.Errorf("captcha input: %w", err)
		}

		graphCheckCodeEnable, err = process(captchaCode)
		if err != nil {
			return err
		}

		if graphCheckCodeEnable == 0 {
			return nil
		}
		fmt.Printf("Captcha verification failed, retrying...\n")
	}

	if graphCheckCodeEnable != 0 {
		return fmt.Errorf("captcha verification failed after 5 attempts")
	}
	return nil
}

func (s *Session) fetchCaptcha() ([]byte, error) {
	params := sharedParams(url.Values{
		"rnd": {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	})
	u := fmt.Sprintf("%s/passport/v1/public/checkCode?%s", s.baseURL(), params.Encode())
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("create captcha request: %w", err)
	}
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

type captchaPayload struct {
	Coordinates [][]int `json:"coordinates"`
	Height      int     `json:"height"`
	Width       int     `json:"width"`
}

func canonicalCaptcha(rawInput string, imgData []byte) (string, error) {
	rawInput = strings.TrimSpace(rawInput)

	var payload captchaPayload
	if err := json.Unmarshal([]byte(rawInput), &payload); err == nil && len(payload.Coordinates) > 0 {
		if payload.Width <= 0 || payload.Height <= 0 {
			return "", fmt.Errorf("captcha dimensions must be positive")
		}
		return marshalCaptcha(payload, imgData)
	}

	var points []struct {
		X *int `json:"x"`
		Y *int `json:"y"`
	}
	if err := json.Unmarshal([]byte(rawInput), &points); err == nil && len(points) > 0 {
		payload.Coordinates = make([][]int, len(points))
		for i, point := range points {
			if point.X == nil || point.Y == nil {
				return "", fmt.Errorf("captcha point %d requires x and y", i)
			}
			payload.Coordinates[i] = []int{*point.X, *point.Y}
		}
		return marshalCaptcha(payload, imgData)
	}

	var coordinates [][]int
	if err := json.Unmarshal([]byte(rawInput), &coordinates); err == nil && len(coordinates) > 0 {
		payload.Coordinates = coordinates
		return marshalCaptcha(payload, imgData)
	}

	return "", fmt.Errorf("unrecognized captcha format: %s", rawInput)
}

func marshalCaptcha(payload captchaPayload, imgData []byte) (string, error) {
	for _, pair := range payload.Coordinates {
		if len(pair) != 2 || pair[0] < 0 || pair[1] < 0 {
			return "", fmt.Errorf("captcha coordinates must be non-negative [x,y] pairs")
		}
	}
	if payload.Width == 0 || payload.Height == 0 {
		w, h, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("captcha image: %w", err)
		}
		payload.Width, payload.Height = w, h
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode captcha: %w", err)
	}
	return string(b), nil
}

// decodeImageSize returns the width and height of an image (JPEG, PNG, GIF).
func decodeImageSize(imgData []byte) (int, int, error) {
	if len(imgData) == 0 {
		return 0, 0, fmt.Errorf("empty image data")
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(imgData))
	if err != nil {
		return 0, 0, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return 0, 0, fmt.Errorf("invalid image dimensions: %dx%d", cfg.Width, cfg.Height)
	}
	return cfg.Width, cfg.Height, nil
}
