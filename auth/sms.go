package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"aSuspect/shared"
)

// SMSAuth logs in with phone + SMS verification code.
// Phone number is prompted interactively.
type SMSAuth struct{}

// Login performs the two-phase SMS authentication:
//
//  1. Send SMS code via /passport/v1/public/sendSms
//  2. Verify code via /passport/v1/auth/smsCheckCode
func (a SMSAuth) Login(s *Session) error {
	// Find the SMS auth domain from server config.
	domain := "local"
	if s.authConfigData != nil {
		for _, m := range s.authConfigData.AuthServerInfoList {
			if m.AuthType == "auth/smsCheckCode" && m.LoginDomain != "" {
				domain = m.LoginDomain
				break
			}
		}
	}

	var phone string
	fmt.Print("Phone number: ")
	fmt.Scanln(&phone)

	// Phase 1: Send SMS.
	if err := withCaptcha(s, func(captchaCode string) (int, error) {
		return s.sendSms(phone, domain, captchaCode)
	}); err != nil {
		return fmt.Errorf("send SMS: %w", err)
	}

	// Prompt user for code.
	fmt.Print("Enter SMS verification code: ")
	var code string
	fmt.Scanln(&code)

	// Phase 2: Verify code.
	return withCaptcha(s, func(captchaCode string) (int, error) {
		return s.smsCheckCode(code, phone, domain, captchaCode)
	})
}

// sendSms POSTs to /passport/v1/public/sendSms.
func (s *Session) sendSms(phone, loginDomain, graphCheckCode string) (int, error) {
	data := map[string]interface{}{
		"phone":          phone + "@" + loginDomain,
		"graphCheckCode": graphCheckCode,
	}
	payload, _ := json.Marshal(data)

	q := sharedParams(nil)
	u := fmt.Sprintf("%s/passport/v1/public/sendSms?%s", s.baseURL(), q.Encode())
	req, _ := http.NewRequest("POST", u, strings.NewReader(string(payload)))
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", randSdpID())

	type responseData struct {
		GraphCheckCodeEnable int `json:"graphCheckCodeEnable"`
	}
	v, err := doAPI[responseData](s.client, req)
	if err != nil {
		return 0, err
	}
	if v.Code != 0 {
		return 0, fmt.Errorf("sendSms: code=%d %s", v.Code, v.Message)
	}
	return v.Data.GraphCheckCodeEnable, nil
}

// smsCheckCode POSTs to /passport/v1/auth/smsCheckCode.
func (s *Session) smsCheckCode(code, phone, loginDomain, graphCheckCode string) (int, error) {
	data := map[string]string{
		"code":  code,
		"phone": phone + "@" + loginDomain,
	}
	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}
	payload, _ := json.Marshal(data)

	q := sharedParams(nil)
	u := fmt.Sprintf("%s/passport/v1/auth/smsCheckCode?%s", s.baseURL(), q.Encode())
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
		return 0, fmt.Errorf("smsCheckCode: code=%d %s", v.Code, v.Message)
	}

	if v.Data.Ticket != "" {
		s.ticket = v.Data.Ticket
	}
	return v.Data.GraphCheckCodeEnable, nil
}
