package shared

import (
	"crypto/tls"
	"net/http"
)

// NewHTTPClient returns a client with the existing aTrust transport settings.
func NewHTTPClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Jar: jar,
	}
}
