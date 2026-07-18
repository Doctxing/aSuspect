package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type apiResponse[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

// doAPI preserves request construction and only centralizes response handling.
func doAPI[T any](client *http.Client, req *http.Request) (apiResponse[T], error) {
	var result apiResponse[T]
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("read response: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}
