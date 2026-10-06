package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCoreGuardStatusHTTP(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
		fail bool
	}{
		{"typed response", 200, `{"mode":"off","entries":[],"staleSince":""}`, false},
		{"permission denied", 403, `{"message":"requires role or scope"}`, true},
		{"malformed JSON", 200, `{`, true},
		{"wrong field type", 200, `{"entries":[{"attached":"yes"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/core-guard" || r.Header.Get("Authorization") != "Bearer token" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				w.WriteHeader(tc.code)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := NewHTTPClient(server.URL, "token")
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetCoreGuardStatus()
			if (err != nil) != tc.fail {
				t.Fatalf("status=%v err=%v", got, err)
			}
			if !tc.fail && (got.Mode != "off" || got.StaleSince != "") {
				t.Fatalf("unexpected response: %v", got)
			}
		})
	}
}
