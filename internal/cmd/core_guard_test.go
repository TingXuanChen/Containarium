package cmd

import (
	"bytes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCoreGuardStatusCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/core-guard" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"mode":"enforce","firewallDriver":"nftables","entries":[{"container":"core-test","attached":true,"rulesApplied":true}]}`))
	}))
	defer server.Close()
	oldAddr, oldToken, oldHTTP := serverAddr, authToken, httpMode
	defer func() {
		serverAddr, authToken, httpMode = oldAddr, oldToken, oldHTTP
		coreGuardStatusCmd.SetOut(nil)
		coreGuardStatusCmd.Flags().Set("json", "false")
	}()
	serverAddr, authToken, httpMode = server.URL, "test-token", true
	for _, jsonOut := range []bool{false, true} {
		var out bytes.Buffer
		coreGuardStatusCmd.SetOut(&out)
		coreGuardStatusCmd.Flags().Set("json", "false")
		if jsonOut {
			coreGuardStatusCmd.Flags().Set("json", "true")
		}
		if err := coreGuardStatusCmd.RunE(coreGuardStatusCmd, nil); err != nil {
			t.Fatal(err)
		}
		if jsonOut {
			got := &pb.CoreGuardStatus{}
			if err := protojson.Unmarshal(out.Bytes(), got); err != nil {
				t.Fatal(err)
			}
			if got.Mode != "enforce" || len(got.Entries) != 1 || !got.Entries[0].Attached {
				t.Fatalf("unexpected typed output: %v", got)
			}
		} else if !strings.Contains(out.String(), "Mode: enforce") || !strings.Contains(out.String(), "core-test") {
			t.Fatalf("unexpected output: %s", out.String())
		}
	}
}
