package mcp

import (
	"errors"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"net/http"
	"net/http/httptest"
	"testing"
)

type guardAPI struct {
	API
	calls int
	err   error
}

func (s *guardAPI) GetCoreGuardStatus() (*pb.CoreGuardStatus, error) {
	s.calls++
	return &pb.CoreGuardStatus{Mode: "off"}, s.err
}

func TestCoreGuardStatusTool(t *testing.T) {
	s := &Server{}
	s.registerTools()
	var tool *Tool
	for i := range s.tools {
		if s.tools[i].Name == "core_guard_status" {
			tool = &s.tools[i]
		}
	}
	if tool == nil || tool.RequiredScope != auth.ScopeNetworkPolicyRead {
		t.Fatal("missing tool or wrong scope")
	}
	stub := &guardAPI{}
	data, err := tool.Handler(stub, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := &pb.CoreGuardStatus{}
	if err := protojson.Unmarshal([]byte(data), got); err != nil {
		t.Fatal(err)
	}
	if stub.calls != 1 || got.Mode != "off" {
		t.Fatalf("calls=%d status=%v", stub.calls, got)
	}
	stub.err = errors.New("unavailable")
	if _, err := tool.Handler(stub, nil); !errors.Is(err, stub.err) {
		t.Fatalf("error lost: %v", err)
	}
}

func TestCoreGuardStatusSharedClient(t *testing.T) {
	t.Setenv("CONTAINARIUM_MCP_ALLOW_INSECURE", "true")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/core-guard" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		w.Write([]byte(`{"mode":"enforce","firewallDriver":"nftables","entries":[{"container":"core-test","attached":true}]}`))
	}))
	defer server.Close()
	data, err := handleCoreGuardStatus(NewClient(server.URL, "test-token"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := &pb.CoreGuardStatus{}
	if err := protojson.Unmarshal([]byte(data), got); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got.Mode != "enforce" || got.FirewallDriver != "nftables" || len(got.Entries) != 1 || !got.Entries[0].Attached {
		t.Fatalf("calls=%d status=%v", calls, got)
	}
}
