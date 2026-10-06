package server

import (
	"context"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/coreguard"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type guardSnapshot struct{ value coreguard.Status }

func (s guardSnapshot) Status() coreguard.Status { return s.value }

func TestCoreGuardStatusTransports(t *testing.T) {
	stale := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	srv := &NetworkServer{coreGuard: guardSnapshot{coreguard.Status{Mode: coreguard.ModeEnforce, FirewallDriver: "nftables", StaleSince: stale, Entries: []coreguard.Entry{{Container: "core-test", Role: incus.RolePostgres, IP: "192.0.2.5", ACLName: "guard-test", Attached: true, RulesApplied: 3, LastError: "previous pass failed"}}}}}
	want := &pb.CoreGuardStatus{Mode: "enforce", FirewallDriver: "nftables", StaleSince: stale.Format(time.RFC3339Nano), Entries: []*pb.CoreGuardEntry{{Container: "core-test", Role: string(incus.RolePostgres), Ip: "192.0.2.5", AclName: "guard-test", Attached: true, RulesApplied: true, LastError: "previous pass failed"}}}
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	pb.RegisterNetworkServiceServer(gs, srv)
	go gs.Serve(listener)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///buf", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pb.NewNetworkServiceClient(conn)
	admin := metadata.Pairs(auth.MDKeyUsername, "operator", auth.MDKeyRoles, auth.RoleAdmin)
	ctx := metadata.NewOutgoingContext(context.Background(), admin)
	got, err := client.GetCoreGuardStatus(ctx, &pb.GetCoreGuardStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("gRPC: got %v, want %v", got, want)
	}
	mux := runtime.NewServeMux(runtime.WithMetadata(func(context.Context, *http.Request) metadata.MD { return admin }))
	if err := pb.RegisterNetworkServiceHandlerClient(context.Background(), mux, client); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/core-guard", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("REST: %d %s", recorder.Code, recorder.Body.String())
	}
	rest := &pb.CoreGuardStatus{}
	if err := protojson.Unmarshal(recorder.Body.Bytes(), rest); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(rest, want) {
		t.Fatalf("REST: got %v, want %v", rest, want)
	}
	for _, tc := range []struct {
		name string
		md   metadata.MD
		code codes.Code
	}{
		{"anonymous", nil, codes.Unauthenticated},
		{"unscoped tenant", metadata.Pairs(auth.MDKeyUsername, "tenant", auth.MDKeyRoles, "user"), codes.PermissionDenied},
		{"wrong scope", metadata.Pairs(auth.MDKeyUsername, "tenant", auth.MDKeyScopes, auth.ScopeRoutesRead), codes.PermissionDenied},
		{"read scope", metadata.Pairs(auth.MDKeyUsername, "reader", auth.MDKeyScopes, auth.ScopeNetworkPolicyRead), codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.GetCoreGuardStatus(metadata.NewOutgoingContext(context.Background(), tc.md), &pb.GetCoreGuardStatusRequest{})
			if status.Code(err) != tc.code {
				t.Fatalf("got %v, want %v", err, tc.code)
			}
		})
	}
}

func TestCoreGuardStatusOff(t *testing.T) {
	srv := &NetworkServer{}
	got, err := srv.GetCoreGuardStatus(auth.ContextWithTestSubject(context.Background(), "operator", auth.RoleAdmin), &pb.GetCoreGuardStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "off" || got.StaleSince != "" || len(got.Entries) != 0 {
		t.Fatalf("unexpected disabled status: %v", got)
	}
}
