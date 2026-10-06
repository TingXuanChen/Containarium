package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// FetchCoreGuardStatus is the shared typed REST operation for CLI and MCP.
// The caller supplies its transport and current token, preserving TLS policy
// and token rotation.
func FetchCoreGuardStatus(ctx context.Context, transport *http.Client, baseURL, token string) (*pb.CoreGuardStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/v1/core-guard", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := transport.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get core guard status: %w", err)
	}
	defer drainClose(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read core guard status: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, httpErr("get core guard status", resp.StatusCode, body)
	}
	out := &pb.CoreGuardStatus{}
	if err := protojson.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("decode core guard status: %w", err)
	}
	return out, nil
}

func (c *HTTPClient) GetCoreGuardStatus() (*pb.CoreGuardStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return FetchCoreGuardStatus(ctx, c.httpClient, c.baseURL, c.token)
}

func (c *GRPCClient) GetCoreGuardStatus() (*pb.CoreGuardStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.networkClient.GetCoreGuardStatus(ctx, &pb.GetCoreGuardStatusRequest{})
}
