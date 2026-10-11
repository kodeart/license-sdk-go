package license

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	licensev1 "github.com/kodeart/license-sdk-go/proto/license/v1"
)

// AgentClientConfig configures the node-local LicenseAgent client. Address is
// the only required field.
//
// The link to the agent is node-local and plaintext: the agent runs as a
// sidecar on the same host (or the same pod network) and never leaves it, so
// there is no network boundary to protect. If a deployment ever splits them,
// add TLS here the same way ClientConfig does for the license server.
type AgentClientConfig struct {
	// Address is the agent's gRPC endpoint, host:port (e.g. "license-agent:6101").
	Address string
	// ConnectTimeout bounds the initial dial (default: 3s).
	ConnectTimeout time.Duration
	// KeepaliveTime is the keepalive ping interval (default: 20s).
	KeepaliveTime time.Duration
}

// AgentClient is a LicenseAgent client. It streams the status the agent has
// cached on this node; a replica never talks to the license server directly.
type AgentClient struct {
	conn *grpc.ClientConn
	svc  licensev1.LicenseAgentClient
}

// NewAgentClient dials the agent's gRPC endpoint. The connection is lazy:
// Watch/Refresh surface an unreachable agent on first use.
func NewAgentClient(cfg AgentClientConfig) (*AgentClient, error) {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 3 * time.Second
	}
	if cfg.KeepaliveTime == 0 {
		cfg.KeepaliveTime = 20 * time.Second
	}
	conn, err := grpc.NewClient(cfg.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			PermitWithoutStream: true,
			Time:                cfg.KeepaliveTime,
			Timeout:             20 * time.Second,
		}),
	)
	if err != nil {
		return nil, err
	}
	return &AgentClient{conn: conn, svc: licensev1.NewLicenseAgentClient(conn)}, nil
}

// Close closes the underlying gRPC connection.
func (c *AgentClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// AgentStatusStream yields the agent's status: the current one immediately,
// then one message on every change, until the context is cancelled or the
// stream breaks.
type AgentStatusStream struct {
	stream licensev1.LicenseAgent_WatchClient
}

// Watch opens the status stream. Callers should Recv in a loop and re-open the
// stream (with backoff) when Recv returns an error.
func (c *AgentClient) Watch(ctx context.Context) (*AgentStatusStream, error) {
	stream, err := c.svc.Watch(ctx, &licensev1.WatchRequest{})
	if err != nil {
		return nil, err
	}
	return &AgentStatusStream{stream: stream}, nil
}

// Recv returns the next status on the stream.
func (s *AgentStatusStream) Recv() (AgentStatus, error) {
	msg, err := s.stream.Recv()
	if err != nil {
		return AgentStatus{}, err
	}
	return AgentStatusFromProto(msg), nil
}

// Refresh asks the agent to re-sync with the license server now and returns the
// resulting status.
func (c *AgentClient) Refresh(ctx context.Context) (AgentStatus, error) {
	msg, err := c.svc.Refresh(ctx, &licensev1.RefreshRequest{})
	if err != nil {
		return AgentStatus{}, err
	}
	return AgentStatusFromProto(msg), nil
}

// AgentStatusFromProto converts the wire form to the shared struct.
func AgentStatusFromProto(m *licensev1.AgentStatus) AgentStatus {
	if m == nil {
		return AgentStatus{}
	}
	return AgentStatus{
		DeploymentID: m.GetDeploymentId(),
		HasLicense:   m.GetHasLicense(),
		Valid:        m.GetValid(),
		Message:      m.GetMessage(),
		Reason:       m.GetReason(),
		RawToken:     m.GetRawToken(),
		LeaseToken:   m.GetLeaseToken(),
	}
}

// ToProto converts the shared struct to its wire form. The agent serves it.
func (s AgentStatus) ToProto() *licensev1.AgentStatus {
	return &licensev1.AgentStatus{
		DeploymentId: s.DeploymentID,
		HasLicense:   s.HasLicense,
		Valid:        s.Valid,
		Message:      s.Message,
		Reason:       s.Reason,
		RawToken:     s.RawToken,
		LeaseToken:   s.LeaseToken,
	}
}
