package license

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	licensev1 "github.com/kodeart/license-sdk-go/proto/license/v1"
)

const deploymentAPIKeyHeader = "x-deployment-api-key"

// ClientConfig configures the LicenseService client.
//
// GrpcAddress is the only required field. When TLS is used, ServerName
// overrides the SNI/authority (e.g. "license.kodeart.com"); set Insecure for
// plaintext/dev use.
type ClientConfig struct {
	GrpcAddress    string        `env:"LICENSE_GRPC_ADDRESS,required"`
	ConnectTimeout time.Duration // gRPC dial timeout (default: 3s)
	KeepaliveTime  time.Duration // keepalive ping interval (default: 20s)

	// ServerName overrides the TLS SNI + gRPC authority when pointing at a
	// load balancer or proxy (Traefik) fronting the gRPC endpoint.
	ServerName string `env:"LICENSE_SERVER_NAME" envDefault:""`
	// Insecure dials with plaintext (no TLS). Dev/staging only.
	Insecure bool `env:"LICENSE_INSECURE" envDefault:"false"`

	// DeploymentAPIKey authenticates product-facing RPCs. It is sent as the
	// x-deployment-api-key metadata header.
	DeploymentAPIKey string `env:"LICENSE_DEPLOYMENT_API_KEY"`
}

// Client is a LicenseService client.
type Client struct {
	Config  ClientConfig
	svc     licensev1.LicenseServiceClient
	grpccon *grpc.ClientConn
}

// NewClient dials the LicenseService at cfg.GrpcAddress, retrying until the
// connection is ready (up to ~15s of backoff).
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 3 * time.Second
	}
	if cfg.KeepaliveTime == 0 {
		cfg.KeepaliveTime = 20 * time.Second
	}

	dialOpts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			PermitWithoutStream: true,
			Time:                cfg.KeepaliveTime,
			Timeout:             20 * time.Second,
		}),
	}

	if cfg.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		creds, err := newTLSCredentials(cfg.ServerName)
		if err != nil {
			return nil, fmt.Errorf("license sdk: TLS credentials: %w", err)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	}
	if cfg.ServerName != "" {
		dialOpts = append(dialOpts, grpc.WithAuthority(cfg.ServerName))
	}

	const maxRetries = 5
	var conn *grpc.ClientConn

	for attempt := range maxRetries {
		c, err := grpc.NewClient(cfg.GrpcAddress, dialOpts...)
		if err != nil {
			return nil, err
		}
		c.Connect()

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
		ready := false
		for {
			state := c.GetState()
			if state == connectivity.Ready {
				ready = true
				break
			}
			if !c.WaitForStateChange(ctx, state) {
				break
			}
		}
		cancel()

		if ready {
			conn = c
			break
		}

		c.Close()
		if attempt == maxRetries-1 {
			break
		}
		time.Sleep(time.Duration(500<<attempt) * time.Millisecond)
	}

	if conn == nil {
		return nil, fmt.Errorf("license sdk: license service unreachable after %d attempts", maxRetries)
	}

	return &Client{
		Config:  cfg,
		svc:     licensev1.NewLicenseServiceClient(conn),
		grpccon: conn,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.grpccon != nil {
		return c.grpccon.Close()
	}
	return nil
}

// ctxWithDeploymentKey attaches the deployment API key to the context, which
// authenticates the end-user deployment.
func (c *Client) ctxWithDeploymentKey(ctx context.Context) context.Context {
	if c.Config.DeploymentAPIKey == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, deploymentAPIKeyHeader, c.Config.DeploymentAPIKey)
}
