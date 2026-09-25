package license

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// serverCA is the optional CA bundle used to verify the license server's TLS
// certificate. Override via WithServerCAFile (see NewClient options).
var serverCAPool *x509.CertPool

// checkServerName sets FromConfig to true and verifies the presented
// certificate hostname against ServerName.
func newTLSCredentials(serverName string) (credentials.TransportCredentials, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if serverCAPool != nil {
		cfg.RootCAs = serverCAPool
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return credentials.NewTLS(cfg), nil
}

// WithServerCAFile loads a PEM CA bundle used to verify the license server's
// TLS certificate. If not set, the system root store is used.
func WithServerCAFile(path string) error {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("license sdk: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("license sdk: no valid PEM certificates in %s", path)
	}
	serverCAPool = pool
	return nil
}
