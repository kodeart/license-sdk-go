package license

import (
	"context"

	licensev1 "github.com/kodeart/license-sdk-go/proto/license/v1"
)

// Activate redeems an activation code and creates a deployment. It returns
// the signed license + lease tokens, the deployment API key, and the
// deployment ID. Callers must persist the returned API key and ID and use
// them for subsequent Heartbeat/FetchLicense/GetCRL calls.
func (c *Client) Activate(ctx context.Context, activationCode, fingerprint, productCode, hostname string) (*licensev1.ActivateResponse, error) {
	return c.svc.Activate(c.ctxWithDeploymentKey(ctx), &licensev1.ActivateRequest{
		ActivationCode: activationCode,
		Fingerprint:    fingerprint,
		ProductCode:    productCode,
		Hostname:       hostname,
	})
}

// Heartbeat validates the license and returns a signed lease (or updated
// license token when the license was reissued). Usage metrics are optional.
func (c *Client) Heartbeat(ctx context.Context, licenseToken, leaseToken, fingerprint string, lastCRLSeq int64, usage ...*licensev1.UsageMetric) (*licensev1.HeartbeatResponse, error) {
	return c.svc.Heartbeat(c.ctxWithDeploymentKey(ctx), &licensev1.HeartbeatRequest{
		LicenseToken: licenseToken,
		LeaseToken:   leaseToken,
		Fingerprint:  fingerprint,
		Usage:        usage,
		LastCrlSeq:   lastCRLSeq,
	})
}

// GetCRL returns CRL entries after sinceSequenceID (0 for the full list).
func (c *Client) GetCRL(ctx context.Context, sinceSequenceID int64) (*licensev1.GetCRLResponse, error) {
	return c.svc.GetCRL(c.ctxWithDeploymentKey(ctx), &licensev1.GetCRLRequest{
		SinceSequenceId: sinceSequenceID,
	})
}

// ReportUsage submits usage metrics for a deployment.
func (c *Client) ReportUsage(ctx context.Context, deploymentID string, metrics ...*licensev1.UsageMetric) (*licensev1.ReportUsageResponse, error) {
	return c.svc.ReportUsage(c.ctxWithDeploymentKey(ctx), &licensev1.ReportUsageRequest{
		DeploymentId: deploymentID,
		Metrics:      metrics,
	})
}

// FetchLicense returns the current signed license for a deployment. Useful on
// agent startup when no cached license token exists yet.
func (c *Client) FetchLicense(ctx context.Context, deploymentID string) (*licensev1.FetchLicenseResponse, error) {
	return c.svc.FetchLicense(c.ctxWithDeploymentKey(ctx), &licensev1.FetchLicenseRequest{
		DeploymentId: deploymentID,
	})
}
