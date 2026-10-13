package license

import (
	"context"
	"fmt"
	"time"
)

// DefaultAgentAddr is where the license-agent serves its local gRPC endpoint
// (LICENSE_AGENT_GRPC_LISTEN).
const DefaultAgentAddr = "127.0.0.1:6101"

// AgentStatus is the payload the license-agent serves over its local gRPC
// Watch stream, summarizing the license cached on that node. App replicas read
// it instead of talking to the license-server directly, so a replica needs no
// credentials and works while the network is down.
//
// This type is defined here, not in the agent, so both sides of the wire share
// one declaration: the agent marshals it and the app unmarshals it.
type AgentStatus struct {
	// DeploymentID is this node's deployment id, and the token's "dep" claim.
	DeploymentID string `json:"deploymentId"`
	// HasLicense reports whether the agent holds a license token at all.
	HasLicense bool `json:"hasLicense"`
	// Valid is the agent's own verdict. It is advisory: an agent with no
	// public key of its own reports false while still handing over a perfectly
	// good token, so consumers verify RawToken themselves rather than trusting
	// this field.
	Valid bool `json:"valid"`
	// Message explains a false Valid, for operators and logs.
	Message string `json:"message,omitempty"`
	// Reason is the machine-readable counterpart to Message: a token from the
	// Reason* vocabulary below. A consumer maps it to its own wording instead
	// of surfacing Message verbatim, so UI text lives with the UI.
	Reason string `json:"reason,omitempty"`
	// RawToken is the signed license token. Verify it — it is the only thing
	// in this payload a consumer should authorize on.
	RawToken string `json:"rawToken,omitempty"`
	// LeaseToken is the signed online-lease token, present when the license
	// requires an online lease. Consumers that must enforce
	// RequireOnlineLease verify it and confirm it belongs to RawToken.
	LeaseToken string `json:"leaseToken,omitempty"`
}

// AgentStatus.Reason vocabulary. These are stable identifiers, not display
// text: a consumer maps them to its own localized string. The agent sets exactly
// one whenever AgentStatus.Valid is false, so a consumer never has to parse
// Message.
const (
	// ReasonNotActivated: no deployment yet and no activation verdict recorded.
	ReasonNotActivated = "not_activated"
	// ReasonActivationExpired: the server rejected the activation code as expired.
	ReasonActivationExpired = "activation_code_expired"
	// ReasonActivationRevoked: the server rejected the activation code as revoked.
	ReasonActivationRevoked = "activation_code_revoked"
	// ReasonActivationRedeemed: the activation code has no redemptions left.
	ReasonActivationRedeemed = "activation_code_redeemed"
	// ReasonActivationInvalid: the activation code was not found.
	ReasonActivationInvalid = "activation_code_invalid"
	// ReasonMaxDeployments: the license has reached its deployment limit.
	ReasonMaxDeployments = "max_deployments_reached"
	// ReasonLicenseNotActive: the license behind the code is not active.
	ReasonLicenseNotActive = "license_not_active"
	// ReasonActivationFailed: an activation rejection the agent could not classify.
	ReasonActivationFailed = "activation_failed"
	// ReasonRevoked: the deployment's license was revoked server-side.
	ReasonRevoked = "revoked"
	// ReasonNoLicense: the deployment exists but holds no license token yet.
	ReasonNoLicense = "no_license"
	// ReasonTokenInvalid: the cached token failed offline verification.
	ReasonTokenInvalid = "token_invalid"
	// ReasonLeaseRequired: the license needs an online lease the agent lacks.
	ReasonLeaseRequired = "online_lease_required"
	// ReasonLeaseExpired: the held online lease has expired.
	ReasonLeaseExpired = "online_lease_expired"
	// ReasonLeaseMismatch: the held lease belongs to a different license.
	ReasonLeaseMismatch = "online_lease_mismatch"
)

// FetchAgentStatus dials the agent's local gRPC endpoint and returns the
// current status. It is a one-shot passive read: it opens the Watch stream,
// takes the status the agent pushes immediately on connect, then closes. It
// does not call Refresh, so it never forces a network round-trip to the
// license-server and works while the network is down.
//
// addr is a gRPC host:port (e.g. "127.0.0.1:6101"); use DefaultAgentAddr for
// the node-local default.
func FetchAgentStatus(addr string) (*AgentStatus, error) {
	const timeout = 3 * time.Second

	client, err := NewAgentClient(AgentClientConfig{Address: addr, ConnectTimeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("license sdk: fetch agent status: %w", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stream, err := client.Watch(ctx)
	if err != nil {
		return nil, fmt.Errorf("license sdk: fetch agent status: %w", err)
	}

	st, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("license sdk: fetch agent status: %w", err)
	}
	return &st, nil
}

// Verify verifies the agent's license token against the package-level key set
// and returns its claims.
//
// ExpectedDep is filled from the status' own DeploymentID when the caller left
// it empty, so a consumer gets deployment binding without threading the value
// through itself. The agent's Valid field is deliberately ignored: it is
// advisory, and this method is the authoritative answer.
//
// Prefer a Verifier's method where the process holds its own key set — this one
// reads the shared defaultVerifier.
func (s AgentStatus) Verify(cfg VerifyConfig) (*LicenseClaims, error) {
	return defaultVerifier.VerifyAgentStatus(s, cfg)
}

// VerifyOnline is Verify, additionally requiring a live online lease for
// licences that mandate one. See AgentStatus.VerifyOnline.
func (s AgentStatus) VerifyOnline(cfg VerifyConfig) (*LicenseClaims, error) {
	return defaultVerifier.VerifyAgentStatusOnline(s, cfg)
}

// VerifyAgentStatus verifies the agent's license token against the Verifier's
// keys and returns its claims.
//
// ExpectedDep is filled from the status' own DeploymentID when the caller left
// it empty, so a consumer gets deployment binding without threading the value
// through itself. The agent's Valid field is deliberately ignored: it is
// advisory, and this method is the authoritative answer.
func (v *Verifier) VerifyAgentStatus(s AgentStatus, cfg VerifyConfig) (*LicenseClaims, error) {
	return v.VerifyAgentStatusAt(s, cfg, time.Now())
}

// VerifyAgentStatusAt is VerifyAgentStatus with an explicit reference time.
func (v *Verifier) VerifyAgentStatusAt(s AgentStatus, cfg VerifyConfig, now time.Time) (*LicenseClaims, error) {
	if cfg.ExpectedDep == "" {
		cfg.ExpectedDep = s.DeploymentID
	}
	return v.VerifyLicenseTokenWithConfigAt(s.RawToken, cfg, now)
}

// VerifyAgentStatusOnline verifies the agent's license token and, when the
// license requires an online lease, its lease token as well — confirming the
// lease is unexpired and belongs to this license. A license that does not
// require a lease passes with the lease check skipped.
//
// This exists so a consumer can enforce lease liveness itself rather than
// trusting the agent's verdict, which it cannot check independently.
//
// No grace period is applied to the lease here, and the license-agent applies
// none either: a lease past its exp fails both paths, so the agent's advisory
// Valid and this verdict cannot disagree. LicenseClaims.GracePeriod is carried
// in the token for a consumer that wants to honor it — apply it explicitly
// (lease.EXP + claims.GracePeriod) rather than expecting it here.
func (v *Verifier) VerifyAgentStatusOnline(s AgentStatus, cfg VerifyConfig) (*LicenseClaims, error) {
	return v.VerifyAgentStatusOnlineAt(s, cfg, time.Now())
}

// VerifyAgentStatusOnlineAt is VerifyAgentStatusOnline with an explicit
// reference time.
func (v *Verifier) VerifyAgentStatusOnlineAt(s AgentStatus, cfg VerifyConfig, now time.Time) (*LicenseClaims, error) {
	claims, err := v.VerifyAgentStatusAt(s, cfg, now)
	if err != nil {
		return nil, err
	}
	if claims.RequireOnlineLease == 0 {
		return claims, nil
	}
	if s.LeaseToken == "" {
		return nil, fmt.Errorf("license sdk: license %s requires an online lease but the agent supplied none", claims.JTI)
	}
	lease, err := v.VerifyLeaseTokenAt(s.LeaseToken, now)
	if err != nil {
		return nil, fmt.Errorf("license sdk: online lease: %w", err)
	}
	if lease.LicenseJTI != claims.JTI {
		return nil, fmt.Errorf("license sdk: lease is for license %q, not %q", lease.LicenseJTI, claims.JTI)
	}
	if lease.DepID != "" && s.DeploymentID != "" && lease.DepID != s.DeploymentID {
		return nil, fmt.Errorf("license sdk: lease is for deployment %q, not %q", lease.DepID, s.DeploymentID)
	}
	return claims, nil
}
