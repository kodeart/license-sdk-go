package license

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultAgentAddr is where the license-agent serves its local status endpoint.
const DefaultAgentAddr = "http://127.0.0.1:6100"

// AgentStatus is the payload the license-agent serves on its local HTTP
// endpoint (/ and /status), summarizing the license cached on that node. App
// replicas read it instead of talking to the license-server directly, so a
// replica needs no credentials and works while the network is down.
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
	// RawToken is the signed license token. Verify it — it is the only thing
	// in this payload a consumer should authorize on.
	RawToken string `json:"rawToken,omitempty"`
	// LeaseToken is the signed online-lease token, present when the license
	// requires an online lease. Consumers that must enforce
	// RequireOnlineLease verify it and confirm it belongs to RawToken.
	LeaseToken string `json:"leaseToken,omitempty"`
}

// FetchAgentStatus GETs the agent's status endpoint. Both / and /status serve
// the same payload; /status is used as the more explicit of the two.
func FetchAgentStatus(addr string) (*AgentStatus, error) {
	resp, err := http.Get(addr + "/status")
	if err != nil {
		return nil, fmt.Errorf("license sdk: fetch agent status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license sdk: agent status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("license sdk: read agent status: %w", err)
	}
	var st AgentStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("license sdk: parse agent status: %w", err)
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
