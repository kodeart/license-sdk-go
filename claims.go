// Package license is a client SDK for the license-server LicenseService.
package license

// LicenseClaims is the JSON payload of a signed license token. The shape
// mirrors the server's domain.LicenseClaims.
type LicenseClaims struct {
	ISS                string        `json:"iss"`
	Sub                string        `json:"sub"`
	Aud                string        `json:"aud"`
	JTI                string        `json:"jti"`
	IAT                int64         `json:"iat"`
	NBF                int64         `json:"nbf,omitempty"`
	EXP                int64         `json:"exp,omitempty"`
	Dep                string        `json:"dep"`
	FP                 string        `json:"fp,omitempty"`
	TenantModel        string        `json:"tenant_model"`
	LicensingModel     string        `json:"licensing_model"`
	Edition            string        `json:"edition,omitempty"`
	Type               string        `json:"type"`
	Seats              int           `json:"seats,omitempty"`
	MaxDeployments     int           `json:"max_deployments,omitempty"`
	Modules            []ModuleEntry `json:"modules,omitempty"`
	Tenants            []TenantEntry `json:"tenants,omitempty"`
	DefaultModules     []string      `json:"default_modules,omitempty"`
	MaxTenants         int           `json:"max_tenants,omitempty"`
	LeaseDuration      int64         `json:"lease_duration"`
	RefreshInterval    int64         `json:"refresh_interval"`
	GracePeriod        int64         `json:"grace_period"`
	RequireOnlineLease int           `json:"require_online_lease"`
	TelemetryEnabled   int           `json:"telemetry_enabled"`
	Ver                int           `json:"ver"`
}

// LeaseClaims is the JSON payload of a signed lease token. The shape mirrors
// the server's domain.LeaseClaims.
type LeaseClaims struct {
	ISS         string `json:"iss"`
	Sub         string `json:"sub"`
	Aud         string `json:"aud"`
	JTI         string `json:"jti"`
	IAT         int64  `json:"iat"`
	EXP         int64  `json:"exp"`
	DepID       string `json:"dep_id"`
	LicenseJTI  string `json:"license_jti"`
	LicenseVer  int    `json:"license_ver"`
	Fingerprint string `json:"fp,omitempty"`
}

// ModuleEntry is a module with optional limits inside a license.
type ModuleEntry struct {
	Code   string             `json:"code"`
	Limits map[string]float64 `json:"limits,omitempty"`
}

// TenantEntry is per-tenant module assignment (multi-tenant).
type TenantEntry struct {
	ID      string        `json:"id"`
	Modules []ModuleEntry `json:"modules"`
}
