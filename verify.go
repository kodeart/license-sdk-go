package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PerpetualExpiryMS is the exp claim emitted for perpetual licenses
// (valid_to = 0). A token carrying this exp never expires.
const PerpetualExpiryMS int64 = 253402300799999

// clockSkew is the leeway applied when checking exp/nbf, so tokens issued by
// a server with a slightly-advanced clock are not rejected by clients.
const clockSkew = 30 * time.Second

// KeySet was the exported key collection before Verifier existed. It had an
// unexported field and no exported methods, so it was never constructible or
// readable from outside this package; it is kept only so existing declarations
// still compile.
//
// Deprecated: use Verifier (NewVerifier with a LoadKeyRing result) instead. It
// holds its keys behind a mutex, which the package-level SetPublicKeys cannot do.
type KeySet struct {
	keys map[string]ed25519.PublicKey
}

// PublicKey is the server's default Ed25519 public key, used when a token
// carries no "kid" header. Override it via SetPublicKey, or use SetPublicKeys
// for multi-key rotation support.
//
// Deprecated: prefer a Verifier built with NewVerifier(keys) from LoadKeyRing.
// The package-level functions below share one process-wide key set, so they
// cannot be configured from two places without racing.
var PublicKey ed25519.PublicKey

// defaultVerifier backs the package-level functions, so the legacy PublicKey
// variable and the kid-keyed set live in one store.
var defaultVerifier = &Verifier{}

// SetPublicKey installs a single default public key (kid ""), kept for
// backward compatibility. Prefer SetPublicKeys/AddPublicKey for rotation.
func SetPublicKey(pk ed25519.PublicKey) {
	PublicKey = pk
	defaultVerifier.SetDefaultKey(pk)
}

// SetPublicKeys installs a key set keyed by JWS "kid". The default key (kid
// "") may be included for tokens without a kid header.
func SetPublicKeys(keys map[string]ed25519.PublicKey) {
	defaultVerifier.SetKeys(keys)
}

// AddPublicKey adds or replaces a single key in the key set. Use it to preload
// a new key ahead of server-side rotation so existing tokens keep validating.
func AddPublicKey(kid string, pk ed25519.PublicKey) {
	defaultVerifier.AddKey(kid, pk)
}

// lookupKey resolves the public key for a JWS kid header against the
// package-level key set. See Verifier.lookup for the resolution rules.
func lookupKey(kid string) (ed25519.PublicKey, error) {
	return defaultVerifier.lookup(kid)
}

// VerifyLicenseToken verifies the Ed25519 signature of a license token, checks
// that it is valid at the current time (exp/nbf with 30s skew), and returns
// its claims. nil error means the token is authorized RIGHT NOW.
func VerifyLicenseToken(token string) (*LicenseClaims, error) {
	return VerifyLicenseTokenAt(token, time.Now())
}

// VerifyLicenseTokenAt is VerifyLicenseToken with an explicit reference time,
// useful for deterministic testing and for callers keeping their own clock.
func VerifyLicenseTokenAt(token string, now time.Time) (*LicenseClaims, error) {
	return VerifyLicenseTokenWithConfigAt(token, VerifyConfig{}, now)
}

// VerifyConfig carries optional binding checks applied after signature and
// time verification. All fields are OPT-IN: a zero value skips that check, so
// existing consumers are unaffected. Callers binding a deployment to a
// specific product (aud), deployment id (dep) or server (iss) should set the
// matching fields.
type VerifyConfig struct {
	// ExpectedAud, if set, must equal the token's "aud" (product code).
	ExpectedAud string
	// ExpectedDep, if set, must equal the token's "dep" (deployment id).
	ExpectedDep string
	// ExpectedIssuer, if set, must equal the token's "iss".
	ExpectedIssuer string
}

// VerifyLicenseTokenWithConfig verifies signature + time, then applies any
// configured binding checks.
func VerifyLicenseTokenWithConfig(token string, cfg VerifyConfig) (*LicenseClaims, error) {
	return VerifyLicenseTokenWithConfigAt(token, cfg, time.Now())
}

// VerifyLicenseTokenWithConfigAt is VerifyLicenseTokenWithConfig with an
// explicit reference time.
func VerifyLicenseTokenWithConfigAt(token string, cfg VerifyConfig, now time.Time) (*LicenseClaims, error) {
	claims, err := verifyToken[LicenseClaims](token)
	if err != nil {
		return nil, err
	}
	if err := checkTime(claims.EXP, claims.NBF, now); err != nil {
		return nil, err
	}
	if err := checkBinding(claims.Aud, claims.Dep, claims.ISS, cfg); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkBinding enforces the VerifyConfig binding fields that are set. A zero
// field skips its check, so callers bind only what they actually know.
func checkBinding(aud, dep, iss string, cfg VerifyConfig) error {
	if cfg.ExpectedAud != "" && aud != cfg.ExpectedAud {
		return fmt.Errorf("license sdk: token aud %q does not match expected %q", aud, cfg.ExpectedAud)
	}
	if cfg.ExpectedDep != "" && dep != cfg.ExpectedDep {
		return fmt.Errorf("license sdk: token dep %q does not match expected %q", dep, cfg.ExpectedDep)
	}
	if cfg.ExpectedIssuer != "" && iss != cfg.ExpectedIssuer {
		return fmt.Errorf("license sdk: token iss %q does not match expected %q", iss, cfg.ExpectedIssuer)
	}
	return nil
}

// VerifyLeaseToken verifies the Ed25519 signature of a lease token and that it
// is valid at the current time, returning its claims.
func VerifyLeaseToken(token string) (*LeaseClaims, error) {
	return VerifyLeaseTokenAt(token, time.Now())
}

// VerifyLeaseTokenAt is VerifyLeaseToken with an explicit reference time.
func VerifyLeaseTokenAt(token string, now time.Time) (*LeaseClaims, error) {
	claims, err := verifyToken[LeaseClaims](token)
	if err != nil {
		return nil, err
	}
	if err := checkTime(claims.EXP, 0, now); err != nil {
		return nil, err
	}
	return claims, nil
}

// IsExpired reports whether a claim's exp is in the past (perpetual never
// expires). now is the reference time.
func IsExpired(claims *LicenseClaims, now time.Time) bool {
	if claims == nil || claims.EXP == PerpetualExpiryMS || claims.EXP == 0 {
		return false
	}
	return now.After(time.UnixMilli(claims.EXP).Add(clockSkew))
}

// ValidUntil returns the instant a license ceases to be valid, or zero Time for
// a perpetual license. The returned time accounts for clock skew.
func ValidUntil(claims *LicenseClaims) time.Time {
	if claims == nil || claims.EXP == PerpetualExpiryMS {
		return time.Time{}
	}
	return time.UnixMilli(claims.EXP).Add(-clockSkew)
}

// checkTime enforces exp/nbf at the reference time with clock-skew leeway. A
// perpetual exp (PerpetualExpiryMS) never expires. Zero exp/nbf values are
// treated as "no constraint" (issued before the fields were populated).
func checkTime(exp, nbf int64, now time.Time) error {
	skew := clockSkew
	if exp != PerpetualExpiryMS && exp != 0 && now.After(time.UnixMilli(exp).Add(skew)) {
		return fmt.Errorf("license sdk: token expired at %s", time.UnixMilli(exp).Format(time.RFC3339))
	}
	if nbf != 0 && now.Before(time.UnixMilli(nbf).Add(-skew)) {
		return fmt.Errorf("license sdk: token not valid until %s", time.UnixMilli(nbf).Format(time.RFC3339))
	}
	return nil
}

// ParseLicenseToken decodes a license token's claims without verifying the
// signature. Useful for inspecting tokens before verification.
func ParseLicenseToken(token string) (*LicenseClaims, error) {
	_, payload, _, err := splitJWS(token)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("license sdk: decode payload: %w", err)
	}
	var claims LicenseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("license sdk: parse license claims: %w", err)
	}
	return &claims, nil
}

// ParseLeaseToken decodes a lease token's claims without verifying.
func ParseLeaseToken(token string) (*LeaseClaims, error) {
	_, payload, _, err := splitJWS(token)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("license sdk: decode payload: %w", err)
	}
	var claims LeaseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("license sdk: parse lease claims: %w", err)
	}
	return &claims, nil
}

// verifyToken verifies the signature and returns the claims, without time
// enforcement (callers apply it via checkTime). It resolves keys from the
// package-level key set; use a Verifier's method when concurrent rotation
// matters.
func verifyToken[T any](token string) (*T, error) {
	return defaultVerifier.verifyToken[T](token)
}

// jwsKid extracts the "kid" header value from a base64url-encoded JWS header.
func jwsKid(header string) string {
	b, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return ""
	}
	return h.Kid
}

// splitJWS splits compact JWS into (headerB64, payloadB64, sigB64, error).
func splitJWS(token string) (string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("license sdk: expected 3 JWS parts, got %d", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}
