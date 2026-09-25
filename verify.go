package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// PublicKey is the server's Ed25519 public key, baked into the SDK for
// offline verification of license and lease tokens. Override it with the
// value printed by the server's keygen tool or SetPublicKey.
var PublicKey ed25519.PublicKey

// SetPublicKey installs the server's Ed25519 public key for offline
// verification. The server's signing key (keys/sk_YYYY_MM.pub) is loaded with
// signer.LoadKey; use its raw 32-byte public key here.
func SetPublicKey(pk ed25519.PublicKey) {
	PublicKey = pk
}

// VerifyLicenseToken verifies the Ed25519 signature of a license token and
// returns its claims. It requires PublicKey to be set.
func VerifyLicenseToken(token string) (*LicenseClaims, error) {
	return verifyToken[LicenseClaims](token)
}

// VerifyLeaseToken verifies the Ed25519 signature of a lease token and
// returns its claims. It requires PublicKey to be set.
func VerifyLeaseToken(token string) (*LeaseClaims, error) {
	return verifyToken[LeaseClaims](token)
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

func verifyToken[T any](token string) (*T, error) {
	if len(PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("license sdk: public key not set; call SetPublicKey first")
	}
	header, payload, sig, err := splitJWS(token)
	if err != nil {
		return nil, err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("license sdk: decode signature: %w", err)
	}
	if !ed25519.Verify(PublicKey, []byte(header+"."+payload), sigBytes) {
		return nil, fmt.Errorf("license sdk: invalid signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("license sdk: decode payload: %w", err)
	}
	var claims T
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("license sdk: parse claims: %w", err)
	}
	return &claims, nil
}

// splitJWS splits compact JWS into (headerB64, payloadB64, sigB64, error).
func splitJWS(token string) (string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("license sdk: expected 3 JWS parts, got %d", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}
