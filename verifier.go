package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Verifier holds an immutable-by-convention set of Ed25519 public keys and
// verifies tokens against them. Unlike the package-level key set, a Verifier's
// keys are guarded by a mutex, so SetKeys/AddKey may be called while other
// goroutines verify — which is what key rotation on a long-running process
// actually does.
//
// The zero Verifier is not usable; construct one with NewVerifier or SetKeys.
type Verifier struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
	// def is the fallback key for tokens carrying no kid header (kid "").
	def ed25519.PublicKey
}

// NewVerifier returns a Verifier over the given key set, keyed by JWS "kid".
// The map is copied, so later changes to keys do not affect the Verifier.
func NewVerifier(keys map[string]ed25519.PublicKey) *Verifier {
	v := &Verifier{}
	v.SetKeys(keys)
	return v
}

// SetKeys replaces the Verifier's key set. Passing an empty map installs no
// keys, which makes every verification fail — call it with a real keyring.
func (v *Verifier) SetKeys(keys map[string]ed25519.PublicKey) {
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for kid, pk := range keys {
		copied[kid] = pk
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys = copied
}

// AddKey adds or replaces a single key. Use it to preload a new key ahead of
// server-side rotation so tokens it signs verify from the moment they appear.
func (v *Verifier) AddKey(kid string, pk ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys == nil {
		v.keys = map[string]ed25519.PublicKey{}
	}
	v.keys[kid] = pk
}

// SetDefaultKey installs the fallback key used for tokens with no "kid"
// header. It is also the fallback for a kid the key set does not contain,
// which keeps single-key callers working after the server starts stamping kid.
func (v *Verifier) SetDefaultKey(pk ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.def = pk
}

// lookup resolves the public key for a JWS kid header.
//
//   - A kid present in the key set is used.
//   - A single default key (SetDefaultKey / SetPublicKey) is the fallback for
//     any kid: one key means "this one key verifies everything it signs", so
//     existing single-key callers keep working once the server stamps kid.
//   - A strict multi-key set rejects unknown kids, so a rotated token is never
//     checked against the wrong key.
func (v *Verifier) lookup(kid string) (ed25519.PublicKey, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if kid != "" && len(v.keys) > 0 {
		if pk, ok := v.keys[kid]; ok {
			return pk, nil
		}
	}
	if len(v.def) == ed25519.PublicKeySize {
		return v.def, nil
	}
	if kid != "" {
		return nil, fmt.Errorf("license sdk: unknown key id %q", kid)
	}
	return nil, fmt.Errorf("license sdk: public key not set; call SetKeys or SetDefaultKey")
}

// verifyToken verifies the signature of a token and returns its claims,
// without time enforcement (callers apply it via checkTime).
func (v *Verifier) verifyToken[T any](token string) (*T, error) {
	header, payload, sig, err := splitJWS(token)
	if err != nil {
		return nil, err
	}
	pk, err := v.lookup(jwsKid(header))
	if err != nil {
		return nil, err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("license sdk: decode signature: %w", err)
	}
	if !ed25519.Verify(pk, []byte(header+"."+payload), sigBytes) {
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

// VerifyLicenseToken verifies signature + time against the Verifier's keys and
// returns the claims. nil error means the token is authorized RIGHT NOW.
func (v *Verifier) VerifyLicenseToken(token string) (*LicenseClaims, error) {
	return v.VerifyLicenseTokenAt(token, time.Now())
}

// VerifyLicenseTokenAt is VerifyLicenseToken with an explicit reference time,
// useful for deterministic testing and for callers keeping their own clock.
func (v *Verifier) VerifyLicenseTokenAt(token string, now time.Time) (*LicenseClaims, error) {
	return v.VerifyLicenseTokenWithConfigAt(token, VerifyConfig{}, now)
}

// VerifyLicenseTokenWithConfig verifies signature + time, then applies any
// configured binding checks.
func (v *Verifier) VerifyLicenseTokenWithConfig(token string, cfg VerifyConfig) (*LicenseClaims, error) {
	return v.VerifyLicenseTokenWithConfigAt(token, cfg, time.Now())
}

// VerifyLicenseTokenWithConfigAt is VerifyLicenseTokenWithConfig with an
// explicit reference time.
func (v *Verifier) VerifyLicenseTokenWithConfigAt(token string, cfg VerifyConfig, now time.Time) (*LicenseClaims, error) {
	claims, err := v.verifyToken[LicenseClaims](token)
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

// VerifyLeaseToken verifies a lease token's signature and time window,
// returning its claims.
func (v *Verifier) VerifyLeaseToken(token string) (*LeaseClaims, error) {
	return v.VerifyLeaseTokenAt(token, time.Now())
}

// VerifyLeaseTokenAt is VerifyLeaseToken with an explicit reference time.
func (v *Verifier) VerifyLeaseTokenAt(token string, now time.Time) (*LeaseClaims, error) {
	claims, err := v.verifyToken[LeaseClaims](token)
	if err != nil {
		return nil, err
	}
	if err := checkTime(claims.EXP, 0, now); err != nil {
		return nil, err
	}
	return claims, nil
}
