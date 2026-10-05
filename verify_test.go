package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// signJWS signs a compact JWS exactly as the server's signer does so the
// offline verification code path can be tested against the wire format.
func signJWS(t *testing.T, priv ed25519.PrivateKey, kid string, payload any) string {
	t.Helper()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(priv, []byte(headerB64+"."+payloadB64))
	return headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func resetKeys() {
	PublicKey = nil
	keySet.keys = nil
}

func TestVerifyLicenseToken_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	SetPublicKey(pub)
	defer resetKeys()

	token := signJWS(t, priv, "kid-1", LicenseClaims{
		Sub:            "tenant-1",
		Aud:            "ERP",
		JTI:            "jti-1",
		Dep:            "dep-1",
		TenantModel:    "multi",
		LicensingModel: "module_based",
		Seats:          25,
		MaxDeployments: 3,
		Ver:            2,
		EXP:            time.Now().Add(24 * time.Hour).UnixMilli(),
	})

	claims, err := VerifyLicenseToken(token)
	if err != nil {
		t.Fatalf("VerifyLicenseToken: %v", err)
	}
	if claims.JTI != "jti-1" {
		t.Errorf("jti = %q, want jti-1", claims.JTI)
	}
	if claims.Seats != 25 {
		t.Errorf("seats = %d, want 25", claims.Seats)
	}
	if claims.MaxDeployments != 3 {
		t.Errorf("max_deployments = %d, want 3", claims.MaxDeployments)
	}
}

func TestVerifyLicenseToken_PerpetualExp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	SetPublicKey(pub)
	defer resetKeys()

	claims := LicenseClaims{
		Sub: "tenant-p", Aud: "ERP", JTI: "jti-perp", Dep: "dep-p",
		TenantModel: "single", LicensingModel: "perpetual", Type: "perpetual",
		EXP: PerpetualExpiryMS,
	}

	token := signJWS(t, priv, "kid-1", claims)
	if _, err := VerifyLicenseToken(token); err != nil {
		t.Fatalf("VerifyLicenseToken: %v", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	if !bytes.Contains(payloadJSON, []byte(`"exp":253402300799999`)) {
		t.Errorf("payload lacks always-present exp: %s", payloadJSON)
	}
}

func TestVerifyLicenseToken_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	SetPublicKey(pub)
	defer resetKeys()

	claims := LicenseClaims{
		JTI: "jti-exp", Aud: "ERP",
		EXP: time.Now().Add(-2 * time.Minute).UnixMilli(),
	}
	token := signJWS(t, priv, "kid-1", claims)
	if _, err := VerifyLicenseToken(token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyLicenseToken_NotYetValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	SetPublicKey(pub)
	defer resetKeys()

	claims := LicenseClaims{
		JTI: "jti-nbf", Aud: "ERP",
		EXP: time.Now().Add(24 * time.Hour).UnixMilli(),
		NBF: time.Now().Add(10 * time.Minute).UnixMilli(),
	}
	token := signJWS(t, priv, "kid-1", claims)
	if _, err := VerifyLicenseToken(token); err == nil {
		t.Fatal("expected error for not-yet-valid token")
	}

	if _, err := VerifyLicenseTokenAt(token, time.UnixMilli(claims.NBF)); err != nil {
		t.Fatalf("VerifyLicenseTokenAt at NBF: %v", err)
	}
}

func TestVerifyLicenseToken_BadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	SetPublicKey(pub)
	defer resetKeys()

	token := signJWS(t, otherPriv, "kid-1", LicenseClaims{JTI: "jti-1", EXP: time.Now().Add(time.Hour).UnixMilli()})
	if _, err := VerifyLicenseToken(token); err == nil {
		t.Fatal("expected error for token signed by wrong key")
	}
}

func TestVerifyToken_NoPublicKey(t *testing.T) {
	resetKeys()
	defer resetKeys()

	if _, err := VerifyLicenseToken("a.b.c"); err == nil {
		t.Fatal("expected error when public key is not set")
	}
}

func TestVerifyToken_MultiKey_KidLookup(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(nil)
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	SetPublicKeys(map[string]ed25519.PublicKey{
		"old": oldPub,
		"new": newPub,
	})
	defer resetKeys()

	// Old kid validates.
	oldToken := signJWS(t, oldPriv, "old", LicenseClaims{JTI: "old", EXP: time.Now().Add(time.Hour).UnixMilli()})
	if _, err := VerifyLicenseToken(oldToken); err != nil {
		t.Fatalf("old kid should verify: %v", err)
	}

	// New kid validates.
	newToken := signJWS(t, newPriv, "new", LicenseClaims{JTI: "new", EXP: time.Now().Add(time.Hour).UnixMilli()})
	if _, err := VerifyLicenseToken(newToken); err != nil {
		t.Fatalf("new kid should verify: %v", err)
	}

	// Unknown kid errors even with a valid default key set.
	_, roguePriv, _ := ed25519.GenerateKey(nil)
	rogue := signJWS(t, roguePriv, "rogue", LicenseClaims{EXP: time.Now().Add(time.Hour).UnixMilli()})
	if _, err := VerifyLicenseToken(rogue); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestVerifyLicenseToken_ConfigBindings(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	SetPublicKey(pub)
	defer resetKeys()

	token := signJWS(t, priv, "kid-1", LicenseClaims{
		JTI: "jti-bind", Aud: "ERP", Dep: "dep-9", ISS: "https://license.acme.com",
		EXP: time.Now().Add(time.Hour).UnixMilli(),
	})

	cfg := VerifyConfig{ExpectedAud: "ERP", ExpectedDep: "dep-9", ExpectedIssuer: "https://license.acme.com"}
	if _, err := VerifyLicenseTokenWithConfig(token, cfg); err != nil {
		t.Fatalf("matching config should verify: %v", err)
	}

	cfgBad := VerifyConfig{ExpectedAud: "OTHER-product"}
	if _, err := VerifyLicenseTokenWithConfig(token, cfgBad); err == nil {
		t.Fatal("expected error for mismatched aud")
	}

	// Zero-value config is a no-op — existing consumers unaffected.
	if _, err := VerifyLicenseTokenWithConfig(token, VerifyConfig{}); err != nil {
		t.Fatalf("zero config should verify: %v", err)
	}
}

func TestIsExpiredAndValidUntil(t *testing.T) {
	future := &LicenseClaims{EXP: time.Now().Add(time.Hour).UnixMilli()}
	if IsExpired(future, time.Now()) {
		t.Fatal("future license should not be expired")
	}
	if v := ValidUntil(future); v.IsZero() {
		t.Fatal("expected a finite ValidUntil")
	}

	past := &LicenseClaims{EXP: time.Now().Add(-time.Hour).UnixMilli()}
	if !IsExpired(past, time.Now()) {
		t.Fatal("past license should be expired")
	}

	perp := &LicenseClaims{EXP: PerpetualExpiryMS}
	if IsExpired(perp, time.Now()) {
		t.Fatal("perpetual license should never expire")
	}
	if v := ValidUntil(perp); !v.IsZero() {
		t.Fatalf("perpetual ValidUntil should be zero, got %v", v)
	}
}

func TestParseLicenseToken_NoSignatureCheck(t *testing.T) {
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"jti-parse","ver":3}`))
	claims, err := ParseLicenseToken("eyJhbGciOiJFZERTQSJ9." + payloadB64 + ".sig")
	if err != nil {
		t.Fatalf("ParseLicenseToken: %v", err)
	}
	if claims.JTI != "jti-parse" || claims.Ver != 3 {
		t.Fatalf("claims = %+v, want jti-parse/ver 3", claims)
	}
}

func TestSplitJWS_Invalid(t *testing.T) {
	if _, _, _, err := splitJWS("only-two-parts"); err == nil {
		t.Fatal("expected error for malformed JWS")
	}
}
