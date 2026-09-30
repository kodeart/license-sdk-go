package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
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

func TestVerifyLicenseToken_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	SetPublicKey(pub)

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

	claims := LicenseClaims{
		Sub: "tenant-p", Aud: "ERP", JTI: "jti-perp", Dep: "dep-p",
		TenantModel: "single", LicensingModel: "perpetual", Type: "perpetual",
		EXP: 253402300799999,
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

func TestVerifyLicenseToken_BadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	SetPublicKey(pub)

	token := signJWS(t, otherPriv, "kid-1", LicenseClaims{JTI: "jti-1"})
	if _, err := VerifyLicenseToken(token); err == nil {
		t.Fatal("expected error for token signed by wrong key")
	}
}

func TestVerifyToken_NoPublicKey(t *testing.T) {
	prev := PublicKey
	PublicKey = nil
	defer func() { PublicKey = prev }()

	if _, err := VerifyLicenseToken("a.b.c"); err == nil {
		t.Fatal("expected error when public key is not set")
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
