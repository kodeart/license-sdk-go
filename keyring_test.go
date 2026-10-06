package license

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"
)

func TestLoadKeyRing_KeysByFileStem(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	fsys := fstest.MapFS{
		"sk_2026_09.pub": &fstest.MapFile{Data: pub1},
		"sk_2026_10.pub": &fstest.MapFile{Data: pub2},
		// Ignored: not a .pub file, and a subdirectory.
		"README.md":        &fstest.MapFile{Data: []byte("notes")},
		"nested/other.pub": &fstest.MapFile{Data: pub2},
	}

	keys, err := LoadKeyRing(fsys)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2: %v", len(keys), keys)
	}
	if !keys["sk_2026_09"].Equal(pub1) {
		t.Error("sk_2026_09 did not map to the first key")
	}
	if !keys["sk_2026_10"].Equal(pub2) {
		t.Error("sk_2026_10 did not map to the second key")
	}
}

func TestLoadKeyRing_EmptyIsAnError(t *testing.T) {
	if _, err := LoadKeyRing(fstest.MapFS{"README.md": &fstest.MapFile{Data: []byte("x")}}); err == nil {
		t.Fatal("expected an error for a keyring with no .pub files")
	}
}

// A keyring that silently loaded zero keys would make every verification fail
// and look like a licensing problem, not a packaging one.
func TestLoadKeyRing_RejectsWrongKeySize(t *testing.T) {
	fsys := fstest.MapFS{"sk_short.pub": &fstest.MapFile{Data: []byte("too short")}}
	if _, err := LoadKeyRing(fsys); err == nil {
		t.Fatal("expected an error for a malformed public key")
	}
}

func TestLoadKeyRingFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sk_2026_09.pub"), pub, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	keys, err := LoadKeyRingFile(dir)
	if err != nil {
		t.Fatalf("LoadKeyRingFile: %v", err)
	}
	if !keys["sk_2026_09"].Equal(pub) {
		t.Error("keyring did not resolve sk_2026_09")
	}
}

func TestLoadPublicKeyFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sk.pub")
	if err := os.WriteFile(path, pub, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	got, err := LoadPublicKeyFile(path, "")
	if err != nil {
		t.Fatalf("LoadPublicKeyFile: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("loaded key does not match")
	}
}

// A keyring loaded with LoadKeyRing must verify the tokens the signer made with
// the matching kid — that pairing is the whole point of keying by filename stem.
func TestLoadKeyRing_VerifiesTokensByKid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sk_2026_09.pub"), pub, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	keys, err := LoadKeyRingFile(dir)
	if err != nil {
		t.Fatalf("LoadKeyRingFile: %v", err)
	}

	v := NewVerifier(keys)
	token := signJWS(t, priv, "sk_2026_09", LicenseClaims{
		JTI: "jti-1",
		EXP: time.Now().Add(time.Hour).UnixMilli(),
	})
	if _, err := v.VerifyLicenseToken(token); err != nil {
		t.Fatalf("verify with matching kid: %v", err)
	}

	// A different kid in the same strict keyring must not fall through to the
	// one installed key, or a rotated token gets checked against the wrong key.
	if _, err := v.VerifyLicenseToken(signJWS(t, priv, "sk_unknown", LicenseClaims{
		JTI: "jti-2",
		EXP: time.Now().Add(time.Hour).UnixMilli(),
	})); err == nil {
		t.Fatal("expected an unknown kid to be rejected by a strict keyring")
	}
}
