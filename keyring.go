package license

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadKeyRing reads every "*.pub" file in fsys and returns the server's
// Ed25519 public keys keyed by JWS "kid" — the file name without its extension,
// which is how the signer names keys (sk_2026_09.pub signs as kid
// "sk_2026_09"). Retired keys stay in the set so tokens they signed keep
// verifying; pass the result to Verifier.SetKeys or SetPublicKeys.
//
// An empty keyring is an error: a verifier with no keys rejects every token,
// which looks like a licensing failure rather than a packaging bug.
func LoadKeyRing(fsys fs.FS) (map[string]ed25519.PublicKey, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("license sdk: read keyring dir: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if name := e.Name(); !e.IsDir() && strings.HasSuffix(name, ".pub") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("license sdk: no *.pub keys found, refusing to run")
	}
	sort.Strings(names)

	keys := make(map[string]ed25519.PublicKey, len(names))
	for _, name := range names {
		raw, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			return nil, fmt.Errorf("license sdk: read key %s: %w", name, readErr)
		}
		pk, parseErr := parsePublicKey(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("license sdk: parse key %s: %w", name, parseErr)
		}
		keys[strings.TrimSuffix(name, ".pub")] = pk
	}
	return keys, nil
}

// LoadKeyRingFile loads a keyring from a directory on disk. It is the
// filesystem counterpart to LoadKeyRing for callers that hold a path rather
// than an fs.FS (the license-agent reads its keyring from config).
func LoadKeyRingFile(dir string) (map[string]ed25519.PublicKey, error) {
	return LoadKeyRing(os.DirFS(dir))
}

// LoadPublicKeyFile reads a single raw 32-byte Ed25519 public key file and
// returns it under an explicit kid. Use it when the key is configured as one
// path rather than a keyring directory.
func LoadPublicKeyFile(path, kid string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("license sdk: read public key: %w", err)
	}
	pk, err := parsePublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("license sdk: public key %s: %w", filepath.Base(path), err)
	}
	return pk, nil
}

// parsePublicKey validates a raw public key. The signer writes the bare
// 32-byte Ed25519 public key, which is what the agent and app keyrings hold;
// PEM is only used for the private key.
func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
