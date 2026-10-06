package license

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// agentStatus builds a signed license token plus the agent status that serves it.
func agentStatus(t *testing.T, kid string, claims LicenseClaims, lease *LeaseClaims) (*ed25519.PrivateKey, AgentStatus) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tokens := map[string]ed25519.PublicKey{kid: pub}
	SetPublicKeys(tokens)
	t.Cleanup(resetKeys)

	claims.EXP = time.Now().Add(time.Hour).UnixMilli()
	token := signJWS(t, priv, kid, claims)

	st := AgentStatus{
		DeploymentID: claims.Dep,
		HasLicense:   true,
		Valid:        true,
		RawToken:     token,
	}
	if lease != nil {
		st.LeaseToken = signJWS(t, priv, kid, *lease)
	}
	return &priv, st
}

func TestAgentStatus_Verify(t *testing.T) {
	_, st := agentStatus(t, "sk_test", LicenseClaims{
		JTI: "jti-1",
		Aud: "inbrokeros",
		Dep: "dep-abc",
	}, nil)

	claims, err := st.Verify(VerifyConfig{ExpectedAud: "inbrokeros"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.JTI != "jti-1" {
		t.Errorf("jti = %q, want jti-1", claims.JTI)
	}
}

// The agent always knows its own deployment id, so Verify binds dep from the
// status without the caller threading the value through.
func TestAgentStatus_VerifyBindsDepFromStatus(t *testing.T) {
	_, st := agentStatus(t, "sk_test", LicenseClaims{JTI: "jti-1", Dep: "dep-abc"}, nil)

	if _, err := st.Verify(VerifyConfig{}); err != nil {
		t.Fatalf("Verify with no expected dep: %v", err)
	}
	if _, err := st.Verify(VerifyConfig{ExpectedDep: "dep-other"}); err == nil {
		t.Fatal("expected an explicit dep mismatch to be rejected")
	}
}

func TestAgentStatus_VerifyRejectsAudMismatch(t *testing.T) {
	_, st := agentStatus(t, "sk_test", LicenseClaims{JTI: "jti-1", Aud: "inbrokeros"}, nil)

	if _, err := st.Verify(VerifyConfig{ExpectedAud: "other-product"}); err == nil {
		t.Fatal("expected an aud mismatch to be rejected")
	}
}

// The agent's Valid flag is advisory. An agent holding a good token but judging
// it false (e.g. it has no public key of its own) must still yield claims.
func TestAgentStatus_VerifyIgnoresAdvisoryValid(t *testing.T) {
	_, st := agentStatus(t, "sk_test", LicenseClaims{JTI: "jti-1", Dep: "dep-1"}, nil)
	st.Valid = false
	st.Message = "no public key configured"

	if _, err := st.Verify(VerifyConfig{}); err != nil {
		t.Fatalf("Verify should not depend on the agent's verdict: %v", err)
	}
}

func TestAgentStatus_VerifyOnline_LeaseNotRequired(t *testing.T) {
	_, st := agentStatus(t, "sk_test", LicenseClaims{
		JTI:                "jti-1",
		Dep:                "dep-1",
		RequireOnlineLease: 0,
	}, nil)

	if _, err := st.VerifyOnline(VerifyConfig{}); err != nil {
		t.Fatalf("a license not requiring a lease must pass without one: %v", err)
	}
}

func TestAgentStatus_VerifyOnline_ValidLease(t *testing.T) {
	leaseExp := time.Now().Add(5 * time.Minute).UnixMilli()
	_, st := agentStatus(t, "sk_test", LicenseClaims{
		JTI:                "jti-1",
		Dep:                "dep-1",
		RequireOnlineLease: 1,
	}, &LeaseClaims{
		JTI:        "lease-1",
		EXP:        leaseExp,
		DepID:      "dep-1",
		LicenseJTI: "jti-1",
	})

	if _, err := st.VerifyOnline(VerifyConfig{}); err != nil {
		t.Fatalf("VerifyOnline with a live lease: %v", err)
	}
}

func TestAgentStatus_VerifyOnline_MissingLease(t *testing.T) {
	_, st := agentStatus(t, "sk_test", LicenseClaims{
		JTI:                "jti-1",
		Dep:                "dep-1",
		RequireOnlineLease: 1,
	}, nil)

	if _, err := st.VerifyOnline(VerifyConfig{}); err == nil {
		t.Fatal("expected a missing lease to be rejected")
	}
}

func TestAgentStatus_VerifyOnline_LapsedLease(t *testing.T) {
	leaseExp := time.Now().Add(-time.Hour).UnixMilli()
	_, st := agentStatus(t, "sk_test", LicenseClaims{
		JTI:                "jti-1",
		Dep:                "dep-1",
		RequireOnlineLease: 1,
	}, &LeaseClaims{
		JTI:        "lease-1",
		EXP:        leaseExp,
		DepID:      "dep-1",
		LicenseJTI: "jti-1",
	})

	if _, err := st.VerifyOnline(VerifyConfig{}); err == nil {
		t.Fatal("expected an expired lease to be rejected")
	}
}

// A lease for a different license proves nothing about this one.
func TestAgentStatus_VerifyOnline_LeaseForOtherLicense(t *testing.T) {
	leaseExp := time.Now().Add(5 * time.Minute).UnixMilli()
	_, st := agentStatus(t, "sk_test", LicenseClaims{
		JTI:                "jti-1",
		Dep:                "dep-1",
		RequireOnlineLease: 1,
	}, &LeaseClaims{
		JTI:        "lease-1",
		EXP:        leaseExp,
		DepID:      "dep-1",
		LicenseJTI: "jti-other",
	})

	if _, err := st.VerifyOnline(VerifyConfig{}); err == nil {
		t.Fatal("expected a lease bound to another license to be rejected")
	}
}

func TestFetchAgentStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AgentStatus{
			DeploymentID: "dep-1",
			HasLicense:   true,
			Valid:        true,
			RawToken:     "a.b.c",
		})
	}))
	defer srv.Close()

	st, err := FetchAgentStatus(srv.URL)
	if err != nil {
		t.Fatalf("FetchAgentStatus: %v", err)
	}
	if st.DeploymentID != "dep-1" || !st.HasLicense || st.RawToken != "a.b.c" {
		t.Errorf("unexpected status: %+v", st)
	}
}

func TestFetchAgentStatus_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, err := FetchAgentStatus(srv.URL); err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
}

// A Verifier is the concurrency-safe alternative to the package-level key set:
// key rotation replaces keys while other goroutines verify.
func TestVerifier_ConcurrentRotationAndVerify(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubB, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	v := NewVerifier(map[string]ed25519.PublicKey{"sk_a": pubA})
	token := signJWS(t, privA, "sk_a", LicenseClaims{
		JTI: "jti-1",
		EXP: time.Now().Add(time.Hour).UnixMilli(),
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Rotate the key set while verifying. Under -race this catches the
	// unsynchronized-map write the package-level key set used to have.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				v.SetKeys(map[string]ed25519.PublicKey{"sk_a": pubA, "sk_b": pubB})
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Either outcome is fine; the point is that it does not race.
				_, _ = v.VerifyLicenseToken(token)
			}
		}()
	}

	close(stop)
	wg.Wait()

	if _, err := v.VerifyLicenseToken(token); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
}

func TestVerifier_SetKeysCopiesInput(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	input := map[string]ed25519.PublicKey{"sk_a": pub}
	v := NewVerifier(input)

	// Mutating the caller's map must not reach into the Verifier.
	delete(input, "sk_a")
	if _, err := v.lookup("sk_a"); err != nil {
		t.Fatalf("verifier should hold its own copy: %v", err)
	}
}

func TestVerifier_DefaultKeyFallbacksForAnyKid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v := &Verifier{}
	v.SetDefaultKey(pub)

	// One key means "this key verifies everything it signs", so an unstamped
	// kid still resolves — that is what keeps single-key callers working.
	token := signJWS(t, priv, "sk_anything", LicenseClaims{
		JTI: "jti-1",
		EXP: time.Now().Add(time.Hour).UnixMilli(),
	})
	if _, err := v.VerifyLicenseToken(token); err != nil {
		t.Fatalf("verify with default key fallback: %v", err)
	}
}

func TestVerifier_NoKeysIsAnError(t *testing.T) {
	v := &Verifier{}
	if _, err := v.VerifyLicenseToken("a.b.c"); err == nil {
		t.Fatal("expected a verifier with no keys to reject every token")
	}
}

func TestAgentStatus_JSONRoundTrip(t *testing.T) {
	// The wire shape is the contract between the agent and app replicas; a
	// renamed field silently breaks every consumer.
	raw, err := json.Marshal(AgentStatus{
		DeploymentID: "dep-1",
		HasLicense:   true,
		Valid:        true,
		Message:      "ok",
		RawToken:     "a.b.c",
		LeaseToken:   "d.e.f",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"deploymentId", "hasLicense", "valid", "message", "rawToken", "leaseToken"} {
		if _, ok := got[field]; !ok {
			t.Errorf("missing %q in %s", field, raw)
		}
	}

	// leaseToken must stay omitempty: an agent holding no lease should not
	// advertise an empty one.
	raw, err = json.Marshal(AgentStatus{DeploymentID: "dep-1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got2 map[string]any
	if err := json.Unmarshal(raw, &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got2["leaseToken"]; ok {
		t.Errorf("empty leaseToken should be omitted: %s", raw)
	}
}
