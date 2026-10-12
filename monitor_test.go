package license

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"
)

// newTestVerifier returns a Verifier over a freshly generated key.
func newTestVerifier(t *testing.T) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewVerifier(map[string]ed25519.PublicKey{"kid-1": pub}), priv
}

// licenseStatus builds an AgentStatus carrying a token signed with priv for the
// given modules. Pass exp to control expiry for liveness tests.
func licenseStatus(t *testing.T, priv ed25519.PrivateKey, dep string, exp time.Time, modules []ModuleEntry) AgentStatus {
	t.Helper()
	claims := LicenseClaims{
		JTI:                "jti-x",
		Aud:                "my-product",
		Dep:                dep,
		TenantModel:        "single",
		LicensingModel:     "module_based",
		EXP:                exp.UnixMilli(),
		RequireOnlineLease: 0,
		Modules:            modules,
	}
	claims.JTI = "jti-" + dep + "-" + exp.Format("150405")
	token := signJWS(t, priv, "kid-1", claims)
	return AgentStatus{DeploymentID: dep, HasLicense: true, Valid: true, RawToken: token}
}

func TestMonitor_GainLossFiresModuleEvent(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{ExpectedAud: "my-product"}, []string{"core"})

	var mu sync.Mutex
	var got []ModuleEvent
	m.OnModuleChange(func(ev ModuleEvent) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ev)
	})

	// First apply: entire granted set is Added.
	future := time.Now().Add(24 * time.Hour)
	ev, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{
		{Code: "root"},
		{Code: "retail"},
	}))
	if err != nil {
		t.Fatalf("ApplyStatus: %v", err)
	}
	if !sameStrings(ev.Added, []string{"root", "retail"}) {
		t.Errorf("first apply Added=%v, want [root retail]", ev.Added)
	}
	if len(ev.Removed) != 0 {
		t.Errorf("first apply Removed=%v, want none", ev.Removed)
	}

	// Gain: a module appears while the license stays valid.
	ev, err = m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{
		{Code: "root"},
		{Code: "retail"},
		{Code: "finma"},
	}))
	if err != nil {
		t.Fatalf("ApplyStatus (gain): %v", err)
	}
	if !sameStrings(ev.Added, []string{"finma"}) {
		t.Errorf("gain Added=%v, want [finma]", ev.Added)
	}

	// Loss: a module disappears.
	ev, err = m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{
		{Code: "root"},
	}))
	if err != nil {
		t.Fatalf("ApplyStatus (loss): %v", err)
	}
	if !sameStrings(ev.Removed, []string{"retail", "finma"}) {
		t.Errorf("loss Removed=%v, want [retail finma]", ev.Removed)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("OnModuleChange fired %d times, want 3 (first, gain, loss)", len(got))
	}
}

func TestMonitor_UnchangedReissueFiresNothing(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{ExpectedAud: "my-product"}, nil)

	future := time.Now().Add(24 * time.Hour)
	if _, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{{Code: "root"}})); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	fired := false
	m.OnModuleChange(func(ModuleEvent) { fired = true })
	// Same modules, different jti — a reissue that changes nothing else.
	ev, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{{Code: "root"}}))
	if err != nil {
		t.Fatalf("reissue apply: %v", err)
	}
	if len(ev.Added) != 0 || len(ev.Removed) != 0 {
		t.Errorf("unchanged reissue event=%+v, want no added/removed", ev)
	}
	if !sameStrings(ev.Unchanged, []string{"root"}) {
		t.Errorf("Unchanged=%v, want [root]", ev.Unchanged)
	}
	if fired {
		t.Error("OnModuleChange fired on an unchanged module set")
	}
}

func TestMonitor_FailClosesOnInvalidToken(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{ExpectedAud: "my-product"}, []string{"core"})

	future := time.Now().Add(24 * time.Hour)
	if _, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{{Code: "root"}})); err != nil {
		t.Fatalf("apply healthy token: %v", err)
	}

	// A token signed by the wrong key must fail closed.
	_, roguePriv, _ := ed25519.GenerateKey(nil)
	rogue := licenseStatus(t, roguePriv, "dep-a", future, []ModuleEntry{{Code: "root"}})
	if _, err := m.ApplyStatus(rogue); err == nil {
		t.Fatal("expected error for token signed by wrong key")
	}
	if m.Valid() {
		t.Error("Valid() = true after a failed apply")
	}
	if m.Licensed("root") {
		t.Error("Licensed(root) = true after a failed apply")
	}
	if !m.Licensed("core") {
		t.Error("Licensed(core) = false — core must stay granted regardless of license state")
	}
	if s := m.Set(); len(s) != 1 || !s["core"] {
		t.Errorf("Set()=%v, want exactly {core}", s)
	}
	if m.Err() == nil {
		t.Error("Err() = nil after a failed apply")
	}
	if m.Claims() != nil {
		t.Error("Claims() retained after a failed apply — must clear")
	}
}

func TestMonitor_ExpiryFlipsLivenessWithoutNewStatus(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{ExpectedAud: "my-product"}, nil)

	// exp sits just inside the clock-skew window and lapses ~1s after the
	// apply, so the token verifies now but expires while we hold it.
	short := time.Now().Add(-clockSkew + time.Second)
	if _, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", short, []ModuleEntry{{Code: "root"}})); err != nil {
		t.Fatalf("apply near-expiring token: %v", err)
	}
	if !m.Licensed("root") {
		t.Fatal("Licensed(root) should be true before expiry")
	}

	// Wait past exp+skew: liveness must flip without an ApplyStatus call.
	time.Sleep(time.Second)
	if m.Licensed("root") {
		t.Error("Licensed(root) = true after exp — must flip live")
	}
	if m.Valid() {
		t.Error("Valid() = true after exp")
	}
	if s := m.Set(); len(s) != 0 {
		t.Errorf("Set()=%v, want empty after expiry", s)
	}
}

func TestMonitor_CoreAlwaysAndResolution(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{}, []string{"core-a", "core-b"})

	future := time.Now().Add(24 * time.Hour)
	// "finma" requires "root" which is missing and is granted.
	if _, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, []ModuleEntry{
		{Code: "root"},
		{Code: "finma", Requires: []string{"root"}},
		{Code: "orphan", Requires: []string{"missing"}},
	})); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if !m.Licensed("core-a") || !m.Licensed("core-b") {
		t.Error("core codes must always be Licensed")
	}
	if !m.Licensed("finma") {
		t.Error("finma (dep satisfied) should be Licensed")
	}
	if m.Licensed("orphan") {
		t.Error("orphan (dep missing) must not be Licensed")
	}
	if !sameStrings(m.Codes(), []string{"core-a", "core-b", "root", "finma"}) {
		t.Errorf("Codes()=%v", m.Codes())
	}
	res := m.Resolution()
	if !sameStrings(res.Codes, []string{"root", "finma"}) {
		t.Errorf("Resolution.Codes=%v, want [root finma]", res.Codes)
	}
	if !sameStrings(res.Filtered, []string{"orphan"}) {
		t.Errorf("Resolution.Filtered=%v, want [orphan]", res.Filtered)
	}
}

func TestMonitor_ConcurrentReadWrite(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{}, []string{"core"})

	done := make(chan struct{})
	var wg sync.WaitGroup

	// One writer applying alternating module sets.
	wg.Add(1)
	go func() {
		defer wg.Done()
		future := time.Now().Add(24 * time.Hour)
		base := []ModuleEntry{{Code: "root"}}
		for i := 0; i < 100; i++ {
			mods := base
			if i%2 == 0 {
				mods = append(mods, ModuleEntry{Code: "retail"})
			}
			if _, err := m.ApplyStatus(licenseStatus(t, priv, "dep-a", future, mods)); err != nil {
				t.Errorf("concurrent apply: %v", err)
			}
		}
		close(done)
	}()

	// Many readers hammer the read paths.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = m.Licensed("root")
				_ = m.Licensed("retail")
				_ = m.Valid()
				_ = m.Codes()
				_ = m.Set()
				_ = m.Resolution()
				_ = m.Err()
			}
		}()
	}

	wg.Wait()
}
