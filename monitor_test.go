package license

import (
	"context"
	"crypto/ed25519"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	licensev1 "github.com/kodeart/license-sdk-go/proto/license/v1"
	"google.golang.org/grpc"
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

// leaseStatus builds an AgentStatus carrying a token that requires an online
// lease, along with a lease token expiring at leaseExp.
func leaseStatus(t *testing.T, priv ed25519.PrivateKey, dep string, licExp, leaseExp time.Time, modules []ModuleEntry) AgentStatus {
	t.Helper()
	claims := LicenseClaims{
		JTI:                "jti-" + dep,
		Aud:                "my-product",
		Dep:                dep,
		TenantModel:        "single",
		LicensingModel:     "module_based",
		EXP:                licExp.UnixMilli(),
		RequireOnlineLease: 1,
		Modules:            modules,
	}
	token := signJWS(t, priv, "kid-1", claims)
	lease := LeaseClaims{
		Sub:        claims.JTI,
		JTI:        "lease-" + dep,
		EXP:        leaseExp.UnixMilli(),
		DepID:      dep,
		LicenseJTI: claims.JTI,
	}
	return AgentStatus{
		DeploymentID: dep,
		HasLicense:   true,
		Valid:        true,
		RawToken:     token,
		LeaseToken:   signJWS(t, priv, "kid-1", lease),
	}
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

func TestMonitor_LeaseExpiryFlipsLivenessWithoutNewStatus(t *testing.T) {
	v, priv := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{ExpectedAud: "my-product"}, []string{"core"})

	licExp := time.Now().Add(24 * time.Hour)
	// The lease lapses ~1s after apply, inside the clock-skew window, so it
	// verifies now but expires while the monitor holds the same status.
	leaseExp := time.Now().Add(-clockSkew + time.Second)
	if _, err := m.ApplyStatus(leaseStatus(t, priv, "dep-a", licExp, leaseExp, []ModuleEntry{{Code: "root"}})); err != nil {
		t.Fatalf("apply live-lease status: %v", err)
	}
	if !m.Licensed("root") {
		t.Fatal("Licensed(root) should be true while the lease is live")
	}

	// Wait past leaseExp+skew: liveness must flip without an ApplyStatus call.
	time.Sleep(time.Second)
	if m.Licensed("root") {
		t.Error("Licensed(root) = true after the lease lapsed — the lease must be re-checked on read")
	}
	if m.Valid() {
		t.Error("Valid() = true after the lease lapsed")
	}
	if s := m.Set(); len(s) != 1 || !s["core"] {
		t.Errorf("Set()=%v, want exactly {core} after the lease lapsed", s)
	}

	// A fresh status carrying a renewed lease restores entitlement.
	if _, err := m.ApplyStatus(leaseStatus(t, priv, "dep-a", licExp, time.Now().Add(5*time.Minute), []ModuleEntry{{Code: "root"}})); err != nil {
		t.Fatalf("apply renewed lease: %v", err)
	}
	if !m.Licensed("root") {
		t.Error("Licensed(root) = false after a renewed lease — entitlement must recover")
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

// countingAgentServer accepts a Watch stream, counts the connect, and ends the
// stream immediately without sending anything — the "accept then drop" server
// that used to spin WatchAgentStatus with no delay.
type countingAgentServer struct {
	licensev1.UnimplementedLicenseAgentServer
	calls atomic.Int64
}

func (s *countingAgentServer) Watch(_ *licensev1.WatchRequest, stream grpc.ServerStreamingServer[licensev1.AgentStatus]) error {
	s.calls.Add(1)
	return nil
}

func TestWatchAgentStatus_BacksOffWhenStreamEndsImmediately(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fake := &countingAgentServer{}
	licensev1.RegisterLicenseAgentServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	v, _ := newTestVerifier(t)
	m := NewMonitor(v, VerifyConfig{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = WatchAgentStatus(ctx, m, AgentClientConfig{Address: lis.Addr().String()})
	}()

	// Let the loop run long enough that an unthrottled reconnect storm would
	// issue thousands of calls, then stop it.
	time.Sleep(1200 * time.Millisecond)
	cancel()
	<-done

	n := fake.calls.Load()
	if n == 0 {
		t.Fatal("expected at least one Watch call")
	}
	// With exponential backoff (500ms, 1s, 2s, ...) ~1.2s admits only a handful
	// of attempts. The bound is generous to stay non-flaky on slow CI while
	// still failing loudly if the sleep is ever dropped again.
	if n > 10 {
		t.Fatalf("Watch called %d times in ~1.2s; reconnect loop is not backing off", n)
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
