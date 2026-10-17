package license

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ModuleEvent describes how the usable (paid) module set changed between two
// applied agent statuses. Core modules never appear in an event — they are
// constant by definition. Each code appears in exactly one slice; the order of
// Added matches the license token, the order of Removed matches the previous
// resolution.
type ModuleEvent struct {
	Added     []string
	Removed   []string
	Unchanged []string
}

// Monitor is a concurrency-safe, live view of "what am I entitled to right
// now". Feed it every agent status (ApplyStatus; or WatchAgentStatus owns the
// stream for you) and it re-verifies the token and recomputes the module
// resolution on every call, so a license that gains or loses a module takes
// effect on the next status — not on restart. It is the counterweight to
// resolving entitlements once at boot and freezing them.
//
// Read the state from any goroutine: middleware calls Licensed to 403 per
// module, /api/modules-style surfaces read Codes/Set, and OnModuleChange lets
// a consumer rebuild its module-dependent wiring (route tables, publisher
// allowlists) when the granted set changes.
//
// The Monitor is the enforcement answer, not the policy source. It applies no
// grace period and no fail-open: an expired token or a lapsed online lease
// drops the paid modules immediately and Valid turns false. Whether to honor a
// grace window, wait at boot for the agent, or keep serving core while the
// license is invalid is the app's call — see README, "What the app owns".
type Monitor struct {
	v   *Verifier
	cfg VerifyConfig

	coreList []string
	coreSet  map[string]struct{}

	mu       sync.RWMutex
	claims   *LicenseClaims    // last successfully verified claims; nil before any success or after a failure
	leaseExp int64             // exp (ms) of the last verified online lease; 0 when none is required
	res      ModuleResolution  // last successful resolution
	lastErr  error             // error from the most recent ApplyStatus, if any
	change   func(ModuleEvent) // invoked outside the lock, only when the module set changed
}

// NewMonitor wraps a Verifier (which owns the public keyring) into a live
// entitlement tracker. cfg is passed as-is to verification (opt-in binding
// checks only). coreCodes are the app's always-built modules: they are always
// Licensed and never appear in a ModuleEvent. Only the app knows its own core
// set, so the SDK refuses to guess it.
func NewMonitor(v *Verifier, cfg VerifyConfig, coreCodes []string) *Monitor {
	m := &Monitor{v: v, cfg: cfg, coreSet: make(map[string]struct{}, len(coreCodes))}
	for _, code := range coreCodes {
		if _, ok := m.coreSet[code]; ok {
			continue
		}
		m.coreSet[code] = struct{}{}
		m.coreList = append(m.coreList, code)
	}
	return m
}

// ApplyStatus verifies st (signature, time, binding, and — for licenses that
// require one — the online lease) and recomputes the module resolution. On
// success it records the claims and returns a ModuleEvent describing how the
// paid set changed since the previous successful apply; the event's Added is
// empty only when nothing changed. On failure it records the error and fails
// closed: claims are cleared, Valid turns false and only core codes remain
// Licensed — no event is fired, because no authoritative module set exists.
//
// The online-lease path is used unconditionally because it is a strict
// superset: a license that does not require a lease verifies identically to
// the plain path, and one that does is enforced live.
//
// The verification error is returned to the caller and available later via
// Err, so a Watch loop can log it without aborting the stream.
func (m *Monitor) ApplyStatus(st AgentStatus) (ModuleEvent, error) {
	claims, lease, err := m.v.verifyAgentStatusOnlineAt(st, m.cfg, time.Now())

	m.mu.Lock()
	m.lastErr = err
	if err != nil {
		m.claims = nil
		m.leaseExp = 0
		m.res = ModuleResolution{}
		m.mu.Unlock()
		return ModuleEvent{}, err
	}
	res := claims.ResolveModules()
	ev := diffModuleSets(m.res.Codes, res.Codes)
	m.claims = claims
	m.leaseExp = 0
	if lease != nil {
		m.leaseExp = lease.EXP
	}
	m.res = res
	cb := m.change
	m.mu.Unlock()

	if cb != nil && (len(ev.Added) > 0 || len(ev.Removed) > 0) {
		cb(ev)
	}
	return ev, nil
}

// Valid reports whether the last successfully verified token is valid right
// now. It is recomputed on every read (exp/nbf against the current time with
// the same clock skew as verification), so an expiring token flips the monitor
// to invalid without needing a new status. False when nothing has verified yet
// or the last ApplyStatus failed.
func (m *Monitor) Valid() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validLocked(time.Now())
}

func (m *Monitor) validLocked(now time.Time) bool {
	if m.claims == nil || checkTime(m.claims.EXP, m.claims.NBF, now) != nil {
		return false
	}
	// Re-check the online lease on every read, not just when a status arrives:
	// once the lease lapses the entitlement is gone even if the license token
	// itself is still within its validity window. leaseExp == 0 means the
	// license requires no lease, which checkTime treats as unconstrained.
	return checkTime(m.leaseExp, 0, now) == nil
}

// Licensed is the per-module enforcement primitive: a core code is always
// true; a paid module is true only while the token verifies right now AND the
// module survived resolution. A 403 middleware gates each request on it, so
// enforcement follows every transition — a module gain, a loss, an expiry —
// without a restart.
func (m *Monitor) Licensed(code string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.coreSet[code]; ok {
		return true
	}
	if !m.validLocked(time.Now()) {
		return false
	}
	for _, c := range m.res.Codes {
		if c == code {
			return true
		}
	}
	return false
}

// Codes returns the modules usable right now: all core codes plus the paid
// codes that are currently licensed and valid. It is the "what can I expose
// this instant" snapshot for /api/modules-style surfaces, readiness probes and
// per-request allowlists.
func (m *Monitor) Codes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.coreList)+len(m.res.Codes))
	copy(out, m.coreList)
	if m.validLocked(time.Now()) {
		copy(out[len(m.coreList):], m.res.Codes)
	}
	return out
}

// Set returns Codes as a set.
func (m *Monitor) Set() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]bool, len(m.coreList)+len(m.res.Codes))
	if m.validLocked(time.Now()) {
		for _, c := range m.res.Codes {
			out[c] = true
		}
	}
	for _, c := range m.coreList {
		out[c] = true
	}
	return out
}

// Resolution returns the last successful module resolution, including modules
// the license granted but which were filtered because a dependency was missing
// (res.Filtered). Unlike Codes it reflects the license, not the current
// instant: it does not expire paid modules and is the raw view for an
// operator-facing module list. Do not mutate the returned slices.
func (m *Monitor) Resolution() ModuleResolution {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.res
}

// Claims returns the last successfully verified claims, or nil when nothing
// has verified yet or the last ApplyStatus failed. Do not mutate the result.
func (m *Monitor) Claims() *LicenseClaims {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.claims
}

// Err returns the error recorded by the most recent ApplyStatus, nil when the
// last apply succeeded or none ran yet.
func (m *Monitor) Err() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

// OnModuleChange registers fn to be called whenever the paid module set
// changes between two successful applies. The first successful apply reports
// the whole granted set as Added, so a consumer that registers before starting
// to watch converges on the initial set. Registering again replaces the
// previous callback. fn is invoked outside the Monitor's lock, so it may call
// back into the Monitor; it must not block.
func (m *Monitor) OnModuleChange(fn func(ModuleEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.change = fn
}

// WatchAgentStatus owns the agent status stream for a Monitor: it dials cfg,
// takes Watch's initial status and every change, applies each to m, and
// reconnects with exponential backoff when the stream breaks. It returns only
// when ctx is cancelled. Verification failures are recorded on the Monitor
// (Err) and do not abort the stream. This is the loop an app replica would
// otherwise rewrite per consumer; the Monitor is safe to read while it runs.
func WatchAgentStatus(ctx context.Context, m *Monitor, cfg AgentClientConfig) error {
	client, err := NewAgentClient(cfg)
	if err != nil {
		return fmt.Errorf("license sdk: watch agent status: %w", err)
	}
	defer func() { _ = client.Close() }()

	const (
		backoffStart = 500 * time.Millisecond
		backoffMax   = 8 * time.Second
	)
	delay := backoffStart

	for ctx.Err() == nil {
		stream, err := client.Watch(ctx)
		if err != nil {
			if !sleepCtx(ctx, delay) {
				return ctx.Err()
			}
			delay = min(2*delay, backoffMax)
			continue
		}

		// Drain the stream until it breaks, then reconnect. A stream that ends
		// after delivering at least one status was healthy, so the backoff is
		// reset; one that breaks immediately grows it. Sleeping before every
		// reconnect is what stops a server that accepts then drops the stream
		// from spinning this loop, since Watch() itself succeeds in that case.
		healthy := false
		for {
			st, err := stream.Recv()
			if err != nil {
				break
			}
			_, _ = m.ApplyStatus(st) // failure is recorded on the monitor via Err
			healthy = true
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if healthy {
			delay = backoffStart
		}
		if !sleepCtx(ctx, delay) {
			return ctx.Err()
		}
		delay = min(2*delay, backoffMax)
	}
	return ctx.Err()
}

// sleepCtx sleeps d unless ctx is cancelled, returning false when cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// diffModuleSets compares two code lists and reports what moved. Order is
// preserved: after's order for Added/Unchanged, before's for Removed.
func diffModuleSets(before, after []string) ModuleEvent {
	afterSet := make(map[string]struct{}, len(after))
	for _, c := range after {
		afterSet[c] = struct{}{}
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, c := range before {
		beforeSet[c] = struct{}{}
	}

	ev := ModuleEvent{}
	for _, c := range after {
		if _, ok := beforeSet[c]; ok {
			ev.Unchanged = append(ev.Unchanged, c)
		} else {
			ev.Added = append(ev.Added, c)
		}
	}
	for _, c := range before {
		if _, ok := afterSet[c]; !ok {
			ev.Removed = append(ev.Removed, c)
		}
	}
	return ev
}
