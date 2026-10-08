# license-sdk-go

Go client SDK for the Kodeart LicenseService — verify licenses offline, resolve
entitlements, and keep a deployment alive.

## Install

```bash
go get github.com/kodeart/license-sdk-go
```

## How integration works

A product app does **not** talk to the license-server. On each node a single
`license-agent` daemon owns the credential and keeps the licence fresh; the
app's replicas read the agent's local endpoint and verify the signed token
themselves:

```
license-server ──issues token──► license-agent (one per node)
                                     │ heartbeat, CRL, activation
                                     ▼
                                /status on 127.0.0.1:6100
                                     │
                                     ▼
                              app replicas (verify locally)
```

A replica holds no credentials and makes no outbound call, so it boots and
keeps running while the network is down. **The SDK owns all cryptography** —
signature, `exp`/`nbf` enforcement, `kid` routing, key rotation, deployment
binding. **The app owns the gate** — which modules exist, where they are
enforced, and what happens when verification fails.

`AgentStatus.Valid` is the agent's own opinion and is advisory; the app must
call `Verify` and treat its result as the only verdict (see
[Consuming the license-agent](#consuming-the-license-agent)).

## Quick start: gate a replica on its node

Bake the server's public keyring into the binary, own a `Verifier`, read the
agent, verify, and resolve entitlements:

```go
package myapp

import (
    "embed"
    "fmt"
    "log/slog"

    license "github.com/kodeart/license-sdk-go"
)

//go:embed keys/*.pub
var keys embed.FS

// newVerifier builds the process-wide, rotation-safe key set once at boot.
func newVerifier() (*license.Verifier, error) {
    ring, err := license.LoadKeyRing(keys) // kid = filename stem, e.g. sk_2026_09
    if err != nil {
        return nil, err
    }
    return license.NewVerifier(ring), nil
}

// entitlements returns the paid modules this replica may expose.
func entitlements(v *license.Verifier) (map[string]bool, error) {
    st, err := license.FetchAgentStatus(license.DefaultAgentAddr) // 127.0.0.1:6100
    if err != nil {
        return nil, fmt.Errorf("license agent unreachable: %w", err)
    }
    // ExpectedDep is filled from the agent's own deployment id, so a token
    // issued to another node is rejected without threading the value through.
    claims, err := v.VerifyAgentStatus(*st, license.VerifyConfig{ExpectedAud: "my-product"})
    if err != nil {
        return nil, fmt.Errorf("license invalid: %w", err)
    }
    res := claims.ResolveModules()
    if len(res.Filtered) > 0 {
        slog.Warn("licensed modules dropped for missing dependencies", "filtered", res.Filtered)
    }
    granted := make(map[string]bool, len(res.Codes))
    for _, code := range res.Codes {
        granted[code] = true
    }
    return granted, nil
}
```

Then apply `granted` at your gate — a REST/gRPC interceptor, a NATS publisher
allowlist, a readiness probe. For licences that mandate an online lease
(`require_online_lease`), call `v.VerifyAgentStatusOnline` instead; it
additionally requires a live, unexpired lease belonging to *this* licence:

```go
claims, err := v.VerifyAgentStatusOnline(*st, license.VerifyConfig{ExpectedAud: "my-product"})
```

`VerifyOnline` applies **no** grace period (neither does the agent, so the two
cannot disagree). If you want to honor the licence's grace, apply it yourself:
`lease.EXP + claims.GracePeriod`.

## What the app owns

Deliberately app-specific, because only the app knows its own module codes:

- **The module set.** Core (always built) and paid module codes.
- **Entitlements.** Resolving claims into "which modules exist", decided once
  at boot — a licence that gains or loses a module takes effect on restart.
- **Where the gate applies.** REST/gRPC interceptors, consumer startup, the
  NATS publisher allowlist, readiness.
- **Fail-open policy.** How long boot waits for the agent, and what happens
  when it never answers.

## Entitlements: `ResolveModules`

`claims.ResolveModules()` returns the modules actually usable given each
module's declared dependencies, and is the SDK's safety net that mirrors the
server's issuance-time validation:

```go
type ModuleResolution struct {
    Codes    []string // granted AND usable
    Filtered []string // granted but skipped: a dependency is not granted
}
```

- `Requires` (all listed codes must be granted) and `RequiresAny` (at least one
  must be granted) live on each `ModuleEntry`.
- Resolution runs to a fixpoint, so transitive requirements clear too.
- A module with no requirements is always usable.

**Migration caveat.** `requires` is `omitempty`, so tokens issued before this
field existed read as "no dependencies". Keep your own hardcoded dependency
fallback until every licence has been through a heartbeat — a stale token would
otherwise grant a module whose dependency is missing. The token is rebuilt on
every heartbeat, so this self-heals within one refresh interval; no reissue is
needed.

## Offline verification

Bake the server's Ed25519 public key in once, then verify tokens locally.
Verification is **strict**: the signature is checked against the key matching
the token's `kid`, and the token's `exp`/`nbf` are enforced against the current
time (with 30s skew). `err == nil` means the token is valid **right now**.

```go
license.SetPublicKey(serverPublicKey) // raw 32 bytes, e.g. from keys/sk_*.pub

claims, err := license.VerifyLicenseToken(token)
// claims.Seats, claims.Modules, claims.MaxDeployments, ...
```

Perpetual licenses (valid_to == 0) carry the far-future `PerpetualExpiryMS`
exp and never expire. Use `IsExpired`/`ValidUntil` to surface remaining
validity to users:

```go
claims, _ := license.VerifyLicenseToken(token)
if license.IsExpired(claims, time.Now()) { /* token lapsed */ }
// license.ValidUntil(claims) -> zero Time for perpetual
```

Binding is opt-in per field via `VerifyConfig`: `ExpectedAud` (product code),
`ExpectedDep` (deployment id) and `ExpectedIssuer` are each skipped when left
empty. Bind what you actually know.

## Key rotation

A product can rotate its signing key without breaking clients. Install the
server's current keys (all of them) via `SetPublicKeys`, keyed by the JWS
`kid`; the server also publishes them over the unauthenticated
`GetSigningKeys` RPC (`/v1/license/signing-keys`). Retired keys keep
validating old tokens until removed from the set.

`LoadKeyRing` reads the whole `keys/` directory straight into that map, keyed
by filename stem (`sk_2026_09.pub` → `kid "sk_2026_09"`), which is exactly how
the signer names keys. Baking the directory into a binary works via `embed.FS`,
so a consumer needs no key management code of its own:

```go
//go:embed keys/*.pub
var keys embed.FS

kr, err := license.LoadKeyRing(keys) // fs.FS: embed.FS or os.DirFS(...)
license.SetPublicKeys(kr)
```

`LoadKeyRingFile(dir)` is the path-based form for a keyring on disk, and
`LoadPublicKeyFile(path, kid)` reads a single raw 32-byte key.

```go
keys := map[string]ed25519.PublicKey{
    "kid-active":  activePub,
    "kid-retired": retiringPub,
}
license.SetPublicKeys(keys)
// tokens signed by either key verify; lookups are by kid header
```

Tokens without a `kid` header fall back to the default `license.PublicKey`
set via `SetPublicKey`. `AddPublicKey(kid, pk)` adds a single key to the set.

## Verifier (rotation-safe keys)

`SetPublicKeys` and friends write to one process-wide key set, so rotating a
key while another goroutine verifies is a data race. Use a `Verifier` for
anything long-lived — it owns its keys behind a mutex and takes a copy, so a
later change to your map cannot reach into it:

```go
v := license.NewVerifier(keys)
claims, err := v.VerifyLicenseTokenWithConfig(token, license.VerifyConfig{
    ExpectedAud: "my-product",
})
v.AddKey("kid-incoming", pub) // preload before the server rotates to it
```

A `Verifier` with a single default key (`SetDefaultKey`) resolves any `kid`,
which keeps one-key deployments working; a key set with two or more entries is
strict and rejects unknown `kid`s rather than checking a rotated token against
the wrong key.

## Consuming the license-agent

App replicas read the agent's local endpoint, which hands over the raw signed
token. A `Verifier` should own its own keyring (quick start above) and use its
status methods — these take the same arguments and verify against those keys:

```go
st, err := license.FetchAgentStatus(license.DefaultAgentAddr)
claims, err := v.VerifyAgentStatus(*st, license.VerifyConfig{ExpectedAud: "my-product"})

// For licences that require an online lease, use VerifyAgentStatusOnline instead:
// claims, err = v.VerifyAgentStatusOnline(*st, license.VerifyConfig{ExpectedAud: "my-product"})
```

`st.Verify`/`st.VerifyOnline` are the same calls on the package-level default
key set, which is what the agent and simple single-consumer tools want:

```go
st, err := license.FetchAgentStatus("http://127.0.0.1:6100")
claims, err := st.Verify(license.VerifyConfig{ExpectedAud: "my-product"})
```

`AgentStatus.Valid` is the agent's own opinion and is deliberately ignored by
`Verify` — an agent with no public key of its own reports false while still
handing over a perfectly good token. Use `Valid` and `Message` only for
operator-facing diagnostics.

`ParseLicenseToken`/`ParseLeaseToken` decode claims without verifying the
signature and without enforcing time — use them to inspect a token before
deciding how to verify it.

## Building the agent / direct server client

Only the **agent** (or a single embedded tool) uses the gRPC client — app
replicas never do. `NewClient` dials the LicenseService, retrying until the
connection is ready (up to ~15s of backoff):

```go
import (
    license "github.com/kodeart/license-sdk-go"
)

cli, err := license.NewClient(license.ClientConfig{
    GrpcAddress: "license.kodeart.com:50053",
    ServerName:  "license.kodeart.com", // TLS SNI / authority override
    Insecure:    false,                 // plaintext for dev only
})
if err != nil {
    panic(err)
}
defer cli.Close()
```

### Activation

The activation code **is** the credential for the first call — the SDK sends it
as the `x-deployment-api-key` header. On success the server returns a dedicated
deployment API key; persist it (and the deployment id) and use it from then on:

```go
resp, err := cli.Activate(ctx, activationCode, fingerprint, productCode, hostname)
// resp.DeploymentApiKey, resp.DeploymentId, resp.LicenseToken, ...
```

### Deployment lifecycle

Swap to the returned key for every subsequent call, then run the refresh loops:

```go
cli.Config.DeploymentAPIKey = resp.DeploymentApiKey

hb, err := cli.Heartbeat(ctx, licenseToken, leaseToken, fingerprint, lastCRLSeq)
lic, err := cli.FetchLicense(ctx, deploymentID)
crl, err := cli.GetCRL(ctx, sinceSequenceID)
n,   err := cli.ReportUsage(ctx, deploymentID, metrics...)
```

The `license-agent` already wires all of this together — activation, persisted
state, heartbeat/CRL loops, and the local endpoint. Run it per node rather than
embedding these calls. Agent configuration lives in its own environment file
(`deploy/license-agent.env`).

## Configuration

Every `ClientConfig` option is configurable from the environment with
`godotenv` + `env.ParseAs`:

```go
import (
    "github.com/caarlos0/env/v11"
    "github.com/joho/godotenv"
    license "github.com/kodeart/license-sdk-go"
)

func loadClient() (*license.Client, error) {
    _ = godotenv.Load() // optional; loads .env if present
    cfg, err := env.ParseAs[license.ClientConfig]()
    if err != nil {
        return nil, err
    }
    return license.NewClient(cfg)
}
```

| Env var | Default | Description |
|---|---|---|
| `LICENSE_GRPC_ADDRESS` | — (**required**) | `host:port` of the LicenseService (e.g. `license.kodeart.com:50053`) |
| `LICENSE_SERVER_NAME` | `""` | TLS/SNI override when the endpoint is fronted by a proxy or load balancer; also sets the gRPC `:authority` |
| `LICENSE_INSECURE` | `false` | Dial with plaintext, no TLS. Dev/staging only |
| `LICENSE_DEPLOYMENT_API_KEY` | `""` | Deployment credential sent as `x-deployment-api-key` on every RPC. Empty = no header |

`ConnectTimeout` and `KeepaliveTime` (dial timeout, 3s; keepalive interval,
20s) default sensibly and are only settable in code. Dialing is blocking:
`NewClient` waits until the connection is `READY`, retrying with backoff up
to ~15s instead of failing on the first try.
