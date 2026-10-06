# license-sdk-go

Go client SDK for the Kodeart LicenseService — validate licenses offline,
redeem activation codes, and keep a deployment alive.

## Install

```bash
go get github.com/kodeart/license-sdk-go
```

## Usage

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

### Offline verification

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

### Key rotation

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

### Verifier (rotation-safe keys)

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

### Consuming the license-agent

App replicas on a licensed node don't talk to the license-server: they read the
agent's local endpoint, which hands over the raw signed token. `FetchAgentStatus`
gets it and `AgentStatus.Verify` decides, binding `dep` to the agent's own
deployment id automatically:

```go
st, err := license.FetchAgentStatus("http://127.0.0.1:6100")
claims, err := st.Verify(license.VerifyConfig{ExpectedAud: "my-product"})
```

`AgentStatus.Valid` is the agent's own opinion and is deliberately ignored by
`Verify` — an agent with no public key of its own reports false while still
handing over a perfectly good token.

For licences with `require_online_lease`, use `VerifyOnline`. It additionally
requires a live lease belonging to *this* licence, so a consumer enforces lease
liveness itself rather than trusting the agent's verdict:

```go
claims, err := st.VerifyOnline(license.VerifyConfig{ExpectedAud: "my-product"})
```

`st.Verify` and `st.VerifyOnline` read the package-level default key set, which
is what the agent and simple single-consumer tools want. A process holding its
own keyring should own a `Verifier` and use its methods instead, which take the
same arguments and verify against those keys:

```go
v := license.NewVerifier(ring)
claims, err := v.VerifyAgentStatusOnline(*st, license.VerifyConfig{ExpectedAud: "my-product"})
```

`ParseLicenseToken`/`ParseLeaseToken` decode claims without verifying the
signature and without enforcing time — use them to inspect a token before
deciding how to verify it.

### Activation

```go
resp, err := cli.Activate(ctx, activationCode, fingerprint, productCode, hostname)
// resp.DeploymentApiKey, resp.DeploymentId, resp.LicenseToken, ...
```

Persist the returned deployment API key and ID; use them for every subsequent
call. After a successful activation, set `cli.Config.DeploymentAPIKey`:

### Deployment lifecycle

```go
cli.Config.DeploymentAPIKey = resp.DeploymentApiKey

hb, err := cli.Heartbeat(ctx, licenseToken, leaseToken, fingerprint, lastCRLSeq)
lic, err := cli.FetchLicense(ctx, deploymentID)
crl, err := cli.GetCRL(ctx, sinceSequenceID)
n,   err := cli.ReportUsage(ctx, deploymentID, metrics...)
```

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