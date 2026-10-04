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