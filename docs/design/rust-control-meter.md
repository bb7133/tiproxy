# Native metering implementation checkpoint

The native consumer/outbox, gzip envelope, LocalFS exporter, export worker, and
WAL sampler and configured storage factory are implemented. The binary still selects the existing Go owner.
CP-METER qualification remains pending until all storage/configuration and
process-lifecycle paths have completed integration and independent review.

## Cloud storage increment

`control-meter::cloud_store::CloudStore` signs S3, OSS V4, COS and Azure Blob HEAD/PUT
requests. An existing object, failed HEAD, rejected PUT, timeout or ambiguous
upload retains the outbox window. Object prefixes and gzip bodies remain intact.
Temporary session tokens are passed with the request. OS TLS roots are added
only to the metering client; other clients' explicit CA trust stays unchanged.
Errors expose fixed classes, not service URLs, headers, response bodies or keys.
Credential file, HTTP response and command output reads have a 4 MiB bound.

AWS and OSS use maintained reqsign source providers and signing primitives with
native role/cache adapters. AWS uses the Go 900-second POST request and a stable
`aws-go-sdk-{UnixNano}` session name, applies custom BaseEndpoint to STS, and caches
until actual expiration (no additional reqsign freshness margin). OSS uses the
pinned regional STS endpoint map, POST/query HMAC-SHA1, a 3600-second request and
`oss-sdk-session-{UnixSeconds}`. Its role cache refreshes 15 minutes before expiry;
refresh errors are returned even while the old credentials remain unexpired.
Configured OSS static keys use access_key semantics for STS, which ignore the
configured SessionToken; direct OSS writes retain it. A five-minute OSS background
refresh starts only after a first token exists and ignores its own refresh errors,
as Go does. The maintenance future is polled alongside all exports and dropped
with the Meter worker, bounding cancellation without an orphaned task.

Actual Go SDK captures verify three AWS endpoint/body cases and two OSS signed
requests (including complete HMACs). AWS's generated session is normalized in
its fixture; OSS timestamp/nonce are captured and reused by the comparison, so
regenerating that fixture changes the recorded signature. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/assume-role-go.go
```

COS adapts the pinned Go SDK's source
precedence (env, TKE, profile, CVM), caches the selected source, and provides its
missing AssumeRole flow. The two-hour role refresh starts before expiration;
a failed refresh may reuse an unexpired credential, never an expired one.
COS's one-hour signature header does not require an additional whole hour of
temporary credential validity. Malformed configured COS credentials stop the
chain rather than silently changing identity. The pinned Go env provider ignores
the token environment variable; explicit configured session tokens still work.

Focused cloud tests exercise real local HTTP HEAD/PUT, key escaping,
session tokens, existing/denied objects, AWS/OSS role replacement and caching,
COS profile/CVM/TKE sources, and role refresh failure/expiration. S3 endpoint/bucket addressing also matches nine
actual Go SDK requests (default/custom/path style/IP/dotted/non-DNS names).
COS STS TC3 signatures match a request produced by the pinned Go Tencent SDK. Regenerate its
fixture from the repository root with:

```sh
go run rust/crates/control-meter/testdata/cos-sts-go.go
```

Azure SharedKey signatures match actual HEAD/PUT requests from the pinned Go
azblob SDK. This proves signature canonicalization; Azure treats the Go SDK
URL escaped blob separators and Rust literal separators as the same blob.
SharedKey takes precedence over SAS; SAS query strings survive
container/prefix/key assembly. A metering-specific transport and bounded command
executor serve the official Azure identity SDK. Environment secret, encrypted
PEM/PFX certificate, username/password, workload assertion, managed identity, CLI,
Developer CLI and PowerShell sources compose the default chain.
`AZURE_TOKEN_CREDENTIALS` selects the chain, configured environment/workload
failure stops it, and the first successful source remains selected. Workload
assertion files use the bounded credential reader. Tests cover SharedKey/SAS HTTP
writes, identity selection/failure/cache, and certificate format/password handling.
Regenerate the Azure request fixture with:

```sh
go run rust/crates/control-meter/testdata/azure-shared-key-go.go
```

Managed identity now implements the pinned Go source selection for IMDS, App
Service, Azure ML, Cloud Shell, Service Fabric and Azure Arc. Nine actual Go SDK
request captures cover these sources, user identity selection, and the IMDS probe
used only when DefaultAzureCredential selects more than the managed credential.
The adapter preserves source-specific methods, query names/versions and secret
headers. Arc supports the Linux token directory, `.key` extension and 4096-byte
limit before using the challenge key in a sensitive Basic header. Windows Arc
(the other Go platform) is outside this Linux dataplane target; other platforms
reject the challenge as Go does. This is local protocol coverage, not
live cloud acceptance.

Only unavailable managed identity permits trying a later default-chain source:
IMDS probe failure, malformed IMDS token JSON, system-assigned IMDS 400, and
403 containing `unreachable`. User-assigned 400 and other authentication failures
stop the chain. Unsupported user-assigned source constructors are skipped, as
Go's unavailable error reporters are. The first successful source stays selected.
The five-minute MSAL cache validity margin, server `refresh_in` refresh/fallback,
retry status sets, jittered backoff and Retry-After precedence/cap are retained.
The synthetic half-life returned by Go MSAL is assigned after `cache.Write`, so
the outer BearerPolicy calls the credential at half-life, but MSAL returns the
same cached token without metadata HTTP and with zero `RefreshOn`. Subsequent
outer refresh uses the five-minute rule. The actual Go end-to-end probe below
forces only the outer timestamp and verifies two credential calls, one metadata
HTTP call and unchanged token/expiration (it waits for azcore's 30-second refresh
backoff). Empty or already expired tokens are rejected more strictly than Go
MSAL; malformed IMDS replies are classified unavailable. Outer credential I/O
and metering upload deadlines still bound all work.

Regenerate managed identity request fixtures with:

```sh
go run rust/crates/control-meter/testdata/azure-managed-go.go
go run rust/crates/control-meter/testdata/azure-managed-cache-go.go
```

Full default-credential/endpoint edge parity and binary ownership handoff remain
in progress. Provider retry-policy and default-chain edge comparisons remain
open; the AWS STS adapter currently makes one bounded attempt and export failure
retains the pending window for the next metering attempt.

This checkpoint rejects endpoint userinfo/fragment, non-Azure endpoint queries,
and object keys with dot path segments because the HTTP URL implementation would
normalize their identity. Azure endpoint/SAS queries are preserved. These edges
must be reconciled with Go before declaring the provider contract complete.

## Factory and disabled billing

`control-meter::service::Service` selects LocalFS/S3/OSS/COS/Azure from the typed,
restart-pinned config. Empty type **or** empty bucket disables billing, including
LocalFS, matching `NewMeter`. Disabled mode opens only the absolute consumer:
baselines, diagnostics, deduplication and pending clearing still persist before
WAL ACK, while any existing outbox remains untouched. Enabling later still checks
the outbox checkpoint; it cannot silently reset an already advanced consumer.
An absent LocalFS subsection retains the SDK's `create-dirs=true` default, while
an explicitly present empty subsection retains false. Unsupported enabled
providers fail before durable state creation.

The native WAL sampler accepts a common in-process intake interface. Both enabled
and disabled services preserve the same producer ACK contract. The process must
stop sessions, join the sampler's final sample, stop/join the service, then retire
ownership. Factory file opens and LocalFS directory setup run on the blocking pool.
Actual Go/Rust observations cover fresh disabled intake and discarding preexisting
Go pending deltas without changing its outbox. Native fault tests also cover final
WAL ACK, shutdown rejection, corruption, retirement and enabled checkpoint mismatch.

## Dependency policy

The global duplicate-version denial and empty advisory ignore list remain.
The reviewed signing libraries require exact duplicate exceptions for
`base64 0.23.1` (the existing TLS/tonic graph uses 0.22) and `hashbrown 0.14.5`
(rust-ini's ordered-multimap; the existing graph uses 0.17). Only
`tiny-keccak 2.0.2` receives a CC0-1.0 license allowance for the profile parser's
build dependency. These are package/version-scoped, not whole-tree exceptions.
Cargo deny bans/licenses and cargo audit pass for this dependency graph.

The Azure identity SDK also requires exact duplicate exceptions for
`getrandom 0.3.4`, `getrandom 0.4.3`, `rand 0.9.5` and `rand_core 0.9.5`:
its typespec transport uses rand 0.9/getrandom 0.3, while its current UUID library
uses getrandom 0.4; existing TLS and signers use getrandom 0.2/rand 0.10.
OpenSSL is used for Azure certificate parsing/signing and built from the locked
vendored source. A C compiler, make and Perl are build prerequisites; no host
libssl/libcrypto runtime ABI is introduced. Cloud HTTP still uses the dedicated
rustls client and metering OS roots, with no global reqwest TLS feature changes.
