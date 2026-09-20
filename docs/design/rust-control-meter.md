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

AWS and OSS use maintained reqsign credential providers, including static keys,
default sources and explicit AssumeRole. COS adapts the pinned Go SDK's source
precedence (env, TKE, profile, CVM), caches the selected source, and provides its
missing AssumeRole flow. The two-hour role refresh starts before expiration;
a failed refresh may reuse an unexpired credential, never an expired one.
COS's one-hour signature header does not require an additional whole hour of
temporary credential validity. Malformed configured COS credentials stop the
chain rather than silently changing identity. The pinned Go env provider ignores
the token environment variable; explicit configured session tokens still work.

Seven focused cloud tests exercise real local HTTP HEAD/PUT, key escaping,
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
PEM/PFX certificate, username/password, workload assertion, VM/App Service managed
identity, CLI, Developer CLI and PowerShell sources compose the default chain.
`AZURE_TOKEN_CREDENTIALS` selects the chain, configured environment/workload
failure stops it, and the first successful source remains selected. Workload
assertion files use the bounded credential reader. Tests cover SharedKey/SAS HTTP
writes, identity selection/failure/cache, and certificate format/password handling.
Regenerate the Azure request fixture with:

```sh
go run rust/crates/control-meter/testdata/azure-shared-key-go.go
```

These are local protocol/authentication tests, not live cloud acceptance.
Full default-credential/endpoint parity and binary ownership handoff remain in progress. In particular, the pinned Rust identity
SDK does not implement Azure Arc, Azure ML, Cloud Shell or Service Fabric managed
identity. Unsupported managed-identity construction stops authentication instead
of falling through to a different identity. Those sources, managed-identity
error classification and token refresh behavior must be reconciled with Go
before selecting the native owner. AWS/OSS role refresh/fallback still needs complete Go comparisons.

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
