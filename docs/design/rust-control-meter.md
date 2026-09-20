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

AWS default selection now validates the active merged profile first, selects
complete environment keys (including the Go legacy aliases), then environment
Web Identity, then profile credentials. Source-profile roles preserve their
signing identity, external ID and duration settings. Profile cycles without a
credential source, conflicting source types and partial file keys are rejected;
keys are not assembled across files. A successful resolution remains selected
through refresh failures. The bounded INI reader uses Go's literal string,
comment, continuation and ignored-line behavior for credential scalars.

Web Identity uses unsigned POST, preserves the complete token-file bytes and
regenerates the default numeric session name per retrieval. Go does not apply
profile `duration_seconds` to Web Identity; regular profile roles use the Go
integer-minute threshold before overriding the 900-second default. The new
fixture compares 41 actual Go resolver outcomes and STS requests, including
configuration validation even when environment credentials win, source-profile
signatures, self-links, file precedence and failed process/Web Identity sources.
Client construction resolves and validates this configuration before the service
opens the consumer/outbox files. Even explicit static credentials validate the
shared profile, while skipping default credential-source resolution. STS, token
file reads and credential processes remain lazy until retrieval; all 41 Go
constructor captures make zero HTTP requests. The resolved profile is retained
if its file changes before the first export.
The Go fixture disables retries to isolate source selection. A separate test
covers concurrent acquisition, actual-expiry caching, failed refresh, profile
changes and token rotation. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-default-go.go
```

STS AssumeRole (explicit and profile role chains) and WebIdentity now retain
client-local retry quotas across retrievals. HTTP 500/502/503/504 remain
retryable even if XML error decoding fails; status 429 alone does not retry.
Wrapped XML error codes select standard retries; only WebIdentity adds the
modeled InvalidIdentityToken retry. Each signed AssumeRole attempt is signed
again; session names, request bodies and the once-read web token stay fixed
within one retrieval. The existing success validation is retained. Fifty-six
actual Go credential-provider observations cover both operations and retry
modes, terminal errors, throttle/timeout codes, malformed/empty bodies,
exhaustion and 2026 retry-after. Native default WebIdentity and AssumeRole tests
compare those attempts/outcomes. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-sts-retry-go.go
```

AWS SSO uses a native adapter for both legacy cached-token profiles and modern
`sso-session` profiles. It validates the same required fields and session/profile
consistency at construction, hashes the start URL or session name for the cache
filename, and preserves the selected identity. Legacy expired tokens fail;
modern expired tokens use CreateToken, retain unknown cache fields and replace
the cache atomically with its original permissions before requesting role
credentials. A failed refresh or cache write returns an error without identity
fallback. Nineteen actual Go cases compare configuration failures, request URLs,
headers and bodies, China endpoints, persisted cache fields, invalid responses
and cache-write failure. The Rust test also verifies restart reuse of the newly
persisted token and mode 0600 retention. After a failed cache rename Rust removes
its own temporary file; Go leaves that orphan file behind. Endpoint mapping
currently covers commercial, GovCloud and China SSO regions; isolated AWS
partitions are not yet supported. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-sso-go.go
```

SSO GetRoleCredentials and OIDC CreateToken now use separate persistent retry
quotas and the shared legacy/2026 backoff engine. The service REST-JSON error
wrapper preserves HTTP 500/502/503/504 even when JSON decoding fails; unlike
container credentials, HTTP 429 alone is not retryable. Decoded retryable error
codes apply at other statuses, with Go header precedence, Code-before-__type,
namespace stripping, folded fields and typed SSO exception canonicalization.
The 2026 retry-after header applies even to a malformed HTTP error body. Failed
OIDC refresh never replaces the token cache. Eighty actual default-retryer Go
observations cover both services and retry modes, including malformed/empty/null
bodies, throttling spellings, header precedence, exhaustion and retry-after;
native tests compare attempt counts and outcomes through the provider methods.
Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-sso-retry-go.go
```

Container credentials now freeze the Go-selected endpoint and token-file path
at construction: relative URI takes precedence over full URI; HTTP full-URI
hosts must resolve exclusively to loopback or the known ECS/EKS addresses. DNS
resolution is capped at ten seconds; Go uses net.LookupHost without an explicit
timeout. The
file overrides the environment token, including an empty file, is read again at
refresh, and is never trimmed; newline tokens fail before a request. Successful
responses may omit token/expiration for static credentials. The Go five-minute
expiry adjustment is retained through both native cache layers. Twenty-six
actual Go cases compare construction failures, GET/Accept/Authorization, typed
JSON decoding and two-retrieval cache behavior. Empty Go request methods are
normalized to the HTTP default GET. A native regression checks token rotation,
refresh while the original token still has 60 seconds remaining, and no env
fallback after the selected file disappears. The probe disables retries to
isolate selection/cache behavior. Container retries are covered separately below.
Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-container-go.go
```

Container HTTP operations now use three attempts with the pinned endpointcreds
retry rules: 429/500/502/503/504, Go retryable/throttling error codes, and transport
failures. Exact `application/json` error decoding happens before retry selection;
a malformed error body is terminal even for 503. The authorization file is read
once for the entire retrieval, so retries preserve the same request identity.
The provider-local 500-token quota survives refreshes, with Go failure costs and
success refunds. `AWS_NEW_RETRIES_2026=true` selects the pinned core's 50ms versus
throttling 1s base delay and revised quota costs; the legacy policy uses a 1s
base. The SDK middleware passes retry indices starting at one in legacy mode
and zero in 2026 mode; actual Go captures pin both argument sequences. Both use
cryptographic jitter, exponential backoff and a 20s cap. Cancellation
drops the pending delay/operation. The retry flag is captured at construction;
changing environment variables in a running process is unsupported.

`aws-container-retry-go.go/json` contains 54 real Go request cases plus two
67-operation quota traces. Rust compares 52 request cases and both full quota
traces under a paused clock; two Go NXDOMAIN cases document a transport
limitation: reqwest does not expose a portable typed NXDOMAIN distinction, so
Rust may make three attempts where Go makes one. HTTP send errors carry only a
sanitized timeout/connection classification, never a request URL or raw error.
A loopback connection-refusal test verifies the real adapter and redaction.
No AWS service is contacted by these probes. The Go quota probe substitutes only
zero backoff; request cases retain the real default retryer. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-container-retry-go.go
```

EC2 IMDS now uses a native adapter with the pinned Go client defaults: IPv4/IPv6
and explicit endpoint selection from environment/shared config, disabled/v1
fallback switches, 300-second token requests, server token TTL, case-insensitive
success codes and first-line role selection with Go path cleaning. Metadata
operations have the Go five-second deadline. Token 400 is terminal; 403/404/405
retain v1 fallback when enabled, while other token failures may retry token
acquisition for the next metadata operation. Valid credentials are capped at one
hour. On refresh failure the same previously acquired identity is retained and,
when needed, its expiry is extended by a random five to fifteen minutes, as in
Go ec2rolecreds; no alternate credential source is selected. Thirty-one real Go
captures compare requests, constructor failures, role paths, token fallback,
cache calls and expiry ranges. The probe now uses the production default
retryer, including three token requests before fallback on a persistent 500. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-imds-go.go
```

IMDS token requests and metadata operations now share the native retry quota.
Each has three attempts; metadata retries negotiate a fresh token after 401,
while exhausted token requests are terminal to the outer operation when v1 is
disabled (no multiplication to nine attempts). The five-second metadata deadline
includes token requests and all backoff. A token timeout disables negotiation for
a later v1 fallback; a metadata 401 re-enables it. Token expiry retains fractional
seconds and the Go duration conversion.

The pinned IMDS client overrides backoff with the legacy one-second-cap helper:
legacy retries wait one second each; in 2026 mode its first retry uses [0,1s)
jitter and later retries wait one second. 2026 `x-amz-retry-after` milliseconds
are clamped between the calculated delay and five seconds above it; the metadata
401 wrapper does not expose that header in Go, so it is ignored there. Forty
actual Go captures compare full PUT/GET/token sequences, terminal errors, nested
retry limits, captured backoff arguments, the operation deadline and the next
call after timeout. The Go probe wraps the default retryer only to observe its
arguments and validates its delay ranges; the fake HTTP client honors context
cancellation before a wire attempt. Rust uses a paused clock. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-imds-retry-go.go
```

For a profile's `credential_source`, missing Environment keys fail during
retrieval; EcsContainer without either container URI fails during construction.
Both timings match the Go resolver, including explicit-static overrides.
`credential_process` invokes the complete configured command through the platform
shell, preserving quoted arguments. Strict decoding follows Go's known field
types, case-insensitive names, duplicate order and null handling. Invalid expiry
fails; a provider response with an already elapsed expiry is returned once and
retrieved again on the next call, as in Go's credential cache. Twenty actual Go
process cases compare command arguments, credentials, failures and cache calls;
a real bounded-shell test verifies the quoted command path. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-process-go.go
```

The shared command adapter retains its 10-second deadline and 4 MiB output cap,
closes stdin and captures stderr; Go defaults to one minute and inherited
stdin/stderr. Interactive or long-running helpers are outside this adapter's
supported boundary. Configured AWS service endpoint overrides and detailed
metadata retry/cache parity remain open. The extra signed
`x-amz-content-sha256` header on AWS AssumeRole is accepted SigV4 metadata that
Go omits. OSS refresh holds the cache lock through STS, matching Go's blocking
lock scope; Rust rechecks under that lock and coalesces concurrent refreshes
where Go may repeat them after reading an earlier snapshot.

OSS default credentials use the pinned credentials-go chain: environment,
OIDC, CLI profile, INI profile, ECS metadata, then credentials URI. Initial
provider errors permit the next source; later calls use the last attempted
source, including after every source initially fails. OSS environment aliases
not recognized by Go are ignored. CLI AK/StsToken/OIDC/RamRoleArn/chainable
roles/ECS/CloudSSO, named INI profiles and roles, and Go INI quoting,
comments, continuation, multiline values and interpolation are handled natively.
Temporary default-source credentials refresh within three minutes of expiration;
that cache is separate from the explicit OSS role's fifteen-minute window and
five-minute maintenance worker. Refresh errors do not select another identity.
Present but empty temporary keys retain the chosen source and fail at signing.
Thirty-three actual Go `NewCredential(nil)` cases compare identity, request
method/endpoint/query/body/headers, and normalized HMAC signatures; all probe
HTTP traffic is redirected to local fixtures. Additional tests cover concurrent
acquisition, cache boundaries, token rotation and sticky initial failures.
Regenerate with:

```sh
go run rust/crates/control-meter/testdata/oss-default-go.go
```

COS adapts the pinned Go SDK's source
precedence (env, TKE, profile, CVM), caches the selected source, and provides its
missing AssumeRole flow. The two-hour role refresh starts before expiration;
a failed refresh may reuse an unexpired credential, never an expired one.
COS's one-hour signature header does not require an additional whole hour of
temporary credential validity. Malformed configured COS credentials stop the
chain rather than silently changing identity. The pinned Go env provider ignores
the token environment variable; explicit configured session tokens still work.
TKE enters the chain only if its constructor inputs and token file are readable;
a constructor failure permits the profile/CVM sources, while a later TKE STS or
token-file failure stops resolution. The selected source determines the refresh
margin (TKE 720 seconds, CVM 300 seconds), and TKE session names use the Go
microsecond timestamp. Six production Go metering-provider uploads compare
selected identity and normalized TKE requests. The capture retains all Go upload
retry attempts; the Rust source test checks one acquisition against those
identical attempts, without claiming upload retry parity. A separate regression
covers a disappearing TKE token after an initial authentication failure.
The native adapter rejects expired TKE/CVM credentials on refresh failure;
the underlying Go credential getters can return their old expired strings.
Regenerate the default-source fixture with:

```sh
go run rust/crates/control-meter/testdata/cos-default-go.go
```

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
open, including nondefault AWS retry configuration and STS clock-skew
correction. Export failure retains the pending window for the next metering
attempt.

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
