# Native metering implementation checkpoint

The native consumer/outbox, gzip envelope, LocalFS exporter, export worker, and
WAL sampler and configured storage factory are implemented. Rust mode now selects
the native owner; Go mode retains the Go implementation.
CP-METER qualification remains pending until all storage/configuration and
process-lifecycle paths have completed integration and independent review.

## Process ownership

Both processes require capability 7 (`RUST_METER_OWNER`) in addition to the
existing config and route-owner capabilities. Ownership is process-fixed.
Rust mode skips Go `NewMeter` and the bridge consumer entirely; metering batch
and ACK bodies are retired on that bridge, with no durable effects. Compatibility
constructors and protobuf tags remain for old fixtures and explicit Go mode.

Rust retains `<control-socket>.metering.wal`,
`<workdir>/run/rust-metering-consumer.json`, and
`<workdir>/run/metering-outbox.json`. It holds exclusive native locks for the
state directory and WAL path, including when distinct workdirs share a WAL.
Consumer/outbox recovery and retained WAL replay occur only after compatible
peer negotiation; the snapshot consumer gates initial SQL installation until
recovery and startup succeed.
Startup failure releases the gate as failed before joined rollback. An older
binary does not participate in the native file locks: stop both old processes
before migrating existing state. Capability negotiation cannot make concurrent
legacy file access safe.

Normal shutdown joins SQL sessions, takes the sampler's final durable sample,
ACKs successful native intake, then joins the export worker's final flush before
retiring process ownership. Sampler and exporter are locally owned futures;
startup rollback leaves no detached worker. Failed final export returns an error
and retains the pending outbox; rejected intake retains the WAL. The health
endpoint includes native intake/export health.

The focused real-process probe starts the actual Go bridge, Rust binary and TiDB
clusters, runs SQL and disconnect recovery, then joins Rust shutdown. Its live
control tap must see zero metering batch/ACK frames. An independent Python reader
checks WAL checksum and sequence, consumer/outbox checkpoint agreement, zero
remaining sources/unacked batches, and exact aggregate byte equality with the
final LocalFS gzip objects. This is a directed ownership check, not the full
transport/fault matrix:

```sh
DATAPLANE_NATIVE_METER=1 TIPROXY_RS_BIN=/path/to/tiproxy-rs \
  tests/dataplane/integration/run.sh --mode rust --variant plain
```

## Cloud storage increment

`control-meter::cloud_store::CloudStore` signs S3, OSS V4, COS and Azure Blob HEAD/PUT
requests. An existing object, failed HEAD, rejected PUT, timeout or ambiguous
upload retains the outbox window. Object prefixes and gzip bodies remain intact.
Temporary session tokens are passed with the request. OS TLS roots are added
only to the metering client; other clients' explicit CA trust stays unchanged.
Errors expose fixed classes, not service URLs, headers, response bodies or keys.
Credential file, HTTP response and command output reads have a 4 MiB bound.

S3 HEAD and PUT each use the configured standard/adaptive retry policy and a
shared S3-client quota, independent of STS credential quotas. Attempts re-sign
and replay the same object URL and immutable payload. A retried PUT does not
restart the successful existence check. S3 v1.105.1, unlike the pinned STS
client, persists the final attempt's valid Date offset across operations;
missing metadata resets the next attempt but leaves that client offset intact.

S3 uses unwrapped XML error codes and status-text fallback for empty errors.
Status 429 alone is terminal; the standard status/code retry rules and clock
correction apply. The metering SDK's Exists result is reproduced from
`NotFound`/`NoSuchKey` in decoded error code/message, including HeadObject's
case-insensitive modeled NotFound; a malformed 404 response is an error. Eighty
actual metering SDK Exists/Upload trajectories compare calls, results and
signed timestamps for both retry modes, including persistent clock healing and
transport failures. Two fixed-time S3 signatures compare authorization bytes.
A real HTTP test exercises HEAD 503→404 and PUT 503→200 with identical object
path/payload on retry. Regenerate the Go observations with:

```sh
rust/crates/control-meter/testdata/aws-s3-retry-go.sh
```

The retry probe's CustomConfig disables optional checksums. A separate probe
constructs the actual metering provider through LoadDefaultConfig and sends
requests to real local HTTP/TLS servers, preserving the production middleware.
The default WhenSupported policy adds CRC32: nonempty HTTPS PUT uses one
aws-chunked body with a CRC32 trailer; HTTP and empty uploads use a checksum
header. HTTP signs the actual payload SHA256, HTTPS PUT uses unsigned payload
(or the streaming trailer sentinel), and HEAD signs the empty payload SHA256.
Retries replay identical encoded bytes, with checksum headers present before
signing. CRC32 reuses the existing compression dependency.

`AWS_REQUEST_CHECKSUM_CALCULATION` overrides the active config profile's
`request_checksum_calculation`; values are case-insensitive WhenSupported or
WhenRequired. WhenRequired disables optional PUT checksums. Invalid selected
profile values fail construction even when overridden by the environment;
the shared credentials file does not supply this service option. Twenty-six
actual provider cases compare checksum/payload-hash headers, their signed
header membership, full body bytes, encoded length, retry attempts and load
errors, including empty/binary/65537-byte bodies. This closes the automatic
checksum encoding gap; it does not assert equality of unrelated SDK telemetry
headers. Regenerate with:

```sh
rust/crates/control-meter/testdata/aws-s3-checksum-go.sh
```

COS HEAD and metering's seekable PUT payloads use the SDK's three immediate
attempts: all HTTP statuses at or above 500 and transport/signing failures may
retry; 401/408/429 and other statuses below 500 do not. Retries add
`x-cos-sdk-retry: true` before signing and replay the same body. Only HTTP 404
means absent, regardless of the XML code. Successful nonempty PUT also verifies
the server's `x-cos-hash-crc64ecma` against the Go-compatible reflected
CRC-64/ECMA checksum; a missing/bad checksum fails without retrying a 2xx
response. The SDK skips this check for an empty `http.NoBody` upload.
Thirty-six actual metering COS provider cases compare attempts, marker, signed
requests, payload and Exists/Upload outcomes, including empty and Unicode
payloads and checksum failures. A real HTTP HEAD/PUT retry sequence checks the
production adapter. Regenerate with:

```sh
go run rust/crates/control-meter/testdata/cos-object-go.go
```

OSS HEAD and seekable PUT use three attempts, with full-jitter delays below
800ms and 1600ms before the second and third attempts. Statuses >=500,
401/408/429, exact BadRequest/RequestTimeTooSkewed codes, recognized connection
failures and CRC mismatches retry. Other service/transport errors are terminal.
Each attempt reacquires credentials and signs the same body. CRC64 checks
include empty uploads: a missing header is accepted, while a nonempty value
must equal the decimal checksum exactly. Exists maps the final service error's
404 status or NoSuchKey code only after the retry policy finishes.

OSS RequestTimeTooSkewed subtracts the previous signing time from the error's
server Date; malformed/missing Date uses current time. Repeated corrections
therefore can alternate, matching SDK v1.2.3 rather than applying a different
healing policy. Only a successful operation saves a changed offset for the next
operation. An explicit-time native V4 signer uses the existing reqsign hashing
primitives and matches six fixed-time actual Go signatures, including Unicode,
percent escapes and repeated leading separators. No dependencies were added.

One hundred actual metering OSS provider cases compare attempts, body/key,
Exists/Upload outcomes and persistent clock trajectories. Scripted cases use
LoadDefaultConfig with the default retry classifier and zero delay; four cases
use the unmodified production constructor and real HTTP servers. No SDK source
is patched. Corrected-time trajectories are recorded to the nearest ten seconds
and compared within two seconds; all request counts and outcomes are exact.
Malformed XML after a completed Code field and x-oss-err fallback are covered.
The adapter preserves literal key separators, ignores OSS endpoint path prefixes,
and selects path-style addressing for IP endpoints. Metering .json.gz MIME uses
the same Unix MIME-file priority as Go, with the SDK application/x-gzip fallback;
other arbitrary file extensions are outside the metering writer's key contract.
The fixture records macOS MIME, while the native test uses the local MIME
selection on Linux. Real HTTP retry checks cover the actual CloudStore adapter.
Regenerate with:

```sh
bash rust/crates/control-meter/testdata/oss-object-go.sh
```

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

STS clock-skew correction follows the pinned STS v1.38.0 client: response
`Date` adjusts the next attempt within one operation; a new operation starts at
zero skew. This service version does not wire the core SDK's persistent
`ClientSkew`. Absent, malformed and transport-failure metadata clear the next
attempt's offset. AssumeRole re-signs at the corrected time; WebIdentity remains
unsigned. The three definite clock-error codes retry unconditionally, while
`InvalidSignatureException`, `SignatureDoesNotMatch` and `AuthFailure` require
the previous attempt's positive skew to exceed four minutes.

Sixty-four actual Go service trajectories cover both operations and legacy/2026
retry behavior, the threshold, negative correction, missing dates and repeated
operations. Twenty-three Smithy date observations cover IMF-fixdate, RFC850,
ANSIC and malformed inputs; two fixed-time Go signatures compare authorization
bytes for plain and custom path/query endpoints. Native signing reuses reqsign's
canonicalization and HMAC helpers. The date parser treats RFC850 named zones as
UTC, matching the fixture's `TZ=UTC`; recognition of a non-GMT zone from the host's
local timezone remains a declared edge difference. Regenerate with:

```sh
rust/crates/control-meter/testdata/aws-sts-clock-go.sh
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

Service credential retries honor `AWS_MAX_ATTEMPTS`/`max_attempts` and
`AWS_RETRY_MODE`/`retry_mode` (`standard` or `adaptive`). Active and linked
profiles are validated even when environment settings override them or explicit
static credentials are supplied. Nonzero environment attempts override the
profile; zero is unset and negative removes the attempt-count limit while
retaining the quota and cancellation. Root settings apply to explicit/profile
STS, WebIdentity, SSO and OIDC clients, with independent per-client state.
Container endpoint credentials and IMDS keep their SDK-specific default retry
policies rather than inheriting these service options.

Adaptive mode adds the pinned SDK's half-second measured-rate buckets and cubic
send-rate limiter, activated after a throttled response. Its bucket is separate
from retry quota. The middleware's 2026 behavior updates the adaptive limiter
only after the first attempt of each operation; all attempts still acquire a
send token. Adaptive success does not receive the standard initial-token bonus.
Dropping the request future cancels its wait. The native timer yields at least
one millisecond for a positive sub-tick deficit to avoid spinning.

Forty-four actual Go config/client-constructor cases compare validation and
resolved settings. Twenty persistent real Go middleware traces compare both
retry modes, legacy/2026 behavior, one/two/four/unlimited attempts, delayed
throttling, terminal failures, quota exhaustion/refunds and recovery. Attempt
counts, outcomes and quota must match exactly; cumulative pacing is within
100ms for Tokio timer quantization. The trace uses SDK testing clock hooks and
zero backoff to isolate adaptive pacing, without replacing middleware or quota.
The helper runs in a temporary SDK-namespaced Go module solely to import those
internal testing hooks; production dependencies and SDK sources are unchanged.
Regenerate with:

```sh
go run rust/crates/control-meter/testdata/aws-retry-config-go.go
rust/crates/control-meter/testdata/aws-adaptive-go.sh
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

Azure object requests follow the production provider's azblob v1.6.3
`UploadStream` path. Bodies below 1 MiB use a direct PUT, including empty bodies;
bodies at or above 1 MiB stage sequential 1 MiB blocks and commit their ordered
XML block list. Each upload uses fresh UUID-based 64-byte block identifiers;
retries preserve the same identifier and bytes. The content types, block type
header and Go-escaped entire blob name match the actual wire requests.

Each HEAD, direct PUT, StageBlock and CommitBlockList has four attempts for
408/429/500/502/503/504 and transport errors, with fresh signatures. Backoff uses
the pinned exponential jitter. Retry-After milliseconds/seconds/date precedence
matches azcore; a server delay above 60 seconds stops retries. Exists maps the
final 404 or exact BlobNotFound/ResourceNotFound/ContainerNotFound header to
absence. HEAD must otherwise return 200 and upload operations 201. Success
metadata date, boolean, integer and base64 decoding errors fail after the retry
policy, without retrying a successful HTTP response. These checks decode the
server CRC header; the SDK default does not compare its CRC to the payload.

The original 95 production-provider loopback HTTP cases compare full request
trajectories, block identity/order, commit XML, payload lengths/hashes, headers,
SAS preservation and Exists/Upload results. Only the public retry delay option is
shortened to 1ns; status classification, retry counts and SDK source are unchanged.
UUID bytes are normalized only for commit XML comparison. Real socket closes
exercise transport retries. A native CloudStore HTTP test also covers signed
HEAD 503→404 and PUT 503→201. Regenerate with:

```sh
bash rust/crates/control-meter/testdata/azure-object-go.sh
```

Seven fixed-time Azure SharedKey signatures match actual HEAD, direct PUT,
StageBlock and CommitBlockList requests from the pinned Go azblob SDK. This
proves signature canonicalization, including the stage/commit query parameters
and headers; two additional HEAD signatures use keys with nonzero base64 pad bits. SharedKey takes precedence over SAS; SAS query strings survive
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

Azure storage bearer challenges now preserve the challenged resource scope across
operations. The pinned parser accepts the same space-delimited resource fields
and appends `/.default` when absent; its tenant field is unused. Continuous
Access Evaluation (CAE) claims take priority across all challenge header values.
Resource challenges may be followed by one CAE replay; a CAE replay does not
recursively process another challenge. HTTP retry attempts may each enter this
challenge flow, and each replay preserves the body.

Typed Azure response dates now validate Go RFC1123 acceptance instead of strict
RFC7231 acceptance. This preserves syntactic (not calendar-matched) weekdays,
case-insensitive day/month names, repeated spaces, optional fractional seconds,
valid leap dates and Go's named/signed-hour zone grammar. Only parse success is
needed for this metadata; no zone offset is inferred. MD5/CRC64 metadata, SharedKey
configuration and CAE claims share Go-compatible non-strict padded base64 decoding.

The object fixture now has 243 actual production-provider cases: the original 95
plus 116 date and 32 base64 metadata cases. Its 58 date inputs run through both
HEAD and PUT, including accepted named zones and rejected date/time ranges. Old
RFC7231 validation and strict base64 both fail the expanded fixture; corrected
validation passes. Two extra fixed-time SharedKey signatures cover nonzero pad
bits, bringing that fixture to seven byte-equal signatures. HTTP Retry-After
clock interpretation remains separate from metadata acceptance.

Managed identity caches are keyed by resource. Nonempty CAE claims bypass the
cached token and replace it on success; claims are not sent to the metadata
endpoint, matching MSAL. Developer and OAuth credentials cache tokens in the outer bearer
policy, which expires the cache on 401 even without a usable challenge. Refresh
uses the five-minute window and 30-second retry backoff; a failed eager refresh
retains the still-valid token. PowerShell has no inner token cache and accepts
the challenged resource after validating the SDK's safe scope character set.
CLI/PowerShell reject claims, while Developer CLI sends base64 `--claims` to azd.

The 241 actual production-provider cases use DefaultAzureCredential, local TLS,
a synthetic App Service metadata endpoint and fake az/azd/pwsh executables.
Sixty cases per source compare every metadata or normalized tool scope/claims
and object authorization/body trajectory, including scope persistence/reversion,
CAE refresh, malformed challenges and ordinary retries before/after challenges.
A further CLI case waits 31 seconds to verify eager refresh failure fallback,
30-second backoff and forced renewal after 401. The native replay advances its
Tokio timer for this wait. Tool executable templates and platform process
launchers are not compared byte-for-byte; their scope, claims and call counts are. The public Go x509 fallback-root API
trusts only the synthetic local certificate in the probe; SDK source is unchanged.
Regenerate with:

```sh
bash rust/crates/control-meter/testdata/azure-bearer-go.sh
```

Environment secret, certificate and workload credentials now wrap fresh maintained
SDK credential objects for actual OAuth fetches. Their scope-keyed cache reuses
unchallenged tokens, bypasses cache for nonempty claims, and replaces an entry
only after success. The username/password adapter follows the same cache and
changed-resource behavior. OAuth requests append the pinned Go OIDC scopes and
merge CP1 capabilities into claims. Invalid JSON or conflicting capability fields
fail before a token request. The outer bearer policy handles the five-minute
refresh window and 30-second fallback backoff for these sources too; managed
identity retains its own `refresh_in` timing.

The OAuth fixture uses the exact production Go dependency graph and four real
DefaultAzureCredential sources: secret, workload file, password and certificate.
Each performs 13 credential steps plus four real Blob client operations. The
native replay compares all 52 token results/errors, 28 normalized token POSTs,
and authorization sequences/body preservation across 16 HEAD/PUT operations.
Certificate assertions are signature-verified on both sides (Go PS256 and the
maintained Rust SDK's RS256); randomized JWT bytes and discovery requests are
not claimed equal. The Go constructor uses only a public custom transport:
canonical authority requests are redirected to local TLS, and every other host
is rejected before network access. Instance discovery remains enabled and the
fixture serves its metadata. No SDK source or token-cache internals are patched.
Regenerate with:

```sh
bash rust/crates/control-meter/testdata/azure-oauth-go.sh
```

These fixtures qualify token request fields, scope/claims/cache and object
challenge behavior for the isolated managed authority. Native SDK instance and
OpenID discovery, authority alias validation, federated password user realms,
OAuth retry/error classification and refresh-token reuse are not covered by this
increment and remain open. The regex and permissive base64 dependencies reuse
package versions already in Cargo.lock; this OAuth increment adds no dependency.

Full default-credential/endpoint edge parity remains in progress, including
general HTTP date/Retry-After clock interpretation, endpoint and platform
transport edges. Export failure retains the pending
window for the next metering attempt.

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
