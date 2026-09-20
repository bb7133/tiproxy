# Native metering implementation checkpoint

The native consumer/outbox, gzip envelope, LocalFS exporter, export worker, and
WAL sampler are implemented. The binary still selects the existing Go owner.
CP-METER qualification remains pending until all storage/configuration and
process-lifecycle paths have completed integration and independent review.

## Cloud storage increment

`control-meter::cloud_store::CloudStore` signs S3, OSS V4 and COS HEAD/PUT
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
COS profile/CVM/TKE sources, and role refresh failure/expiration. COS STS TC3
signatures match a request produced by the pinned Go Tencent SDK. Regenerate its
fixture from the repository root with:

```sh
go run rust/crates/control-meter/testdata/cos-sts-go.go
```

These are local protocol/authentication tests, not live cloud acceptance.
Azure, full default-credential/endpoint parity, storage factory selection and
binary ownership handoff remain in progress. This checkpoint rejects endpoints
with userinfo/query/fragment and object keys with dot path segments, because the
HTTP URL implementation would normalize their identity. Those configuration
edges must be reconciled with Go before declaring the provider contract complete.

## Dependency policy

The global duplicate-version denial and empty advisory ignore list remain.
The reviewed signing libraries require exact duplicate exceptions for
`base64 0.23.1` (the existing TLS/tonic graph uses 0.22) and `hashbrown 0.14.5`
(rust-ini's ordered-multimap; the existing graph uses 0.17). Only
`tiny-keccak 2.0.2` receives a CC0-1.0 license allowance for the profile parser's
build dependency. These are package/version-scoped, not whole-tree exceptions.
Cargo deny bans/licenses and cargo audit pass for this dependency graph.
