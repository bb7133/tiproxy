# Rust control-plane external dependency boundary

CP-002 introduces one process-local, owner-fenced construction boundary for
external control dependencies. It deliberately does not migrate an etcd key,
leader lease, topology source, or API endpoint; the consuming issue acquires
that production responsibility and removes the matching legacy bridge seam.

## Shipped boundary

- `etcd-client` 0.20.0, built with the ring TLS provider, supplies balanced
  multi-endpoint PD etcd v3 clients. TiProxy validates endpoint count and form,
  complete mTLS material, and bounded connect/request/HTTP2/TCP keepalive
  values. Generated etcd protobuf modules do not enter TiProxy domain APIs.
- HTTP reads have immutable TLS policy, exact HTTP 200 acceptance, no redirect
  or idle-connection reuse, and a streaming response cap. DNS lookups have
  deadline, deterministic deduplication, and a bounded result set. Retries are
  explicit, classified, capped, and stop when their owner generation expires.
  TLS material has a redacted diagnostic surface, and dependency URLs reject
  embedded credentials.
- The only direct project protobuf binding is
  `diagnosticspb.Diagnostics`, matching the sole production Go `kvproto`
  import in `pkg/server/api/server.go`. The local schema removes only
  language-specific generation options and preserves service paths, field
  numbers, and enum values from kvproto `b41e86365ce0`.

## Deferred dependencies

TiDB `Normalize` / `NormalizeDigest` is used only for backend-disconnect
diagnostics and traffic capture/replay. A generic SQL parser is not accepted as
equivalent. The consumer slices must first freeze Go outputs, then introduce a
bounded Rust tokenizer/normalizer and prove exact behavior on malformed and
TiDB-specific inputs.

TiDB `objstore/storeapi` backs both durable metering and capture/replay. Those
consumers will use TiProxy-owned storage traits backed by Apache OpenDAL with
only `fs`, `s3`, `gcs`, `azblob`, `oss`, and `cos` services enabled. Provider
path rules, pagination, atomic publish, retries, credential redaction, and
error classes must be differential-green before ownership moves.

The machine-checked detailed inventory is
`rust/crates/control-external/external-inventory.v1.json`.

## Ownership and bridge statement

CP-002 owns only external client construction and dependency policy in Rust.
No Go responsibility is dual-owned and no bridge message is consumed:

```
removed = []
added = []
remaining = 24
```

CP-ETCD (#144) is the first consumer allowed to own an etcd session/lease and
must re-run live transient, compaction, and process-death evidence before that
handoff.

The CP-002 evidence itself exercises production Go and Rust clients against a
real embedded-etcd/HTTP/DNS fixture, kills and replaces that process at the
same etcd address, and proves that endpoint, TLS-policy, and owner-generation
mutations cannot pass the comparison gate.
