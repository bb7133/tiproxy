# `control-external`

`control-external` is the only Rust control-plane boundary allowed to construct
clients for PD etcd, HTTP, and DNS dependencies. Every client carries a
`control-plane::OwnerToken`; connection and request APIs reject a stale owner
before and after await points.

The crate deliberately exposes semantic `etcd-client` operations rather than
generated etcd protobuf modules. Its only project protobuf binding is the
wire-compatible `diagnosticspb.Diagnostics` service already registered by the
Go API server. The source revision and all deferred parser/object-storage calls
are frozen in `external-inventory.v1.json`.

CP-002 owns this construction and dependency-policy seam. It does not own an
etcd namespace, election lease, topology key, or admin endpoint. Those owners
move only in their consumer slices, beginning with CP-ETCD (#144), so this
foundation adds or removes no legacy bridge messages.

The minimal project binding is checked in beside its source schema, so TiProxy
does not regenerate that diagnostic surface during ordinary builds. The pinned
`etcd-client` dependency still generates its upstream etcd bindings in its own
build script and therefore requires the workflow runner's `protoc` package;
release and quality jobs install it explicitly.

TLS material is never exposed by `Debug`; diagnostics report only whether a
client identity is configured. The live CP-002 harness also kills endpoint,
TLS-policy, and owner-generation mutations in addition to proving successor
process reconnection.
