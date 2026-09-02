# Rust etcd control ownership

`control-etcd` owns the stateful PD-etcd session and election seam for the
single-process Rust control plane. It composes the owner-fenced,
TLS/multi-endpoint client from `control-external`; generated protobuf types and
raw clients do not cross this boundary.

The public snapshot deliberately distinguishes confirmed `Leader` from
`Uncertain`. A transport failure retains the last-known owner so an etcd outage
does not force an availability gap, while new owner-only transactions fail
closed until recovery verifies the exact lease, leader value, and creation
revision. Missing leases, leader mismatches, stale process generations, and
explicit shutdown are the only retirement fences.

Every presence or owner-only key is attached to the election lease by a
transaction comparing the elected key's creation revision, lease, and exact
member value. Revisioned watches resume from the last consumed revision and
recover a compaction cancellation by relisting the current leader before
installing a fresh watch.

Campaigning uses the same lease-derived candidate key, create-revision
transaction, and newest-predecessor watch ordering as etcd's Go concurrency
client. The watch remains open across the per-request deadline while bounded
keepalives preserve the candidate lease, so a waiting contender neither loses
its queue position at every unary RPC timeout nor silently expires.

Run the real Go/Rust differential and fault evidence from the repository root:

```bash
make controlplane-cp003-evidence
```

The Go oracle drives `pkg/manager/elect` for campaign, transient restart, lease
loss, successor election, and process death. Because its public API has no
single-step recovery hook, the oracle explicitly closes the Go member after
revoking its lease; the Rust member must detect the same revocation and retire
itself before its already-waiting successor is allowed to finish. The Rust
fixture keeps that successor queued for longer than its lease TTL before
revocation. The stale-watch row uses the same real Go etcd client boundary to
force a compacted revision, relist the exact leader, and consume a
post-compaction event from the replacement watch.

CP-ETCD does not consume a legacy Go/Rust bridge message. It establishes the
in-process election/session object that later topology, config, metering, and
HA slices will use; those owner-only jobs remain with their current owners until
their own migration slices close.
