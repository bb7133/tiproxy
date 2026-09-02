# Rust control-plane contract baseline

This document defines the executable baseline for migrating the Go control plane
into the existing Rust TiProxy process. It is the foundation for
[`CP-000`](https://github.com/bb7133/tiproxy/issues/141) and the M1 work in
[`#140`](https://github.com/bb7133/tiproxy/issues/140).

## Architecture boundary

The target is one Rust process and one binary. New control modules link directly
into the existing Rust dataplane and use in-process Rust types, traits, and
channels. The Go/Rust control bridge is a legacy migration seam: it may support
responsibilities that still belong to Go, but it must only shrink.

CP-000 changes no production owner. It freezes the Go oracle and supplies the
schema, comparator, and fault vocabulary that later slices use when they move an
owner. Each later stateful slice must prove:

1. one namespace/cluster/generation has exactly one owner, Go or Rust;
2. the Rust in-process owner matches the anchored Go observations;
3. the required fault and restart scenarios converge;
4. the PR lists bridge messages it stops consuming or deletes and the remaining
   bridge surface.

Traffic capture and the offline replayer belong to M2 and are intentionally
absent from this M1 catalog.

CP-001 adds `rust/crates/control-plane` to the existing `tiproxy-rs` binary. It
owns one process-local runtime lease, Rust-native module/config/TLS types,
bounded lifecycle observations, and the shutdown order: quiesce admission,
drain and join sessions, seal final metering, stop and join the residual bridge,
then release the owner. Invalid config lineage retains the last-good view;
existing TLS users retain their immutable `Arc` while new users see the next
committed view. The internal crate deliberately has no `control-proto`
dependency.

CP-001 does **not** claim that the migration bridge has already disappeared.
`hello`, `hello_ack`, `heartbeat`, and `error`, along with every remaining
responsibility message, stay in the exact inventory until their real owner
moves. The final lifecycle transport retirement belongs to CP-CUTOVER #153.

## Contract catalog

[`contracts.v1.json`](../../tests/controlplane/contracts.v1.json) is the
machine-readable source of truth. Every row contains:

- the current Go source/test owner and at least two drift-sensitive anchors;
- the Rust handoff issue and a plain-language handoff boundary;
- the semantic fields that differential evidence must expose;
- directly bound fault scenarios and the bridge messages the contract actually
  traverses (an empty bridge list is explicit for Go-only responsibilities).

The gate requires coverage of every M1 target issue (#142 through #150). It also
parses `ControlEnvelope.oneof body` from the protobuf and compares it exactly to
the catalog. Adding, removing, or renaming a bridge message therefore fails CI
until the baseline and its intended retirement target are updated.

Certificate/TLS rotation, namespace/keyspace behavior, semantic network
addresses, election owner identity, and VIP fencing are explicit contracts.
They are not treated as unstable transport noise.

## Fault catalog

[`fault-scenarios.v1.json`](../../tests/controlplane/fault-scenarios.v1.json)
defines deterministic steps, expected convergence, and required observed fields.
Contracts and faults reference each other in both directions; asymmetric or
dangling bindings fail closed.

The catalog covers invalid reloads, snapshot rejection, TLS rotation, dependency
timeouts, etcd interruption and lease loss, watch compaction, partial topology,
namespace/keyspace changes, empty routing, duplicate redirects, absolute
metering duplicate/gap/restart behavior, metrics epoch replacement, VIP owner
loss, bridge reconnect, and process death.

## Observation format and comparison

An observation contains a scenario/step identity, contract IDs, a bounded
subject, outcome, public error class/source, effects, state fields, and integer
counters. Observations contain semantic evidence only: no raw packets, SQL text,
authentication response, credentials, or arbitrary payloads. Secret-bearing key
names are rejected.

Comparison is exact after deterministic ordering. The only ignored field is the
top-level producer label (`go` versus `rust`). In particular, semantic addresses,
owner IDs, namespaces, clusters, generations, sequences, error classes, and
counters are compared. A mismatch reports the first scenario, step, and field.

The committed fixtures are comparator self-tests, not production parity
evidence. A later CP-* slice records Go and Rust observations from the same
scenario, publishes them as CI artifacts, and invokes:

```bash
make controlplane-differential \
  CONTROLPLANE_BASELINE=path/to/go.json \
  CONTROLPLANE_CANDIDATE=path/to/rust.json
```

## Gates

```bash
make controlplane-contracts
make controlplane-differential-self-test
make controlplane-cp001-evidence
go test ./tests/controlplane/...
```

The contract gate validates strict JSON decoding, anchors, family/issue
coverage, bidirectional contract/fault references, schema syntax, and exact
protobuf inventory. The self-test proves that order-only differences normalize
and that a known metering mutation is killed at the expected field.

The CP-001 evidence gate is not a committed synthetic fixture. It drives the
production Go `ConfigManager` and the actual Rust `control-plane` crate through
invalid/valid reload, immutable old/new TLS views, owner retirement, and clean
successor claim. Their public observations must compare exactly. A second Rust
run mutates `owner_generation`; CI passes only when the comparator rejects it.

When Go behavior changes intentionally, update its test first, then the contract
and fault row in the same PR. When a Rust slice takes ownership, keep the row and
attach real paired evidence; do not mark parity from the synthetic fixtures.
