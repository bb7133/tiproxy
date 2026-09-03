# Rust control configuration and namespace ownership

Status: design freeze for CP-CFG/NS ([#146](https://github.com/bb7133/tiproxy/issues/146)).

This document defines the Rust-native configuration and namespace boundary used
by later control-plane modules. The target is one Rust TiProxy process. The
legacy Go/Rust protocol is a migration seam, not an internal Rust domain model.

## Ownership boundary

`control-config` owns:

- parsing, defaults, validation, canonical encoding, and checksums for the full
  TiProxy configuration;
- classification of dynamic and restart-required fields;
- the local-file reload loop and its last-good state;
- persistent dynamic configuration and namespace keys below `/config`;
- the only immutable config/namespace snapshot published in the Rust process;
- certificate-material validation and atomic TLS generation changes.

`control-topology` owns:

- TiProxy self-registration below `/topology/tiproxy`;
- TiDB discovery below `/topology/tidb` and `/keyspaces/tidb`;
- Prometheus discovery and backend health;
- immutable topology snapshots, including the keyspace derived from topology
  paths.

`control-topology` consumes the backend-cluster projection from
`control-config`. It must not read, watch, or write `/config`. `control-config`
must not read, watch, or write topology paths. A namespace does not contain a
keyspace field in the current Go model; CP-CFG must not invent one. Keyspace is
discovered by CP-TOPO and bound immutably to a routed session by CP-ROUTE.

## Process-local consumer API

The domain types and source trait live in the `control-config` crate. This
keeps `control-plane` independent of feature modules and avoids a dependency
cycle. The binary composition root passes a cloned source handle directly to
CP-TOPO and later CP-ROUTE constructors.

```rust
pub trait ConfigNamespaceSource: Send + Sync {
    fn current(&self) -> Arc<ConfigNamespaceSnapshot>;
    fn subscribe(&self) -> watch::Receiver<Arc<ConfigNamespaceSnapshot>>;
}

pub struct ConfigNamespaceSnapshot {
    pub generation: u64,
    pub source_revision: SourceRevision,
    pub config_checksum: u32,
    pub namespace_checksum: u32,
    pub effective: Arc<EffectiveConfig>,
    pub namespaces: Arc<[NamespaceConfig]>,
}

pub struct SourceRevision {
    pub file_revision: u64,
    pub etcd_revision: i64,
}

pub struct BackendClusterConfig {
    pub name: Arc<str>,
    pub pd_addrs: Arc<[Arc<str>]>,
    pub ns_servers: Arc<[Arc<str>]>,
}

pub struct TopologyConfig {
    pub advertise_host: Arc<str>,
    pub sql_port: u16,
    pub status_port: u16,
    pub backend_clusters: Arc<[BackendClusterConfig]>,
    pub cluster_tls: ClientTlsConfig,
    pub health: HealthCheckConfig,
}

pub struct TopologyRuntimeIdentity {
    pub version: Arc<str>,
    pub git_hash: Arc<str>,
    pub deploy_path: PathBuf,
    pub start_timestamp: i64,
}
```

The actual types may use private fields plus accessors, but the information and
semantics above are stable:

- `generation` starts at one and is the sole consumer ordering key. It advances
  by exactly one only when a fully validated effective snapshot changes.
- `file_revision` is a process-local accepted-file lineage. `etcd_revision` is
  the highest observed etcd revision incorporated or deliberately rejected.
  They are audit/recovery evidence only. Etcd revisions may skip and therefore
  must never be fed to CP-001's immediate-successor `ConfigStore`.
- A rejected file or etcd candidate records a bounded rejection event but does
  not publish, mutate the current view, or advance `generation`.
- `current` plus `tokio::sync::watch` gives consumers a race-free pull/watch
  pattern. `Arc` makes an accepted snapshot immutable for existing sessions.
- `namespaces` and backend clusters are sorted by name. Address and common-name
  lists are normalized, sorted where order is not semantic, and de-duplicated.
- `pd_addrs` is the trimmed, non-empty expansion of Go's comma-separated
  `PDAddrs`. `ns_servers` is host:port-normalized, using port 53 when omitted.
- When `proxy.backend-clusters` is empty, non-empty legacy `proxy.pd-addrs`
  yields one cluster named `default`, matching `Config.GetBackendClusters`.

CP-TOPO consumes `TopologyConfig`, which is a stable projection of the
effective configuration. `cluster_tls` contains the complete CA and optional
client certificate/private-key paths needed to construct an mTLS etcd client,
not only minimum-version or common-name policy. `health` initially carries the
current Go defaults (enable, interval, retry count/interval, dial timeout, and
metrics interval/timeout); those values become ordinary validated fields if
Go exposes them as user configuration later. `advertise_host`, `sql_port`, and
`status_port` are the resolved equivalent of Go `Config.GetIPPort`.

Binary/build/process facts are not configuration: the composition root passes
`TopologyRuntimeIdentity` directly to the CP-TOPO constructor. CP-TOPO combines
it with `TopologyConfig` to write its self-registration record. Namespace
frontend/backend TLS and static backend instances remain in the same immutable
CP-CFG snapshot for CP-ROUTE. Routing/balance policy is retained by
`EffectiveConfig` but is not a CP-TOPO input.

## CP-001 module executor and composition

CP-001 remains a feature-agnostic runtime foundation. It gains a small explicit
executor owned by the binary composition root:

```rust
let mut modules = ControlModuleSet::new(in_process.handle());
modules.spawn(config_module)?;
modules.spawn(topology_module)?;
```

`ControlModuleSet` has these semantics:

- `spawn` rejects duplicate stable module names and starts
  `ControlModule::run` with `RuntimeHandle::module_context()`;
- `join_next` returns the module name and bounded `ModuleError`; a panic is
  converted to the stable `module_panicked` class;
- readiness is marked only after every required module reports its initial
  last-good snapshot through its constructor-specific ready handle;
- signal or first module failure moves the shared lifecycle to shutdown; every
  module observes the lifecycle watch and returns;
- the composition root joins every module before `ControlRuntime::finish`;
  abort is only the bounded final backstop.

Feature-specific sources are constructor dependencies, not fields added to
`ModuleContext`. Startup order is CP-CFG initial snapshot, CP-TOPO initial
snapshot, later CP-ROUTE, then SQL listener readiness. This establishes one
generation authority per domain without a protobuf or a global generation
shared across unrelated sources.

`ConfigNamespaceSource` never has a pre-initial empty view. Its constructor
synchronously parses and validates defaults plus the configured file/CLI
overrides and installs generation 1 before returning the source handle. The
etcd overlay loop may then advance later generations. Therefore CP-TOPO's first
`current()` is always a real generation-1-or-newer snapshot; module readiness
does not race initialization.

The first CP-CFG implementation adds this executor to `control-plane`. CP-TOPO
may build its module core in parallel and then use the same executor after
rebasing; it must not add a second runner.

## Static and dynamic configuration

The Rust model covers every field in Go `lib/config.Config`; no field is
silently dropped. The implementation maintains two layers:

1. `file_base`: defaults plus the last accepted partial TOML update and command
   line overrides.
2. `persistent_overlay`: legacy dynamic values from etcd.

A local reload decodes into a clone of the previous accepted `file_base`, so
omitted fields retain their previous values and explicitly supplied zero/empty
values overwrite them, matching `SetTOMLConfig`. Command-line advertise address
always wins. File removal/read failure and invalid candidates retain last-good.
Polling remains two seconds for Go parity.

After startup, changes to restart-required fields fail closed as one atomic
candidate. Dynamic fields are recomputed with the persistent overlay, fully
validated, canonically encoded, and published only when bytes change. The
field-level implementation table must classify every Go field as dynamic,
restart-required, deferred with an explicit rejection, or removed with proof.

The config checksum is CRC32-IEEE over canonical TOML of the effective full
config, matching Go. The namespace checksum is CRC32-IEEE over canonical JSON
of the name-sorted namespace array. Checksums are evidence, not ordering keys.

## Persistent key compatibility and fencing

The exact historical keys and JSON shapes remain readable and writable:

- `/config/proxy`: `ProxyServerOnline`
- `/config/log`: `LogOnline`
- `/config/ns/<namespace>`: `Namespace`

Values are persistent and must not be attached to a lease. On bootstrap a
linearizable prefix read at revision `R` creates one validated overlay. Missing
`proxy` or `log` keys are initialized from `file_base` only by the current
CP-ETCD election owner. The write is one etcd transaction that compares the
exact election ownership token and the target key's non-existence, then puts
without a lease. Namespace key mutations use the same owner-fenced persistent
transaction. `ElectionSession::fenced_put` is not reused because it attaches
the election lease and is intentionally ephemeral.

CP-CFG extends `control-etcd` with a bounded owner-fenced persistent transaction
primitive. It exposes neither a raw unaudited client nor a generic arbitrary
transaction API. Losing election ownership before commit fails closed. Readers
need only the process `OwnerToken`; writes additionally require the current
election fence.

After the bootstrap read, a prefix watch begins at `R + 1`. All events from one
watch response are applied as one candidate, sorted by key. A disconnect or
compaction performs a fresh linearizable relist and resumes after its header
revision. Invalid JSON, a namespace key/value name mismatch, a missing name,
or an invalid effective config rejects the complete candidate and preserves
last-good. The observed etcd revision still advances for watch recovery, so a
later corrective revision can be accepted without replay loops.

## TLS rotation

TLS paths must be absolute and under configured allowed roots. Certificate and
key must be supplied together; minimum TLS is 1.2 or 1.3; allowed common names
are bounded and canonicalized. A watcher loads a complete cert/key/CA set into
a new connection factory before publishing it. Partial or unreadable material
is rejected atomically. Existing sessions keep their prior `Arc`; only new
connections observe the new certificate generation.

## Migration and bridge accounting

CP-CFG first installs the Rust source and uses its accepted snapshot as the
authoritative config/namespace input. While CP-TOPO is still landing, the
legacy `StateSnapshot` adapter may continue to provide topology fields, but its
config and namespace fields are ignored and cannot overwrite Rust-owned state.
After CP-TOPO rebases, an in-process composer combines CP-CFG and CP-TOPO
snapshots for the dataplane. There is no shared source generation: the composer
records `{config_generation, topology_generation}` and publishes exactly once
per changed pair.

The final #146 bridge delta must state exactly which `state_snapshot` fields are
no longer consumed. The `state_snapshot`/`snapshot_result` message pair can be
deleted only when no remaining topology or route field depends on it; until
then the catalog records the remaining field-level bridge surface rather than
claiming whole-message retirement.

## Required evidence

- Go/Rust differential fixtures for defaults, partial TOML, canonical checksum,
  every field classification, legacy PD fallback, namespaces, and legacy JSON
  keys.
- Invalid reload: last-good checksum and effective generation remain unchanged.
- Rejected revision `N` followed by valid `N+1`: `N` never applies and `N+1`
  publishes exactly once, including disconnect/relist recovery.
- TLS rotation: partial material rejects; an existing session survives on its
  old generation; a new connection presents the new generation.
- Namespace change: existing session binding is immutable, new session uses the
  new namespace generation, and cross-keyspace redirect is rejected after
  CP-TOPO supplies authoritative keyspace.
- Real embedded-etcd restart/compaction and old-owner write attempts prove
  watch recovery and owner-fenced persistent writes.
- Mutations must kill: skipped field projection, generation skip, invalid
  candidate overwrite, lease-attached persistent key, and old-owner write.
