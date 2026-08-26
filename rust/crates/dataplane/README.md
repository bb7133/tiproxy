# TiProxy Rust dataplane composition

`dataplane` owns the SQL listener and frontend admission lifecycle. It stops at
an admitted, registered `TcpStream`: `mysql-wire` owns packet formats,
`proxy-io` owns transport mechanics, and `session-core` owns session policy.
The DPL-01 runtime is injected through `ConnectionHandler`, so this layer does
not duplicate protocol or routing state.

## Accept lifecycle

The initial validated control snapshot is preflighted before any listener is
bound. Traffic replay fails explicitly. All configured addresses (including a
Go-expanded port range) bind as one attempt; a failure drops every socket
opened by that attempt, and successful listeners report their OS-observed
addresses.

For every accepted socket, the server:

1. captures one immutable snapshot generation;
2. checks memory pressure, then `max-connections` (`0` is unlimited);
3. applies mandatory socket policy;
4. allocates a nonzero process-lifetime connection ID and inserts payload-free
   metadata into the registry;
5. applies best-effort frontend keepalive and transfers ownership to the
   injected connection handler.

The registry lease contains the admission permit. Normal return, rejection,
panic, task cancellation, listener shutdown, and ID exhaustion therefore all
drop the frontend fd, remove registry membership, and release the two-buffer
reservation exactly once. The registry accepts validated nonzero IDs from the
control protocol for later close/reconcile composition.

## Admission and reload

`AdmissionController` serializes the memory and maximum checks, so concurrent
accepts cannot cross a configured boundary. `SystemMemoryProbe` samples Linux
process RSS under the effective finite cgroup/host limit at most every five
seconds. A usable cached observation expires after fifteen seconds; probe
failure then fails open, matching Go's availability posture. Connection buffer
deltas since a sample are included immediately rather than waiting for the
next `/proc` read.

Reload publishes a complete validated snapshot atomically for new connections.
Existing handlers retain their captured `Arc`. Listener changes remain
restart-required under control protocol v1; DPL-03 owns any later listener
generation policy.

This implements the Rust targets behind `PARITY-ADM-001`, `PARITY-ADM-002`,
`PARITY-KA-001`, the new-session subset of `PARITY-CFG-001`, and the
capture/replay preflight in `PARITY-EXCL-001`.

From the repository root:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p dataplane
cargo clippy --locked --manifest-path rust/Cargo.toml \
  -p dataplane --all-targets --all-features -- -D warnings
```

## Session event loop (`session`, DPL-01)

`SessionLoop` is the single owner of one session's mutable state: the
SES-00 FSM, the armed one-shot deadline (handshake until the
authenticating transition itself disarms it, drain when
`BeginDrainTimer` fires), the backend-active probe cadence (Go
`checkBackendActive`, gated to idle-safe states — `Ready`/`Draining` —
per KA-003 so it never races command I/O), and the child-operation
`JoinSet`. There is no session mutex: the `EffectHandler` (which may
spawn **tracked** children but cannot own session state) borrows `&mut`
for one call at a time, and the `SessionEventSource` (SES-layer
classification; the loop never sees packet bytes) is moved into a
dedicated **pump task** that reserves the one-slot channel's permit
**before** reading the transport, polls each `next_event` future to
completion, and submits through the permit — the loop selects on the
channel's cancel-safe `recv`, so classifier futures holding partial
read state are never dropped by a lost select race, and the classifier
is never more than one event ahead of the loop (real backpressure).

Biased select order: server shutdown (with the current value checked
first, so a shutdown that predates the loop is never missed), control
commands, the armed deadline, the probe, finished children, pumped
transport events. Control-channel closure follows control-protocol v1
last-good semantics: it never tears down an established session — the
arm is disabled, traffic continues, and the detachment is reported in
`SessionSummary`. When the FSM enters `Closing` the loop seals the
machine with `TeardownComplete`; the tracked teardown children drain in
the terminal cleanup. That cleanup runs exactly once, owned by `run`,
under **one absolute budget** (`cleanup_deadline`): the pump stops
first — the source, standing for the transport, releases before any
child is waited on — then children drain normally (teardown effects
complete exactly once), and only stragglers are aborted and joined in a
reserved slice of the same window. Every exit path (client/backend EOF,
server shutdown, normal close) drives the FSM's teardown effects
exactly once.

`tests/session_loop.rs` runs under Tokio's paused-time deterministic
scheduler: scripted lifecycle with exact effect order; stuck children
aborted only after the drain window while a slow teardown child runs to
observable completion; the terminal sequence bounded by one
`cleanup_deadline` with the source provably dropped before a teardown
child completes; the classifier held to at most one event of
read-ahead; all six redirect × transport command boundary ×
shutdown arrival orders with quiesced hand-offs plus one
all-arms-ready race with a handler gate proving every arm was loaded
(exactly-once teardown asserted in each); the
handshake deadline firing pre-auth but an authenticated fully idle
session (probe disabled, no events) surviving far past it; a
pre-existing shutdown observed at start; probe ticks skipping in-flight
commands and resuming at the boundary; control detachment with the
session still serving complete commands afterwards; and a multi-await
classifier under select-arm noise delivering every event exactly once.
The no-detached-task property is structural: handlers only ever receive
`&mut JoinSet`, and the pump task is owned and stopped by the loop.
