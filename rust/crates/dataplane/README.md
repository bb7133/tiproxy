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
