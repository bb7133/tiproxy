# Native durable metering (CP-METER-001, issue #148)

`make controlplane-cpmeter-evidence` runs the production Go absolute consumer
and `pkg/manager/meter` durable outbox against the native `control-meter` crate.
The Go SDK uses LocalFS without starting its export loop; no cloud credentials
or external service are required. Observers are test binaries, not runtime adapters.

The 13 shared events compare ACK/error/health outcomes and complete decoded disk
state after each event: duplicate sequence, gap, counter regression, attribution
mutation, valid deltas, final old backend plus new backend, process restart,
process-generation pruning/regression, and duplicate source rejection.
The same run also switches Go→Rust and Rust→Go on existing real state, preserving
producer identity, source baselines, tenant totals, outbox checkpoint, and self ID.
A one-byte accounting mutation must fail comparison. Raw observations are kept
in `CPMETER_OUTPUT` (a temporary directory by default).

Native fault tests (`cargo test --locked --manifest-path rust/Cargo.toml -p
control-meter`) exercise consumer persist failure, interruption before/after
sink commit, identical pending-window retry across restart and new traffic,
single counter wrap, sink checkpoint loss, corrupt/unsafe state, and retired ownership.

This is the durable-core migration slice. The cloud exporter, periodic runtime
owner, sampler/WAL handoff, and removal of the Go sink remain follow-up work.
`CP-METER-001.rust_status` therefore remains pending and the existing production
bridge is unchanged. Only one runtime may open these state files during handoff.
