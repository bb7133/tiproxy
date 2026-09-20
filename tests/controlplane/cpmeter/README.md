# Native durable metering (CP-METER-001, issue #148)

`make controlplane-cpmeter-evidence` runs the production Go absolute consumer
and `pkg/manager/meter` durable outbox against the native `control-meter` crate.
The Go SDK uses LocalFS; ingestion observations leave the loop stopped, while
the export observation starts and joins it against a sealed crash fixture. No
cloud credentials or external service are required. Observers are test binaries, not runtime adapters.

The 13 shared events compare ACK/error/health outcomes and complete decoded disk
state after each event: duplicate sequence, gap, counter regression, attribution
mutation, valid deltas, final old backend plus new backend, process restart,
process-generation pruning/regression, and duplicate source rejection.
The same run also switches Go→Rust and Rust→Go on existing real state, preserving
producer identity, source baselines, tenant totals, outbox checkpoint, and self ID.
A separate six-event sequence checks wrap, sink overflow, and pending restart.
The export comparison resumes the same sealed pending window in both owners,
compares the object key and decompressed JSON (sorting tenant records), and checks
pending clearing. A one-byte accounting mutation must fail comparison. Raw observations are kept
in `CPMETER_OUTPUT` (a temporary directory by default).

Native fault tests (`cargo test --locked --manifest-path rust/Cargo.toml -p
control-meter`) exercise consumer persist failure, interruption before/after
sink commit, identical pending-window retry across restart and new traffic,
single counter wrap, sink checkpoint loss, corrupt/unsafe state, and retired ownership.
Two additional async tests cover actual LocalFS export, SDK fields/mode, refusal
to overwrite, upload failure/timeout, and health recovery.

The native exporter now implements the Go single-part gzip envelope and object
key, default shared pool, existing-object refusal, durable seal/commit, and
LocalFS provider options. Go TiProxy uses the SDK default with pagination off.

The cloud provider adapters, periodic runtime
owner, sampler/WAL handoff, and removal of the Go sink remain follow-up work.
`CP-METER-001.rust_status` therefore remains pending and the existing production
bridge is unchanged. Only one runtime may open these state files during handoff.
