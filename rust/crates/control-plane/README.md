# control-plane

`control-plane` is the process-local control-domain foundation for the single
Rust TiProxy binary. It owns lifecycle, shutdown phases, ownership fencing,
versioned process configuration, TLS-view generations, and bounded lifecycle
observability.

The crate intentionally has no dependency on `control-proto` or `dataplane`.
The legacy Go/Rust bridge remains an outer migration adapter for responsibilities
that have not moved to Rust yet; protobuf messages never become this crate's
domain model.

`ControlRuntime::finish` is called only after the composition root has stopped
admission, drained and joined sessions, sealed final metering, and stopped and
joined the residual bridge. The owner token remains current for those bounded
final effects and is released before the terminal `runtime_stopped` event.

`ConfigStore` accepts only immediate-successor generations. Rejected lineage
does not notify watchers or replace the last-good config. TLS policy is shared
as an immutable `Arc`, so established users keep their original view and new
users see only a fully validated committed successor.
