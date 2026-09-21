# Log rotation retention parity (CP-ADMIN B0)

`make controlplane-cplog-evidence` rotates a log file through the production Go
logger's writer (`gopkg.in/natefinch/lumberjack.v2` with `LocalTime: true`, as
`lib/util/logger` configures it) and through the Rust `control_plane::logging`
writer, under `TZ=UTC`, `TZ=Asia/Shanghai` and `TZ=America/Los_Angeles`, and
requires both to keep exactly the same backups.

The crafted backups sit around the `max-days=1` boundary as lumberjack parses
them: names are rendered in local time but `timeFromName` uses `time.Parse`,
which reads the zone-less name as UTC. A 20-hour-old name must survive and a
28-hour-old name must be pruned in every zone; a local-time parse would move
that boundary by the zone offset. Files of another prefix are never touched.

`go-prune/` is the Go oracle; `rust/crates/control-plane/examples/log_prune.rs`
is the Rust half. Neither is a runtime adapter.
