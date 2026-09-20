# Rust native metrics exposition parity

The Rust dataplane serves `GET /metrics` (alias `GET /api/metrics`) natively from
its process-local `MetricsRegistry` when `tiproxy-rs` is started with
`--metrics-addr <host:port>`. This directory pins that exposition to the Go
`promhttp` output for the same series, so the two can be swapped without a
scrape-time difference for the Rust-owned families.

- `parity-batches.json` — the `MetricsBatch` deltas the Rust exporter produces
  for a fixed observation script (`observability::tests::parity_script`).
  Recorded by `TIPROXY_UPDATE_METRICS_PARITY=1 cargo test -p dataplane
  native_exposition_matches_go_golden`.
- `parity-expected.txt` — the Go oracle: `go run ./tests/dataplane/metrics/gen`
  applies the recorded batches through `metrics.ApplyRustMetricsBatch` and
  prints the Rust-owned families exactly as the Go API server would serve them.
- `parity-rust.txt` — the Rust rendering for the same script, written alongside
  the batches for review; the Rust unit test asserts it equals the Go oracle.

`make dataplane-metrics-parity` regenerates the Go oracle and fails when it
drifts from the committed file, and the Rust unit test fails when the native
rendering drifts from that oracle. Update both files together when the catalog
in `rust/crates/dataplane/src/observability.rs` and `pkg/metrics/rust_metrics.go`
changes.
