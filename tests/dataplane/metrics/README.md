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
- `native-families.json` — the families the Rust process serves natively. The
  Go oracle selects exactly these, and the Rust test asserts the list equals
  `METRIC_SPECS`, so a family present on only one side fails instead of
  quietly dropping out of the comparison. This is **not** the retired
  `MetricsBatch` wire catalogue: `RustMetricNames` in `pkg/metrics` still
  describes that wire contract and still validates it, but since CP-ADMIN
  slice 5c Rust also serves families the bridge never carried.
- `parity-expected.txt` — the Go oracle: `go run ./tests/dataplane/metrics/gen`
  applies the recorded batches through `metrics.ApplyRustMetricsBatch`, applies
  fixed observations directly to the collectors of families that never crossed
  the bridge, and prints every listed family exactly as the Go API server
  would serve it.
- `parity-rust.txt` — the Rust rendering for the same script, written alongside
  the batches for review; the Rust unit test asserts it equals the Go oracle.

The oracle registers the proxy collectors with `metrics.RegisterProxyMetrics`
rather than `MetricsManager.Init`, because `Init` also starts the system time
monitor. That monitor writes the keepalive and time-jump counters off a real
wall clock, so leaving it running would make the fixture depend on how long
generation took. Generating twice must be byte-identical.

`make dataplane-metrics-parity` regenerates the Go oracle and fails when it
drifts from the committed file, and the Rust unit test fails when the native
rendering drifts from that oracle. When a family is added or retired, update
`native-families.json`, the catalog in
`rust/crates/dataplane/src/observability.rs`, and both fixtures together; a
family the list names but the Go collectors do not expose is an error, so the
oracle cannot vouch for something it never gathered.
