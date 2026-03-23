# mysql-proxy-poc

A minimal standalone Rust PoC for TiProxy data-plane exploration.

## What it does
- listens on a local TCP port
- connects to a configured backend
- forwards MySQL packets in both directions using packet boundaries
- detects the initial MySQL handshake v10 packet shape
- serves as the first stepping stone toward packet-aware protocol experimentation

## Run
```bash
cd rust/poc/mysql-proxy-poc
cargo run -- --listen 127.0.0.1:6000 --backend 127.0.0.1:4000
```

## Notes
This is intentionally minimal. It does **not** yet implement:
- MySQL packet parsing
- authentication logic
- migration semantics
- load balancing behavior

## Benchmark
```bash
cargo run -- --bench --bench-iterations 1000000
```

This currently benchmarks packet-header parse/encode as a tiny local signal, not end-to-end TiProxy behavior.

## Current PoC Coverage
- MySQL packet header parse/encode
- packet-aware forwarding loop
- initial server handshake parsing (minimal)
- client handshake response 4.1 parsing (minimal)
- tiny local benchmark harness

## Next Technical Targets
- OK / ERR / EOF packet parsing
- richer text resultset parsing
- small query-path benchmark for Rust PoC versus baseline path
