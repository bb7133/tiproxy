# TiProxy Rust Migration Roadmap

## Recommended Strategy
Use an incremental migration strategy:
1. baseline and profile the current Go implementation
2. build a narrow Rust data-plane PoC
3. validate protocol compatibility and benchmark value
4. integrate in dual-stack mode with a safe rollback path
5. only then evaluate session-migration-core work

## Phase 0 — Baseline
- collect CPU / memory / allocation / latency profiles
- define benchmark matrix
- define compatibility acceptance criteria

## Phase 1 — Minimal PoC
- standalone Rust binary
- basic MySQL packet codec
- simple proxy forwarding loop
- health-friendly local validation

## Phase 2 — Data-plane foundations
- reusable codec layer
- buffer management strategy
- wire protocol tests
- fuzz / regression tests

## Phase 3 — Dual-stack validation
- Go control plane + Rust PoC sidecar
- shadow traffic or canary validation
- rollback switch by instance or feature flag

## Phase 4 — Session migration pilot
- non-transactional redirect path first
- constrained session-state scenarios
- prepared statement support later

## Phase 5 — Production rollout
- internal clusters first
- canary instances first
- full observability and rollback required
