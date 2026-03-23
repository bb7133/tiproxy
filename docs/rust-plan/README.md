# TiProxy Rust Initiative

This directory tracks the design and execution plan for the TiProxy Rust initiative.

## Goals
- Keep the current Go control plane stable.
- Explore Rust for the TiProxy data plane hot path.
- Reduce long-term protocol/state-machine risk.
- Validate performance, safety, and operability with measurable PoCs.

## Scope
The initial scope is intentionally narrow:
- MySQL packet parsing/serialization
- protocol codec foundations
- forwarding hot path PoC
- minimal standalone Rust binary for benchmarking and experimentation

Out of scope for the first phase:
- full control-plane rewrite
- etcd / topology sync rewrite
- VIP rewrite
- full session migration rewrite

## Documents
- `migration-roadmap.md` — phased migration roadmap
- `module-priority.md` — migration priority by subsystem
- `poc-plan.md` — first Rust PoC scope and validation plan

## Code Layout
- `rust/poc/mysql-proxy-poc/` — first standalone Rust PoC
