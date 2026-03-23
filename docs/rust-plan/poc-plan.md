# TiProxy Rust PoC Plan

## Objective
Build a standalone Rust PoC that validates whether Rust is a practical choice for TiProxy's data-plane hot path.

## Initial Functional Scope
- accept a frontend TCP connection
- parse basic MySQL packet headers
- forward raw packets between frontend and backend
- collect basic metrics/logging
- handle graceful close on either side

## Non-goals
- authentication parity with TiProxy
- session migration
- load balancing
- full protocol coverage

## Suggested Validation
- local manual tests against a MySQL-compatible backend
- packet-level unit tests
- smoke benchmark for throughput/latency
- memory-allocation observation during sustained forwarding

## Exit Criteria
- stable forwarding loop
- basic packet framing correctness
- benchmark data worth comparing with Go baseline
