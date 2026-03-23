# TiProxy Rust Rewrite Assessment

## Executive Summary

This document summarizes the potential benefits, risks, and a recommended phased migration plan for rewriting TiProxy in Rust.

**Bottom line:** a full rewrite of TiProxy in Rust may bring meaningful long-term gains in memory safety, state-machine rigor, and hot-path performance, but it also carries substantial delivery and compatibility risk. The recommended strategy is **not** a big-bang rewrite. Instead, the preferred approach is **incremental Rust adoption focused on the data plane**, with strong benchmarking, compatibility validation, and rollback mechanisms at every stage.

---

## 1. Context

TiProxy is not a generic TCP proxy. It is a TiDB-aware, MySQL-protocol proxy that provides:

- connection continuity during TiDB restart, upgrade, scale-in, and scale-out
- backend health awareness and service discovery
- dynamic routing and load balancing
- session migration while keeping the frontend client connection alive
- operational control plane capabilities such as API management, topology sync, VIP management, and traffic replay/capture

This means any rewrite effort must preserve not only basic forwarding behavior, but also the semantics of:

- MySQL protocol negotiation
- TiDB-specific capability handling
- session state preservation
- connection migration correctness
- graceful shutdown and failover behavior

---

## 2. Potential Benefits of a Rust Rewrite

### 2.1 Stronger Memory Safety

TiProxy includes several classes of logic that are naturally error-prone:

- connection lifecycle management
- concurrent state transitions
- packet buffer reuse
- protocol parsing and forwarding
- backend migration under failure or rebalance conditions

Rust can reduce an entire category of memory and concurrency issues through:

- ownership and borrowing rules
- compile-time guarantees around aliasing and mutation
- stricter modeling of state transitions
- safer low-level buffer handling

For a system like TiProxy, this is a practical benefit rather than a theoretical one.

### 2.2 Better Control Over Hot-Path Performance

Rust is well suited for performance-sensitive components such as:

- packet parsing and serialization
- forwarding loops
- compression/decompression
- custom buffer pools or slab allocators
- low-copy or zero-copy style packet paths

In TiProxy, likely hot-path candidates include:

- packet I/O
- MySQL protocol encode/decode
- handshake processing
- backend forwarding and migration path coordination

That said, performance improvement is not automatic. TiProxy bottlenecks may also be dominated by network latency, backend TiDB response time, TLS overhead, or migration semantics.

### 2.3 More Robust State-Machine Modeling

TiProxy’s most difficult logic is stateful:

- client/frontend handshake
- backend handshake
- redirect and migration lifecycle
- transaction-sensitive migration constraints
- graceful close and draining
- replay/capture progress management

Rust is particularly strong when a system must encode and defend state transitions explicitly. This can improve long-term maintainability in the most fragile parts of the codebase.

### 2.4 Better Long-Term Ceiling for a High-Performance Data Plane

If TiProxy continues evolving toward a long-running, high-throughput, protocol-aware database gateway, Rust may offer a higher long-term ceiling in:

- memory efficiency
- throughput per core
- tail-latency stability
- explicit resource control
- runtime predictability under sustained load

---

## 3. Major Risks of a Rust Rewrite

### 3.1 The Biggest Risk Is Semantic Reimplementation, Not Syntax Rewrite

TiProxy’s core value is not just packet forwarding. The hard part is preserving behavior across:

- frontend/backend handshake quirks
- TiDB-compatible capability handling
- session migration correctness
- transaction boundary safety
- prepared statement behavior
- graceful failover and draining

A Rust rewrite may produce cleaner code but still regress subtle production behavior. This is the central risk.

### 3.2 Session Migration Is the Highest-Risk Subsystem

The session migration path is TiProxy’s most valuable and most fragile subsystem. It involves:

- stable frontend connection identity
- replaceable backend connections
- session token and state handling
- transaction-sensitive redirectability
- prepared statement and session variable continuity
- correct failure classification and retry behavior

A rewrite that reaches this area too early is highly likely to introduce compatibility or correctness regressions.

### 3.3 Team Productivity and Hiring Risk

The current implementation is in Go. A Rust rewrite changes the profile of the team required to deliver and maintain the system:

- fewer engineers may be able to review all core code paths confidently
- onboarding time becomes longer
- debugging asynchronous or systems-level behavior may become slower
- long-term maintenance depends on retaining Rust systems expertise

If the organization is primarily optimized for Go infrastructure work, this matters a lot.

### 3.4 Slower Iteration Speed in Large Portions of the Control Plane

Many TiProxy modules are closer to cloud/control-plane engineering than to high-performance packet processing, for example:

- API server
- config management
- etcd/topology synchronization
- VIP orchestration
- namespace management
- metering and operational glue code

These parts are already a good fit for Go. Rewriting them in Rust may add complexity without proportional payoff.

### 3.5 Ecosystem and Integration Cost

TiProxy benefits from Go ecosystem alignment in areas such as:

- etcd clients
n- gRPC and HTTP control-plane tooling
- TiDB-adjacent dependencies and implementation proximity
- existing observability and test patterns

A full rewrite would lose part of that leverage and require rebuilding or re-integrating several layers.

---

## 4. Recommended Technical Direction

### 4.1 Do Not Start With a Full Rewrite

The recommended strategy is:

> Keep the Go control plane and evaluate Rust first in the data plane hot path.

That means preserving Go for:

- bootstrap and service lifecycle
- config and API management
- etcd/topology synchronization
- VIP management
- most operational and administrative capabilities

And evaluating Rust first for:

- packet I/O
- protocol encoding/decoding
- forwarding path
- buffer management
- eventually, selected session-migration internals

### 4.2 Why a Hybrid Architecture Is the Most Practical Target

A hybrid model captures most of the upside while reducing delivery risk:

- Go remains the control-plane language, preserving engineering velocity
- Rust is used where safety and performance matter most
- migration can proceed incrementally
- rollback becomes much easier than in a full rewrite

---

## 5. Recommended Phased Migration Roadmap

The migration should proceed in six phases.

### Phase 0: Baseline and Feasibility Assessment

**Goal:** prove whether the rewrite is worth doing.

**Work items:**
- collect CPU, heap, allocation, goroutine, and latency profiles from the current Go implementation
- identify true hot paths and operational pain points
- build benchmark scenarios for:
  - high connection counts
  - TiDB rolling restart/upgrade
  - backend scale-in/scale-out
  - long-lived connections
  - prepared statements
  - failover and rebalance
- define compatibility criteria and rollback strategy

**Deliverables:**
- Go baseline performance report
- top-risk subsystem list
- benchmark suite
- decision memo on whether Rust is justified

**Exit criteria:**
- confirmed hotspot(s) in the data plane
- clear expected value beyond what Go optimization alone can deliver

---

### Phase 1: Minimal Rust Proof of Concept

**Goal:** validate that Rust has real value in the TiProxy context.

**Scope:**
- MySQL packet parser/serializer
- packet forwarding loop
- simplified handshake bridge
- buffer management prototype

**Out of scope:**
- full routing and balancing
- full control plane
- full session migration
- VIP, etcd, or full replay/capture semantics

**Recommended implementation style:**
- start with a standalone Rust prototype or sidecar-style data-plane experiment
- avoid tight FFI coupling too early

**Exit criteria:**
- protocol behavior is correct enough for controlled validation
- benchmark shows measurable gain or significantly better resource behavior
- team confirms engineering model is maintainable

---

### Phase 2: Rust Data-Plane Foundations

**Goal:** build reusable Rust foundations for the forwarding path.

**Candidate modules:**
- packet I/O
- protocol parsing and serialization
- compression/decompression
- buffer pool / allocator strategy
- forwarding loop primitives

**Equivalent current areas in TiProxy:**
- packet I/O and protocol handling
- forwarding hot path around connection relay logic

**Exit criteria:**
- stable low-level library or sidecar with tests
- fuzzing and regression coverage for protocol behavior
- repeatable performance gain under benchmark

---

### Phase 3: Dual-Stack Integration

**Goal:** run Go control plane and Rust data plane together.

**Integration options:**
1. process boundary integration (preferred first)
2. in-process FFI integration (only after the boundary is well understood)

**Why start with process separation:**
- better fault isolation
- easier rollback
- easier debugging
- cleaner validation during early adoption

**Scope in this phase:**
- new connection handling
- basic request forwarding
- baseline TLS/capability handling
- metrics and observability integration
- shadow or mirrored traffic validation

**Exit criteria:**
- Rust path can run in shadow mode safely
- results are comparable to Go path
- per-instance or per-feature rollback is straightforward

---

### Phase 4: Session Migration Core Pilot

**Goal:** carefully move into TiProxy’s highest-value subsystem.

**Scope:**
- redirect signal path
- backend connection manager internals
- graceful close coordination
- limited redirect scenarios

**Recommended rollout order:**
1. non-transactional session migration
2. simple session-state scenarios
3. prepared statements and more complex state later

**Validation required:**
- fault injection
- chaos testing
- rolling restart of TiDB backends
- long-running soak tests
- migration success-rate tracking
- latency and reconnect regression analysis

**Exit criteria:**
- migration semantics are equivalent or better
- failures degrade safely
- no unacceptable regression in connection continuity

---

### Phase 5: Controlled Production Rollout

**Goal:** move from technical success to operational trustworthiness.

**Recommended rollout targets:**
- internal or non-critical clusters first
- read-heavy or less complex workloads first
- namespaces or tenants with strong rollback options first
- canary instances before broad rollout

**Must-have controls:**
- feature flags
- one-click rollback to Go path
- rich metrics and tracing
- compatibility dashboards
- per-stage gating and explicit release criteria

**Exit criteria:**
- stable production canaries
- clear operational runbook
- rollback tested and reliable

---

### Phase 6: Long-Term Architecture Decision

**Goal:** decide the steady-state architecture.

At this point, choose among:

1. **Go control plane + Rust data plane** (recommended default target)
2. broader Rust adoption into the migration core and additional data-plane modules
3. stop at partial Rust adoption if that already captures most of the value

This decision should be made only after production evidence, not before.

---

## 6. Recommended Team Structure

A project like this needs at least four roles:

### 6.1 Protocol / TiProxy Domain Owner

Responsible for:
- protocol compatibility requirements
- TiProxy behavior definition
- migration semantics and acceptance criteria

### 6.2 Rust Systems Lead

Responsible for:
- async and networking model
- buffer and protocol implementation quality
- performance and safety trade-offs

### 6.3 Validation / Benchmark Lead

Responsible for:
- benchmarks
- compatibility suites
- chaos and soak testing
- regression detection

### 6.4 Release / Observability Owner

Responsible for:
- rollout control
- feature flags
- metrics and tracing
- rollback procedures

Without these capabilities, the project is likely to over-focus on implementation and under-invest in validation.

---

## 7. Acceptance Criteria Across All Phases

Every phase should be judged using the same five dimensions:

1. **Protocol compatibility**
   - driver compatibility
   - handshake correctness
   - TLS, compression, and authentication behavior

2. **Connection continuity**
   - no regression in rolling upgrade or backend restart scenarios
   - graceful shutdown remains reliable

3. **Performance**
   - CPU
   - memory
   - allocations
   - throughput
   - tail latency

4. **Stability**
   - soak tests
   - fault injection
   - chaos testing
   - leak detection

5. **Rollback readiness**
   - feature flags
   - fast disable path
   - operational runbook
   - tested rollback in staging and canary

---

## 8. Final Recommendation

A Rust initiative for TiProxy is worth evaluating, but only under a disciplined, staged plan.

**Recommended position:**
- do not launch a full rewrite program immediately
- begin with a narrow Rust PoC on packet and forwarding hot paths
- preserve the Go control plane
- move into session migration only after protocol compatibility and operational safety are proven

In short:

> The right path is not “rewrite TiProxy in Rust.” The right path is “validate Rust where TiProxy needs it most, then expand only when evidence justifies it.”

---

## 9. Reference Areas in the Current TiProxy Codebase

The following parts of the current implementation are especially relevant to this assessment:

- `pkg/server/server.go`
- `pkg/proxy/net/packetio.go`
- `pkg/proxy/backend/authenticator.go`
- `pkg/proxy/backend/backend_conn_mgr.go`
- `pkg/balance/router/router_score.go`
- `docs/design/2024-02-01-multi-factor-based-balance.md`
- `docs/design/2024-07-02-vip-management.md`
- `docs/design/2024-08-27-traffic-replay.md`

These files and design documents show that TiProxy combines a high-frequency data plane with a non-trivial control plane, which is exactly why an incremental migration strategy is preferred.
