# TiProxy #223 Rust-only route-owner cutover design

Status: proposal for independent review and human confirmation; no product code has been changed.

Design base: `bb7133/tiproxy:main` `068671fe6259483ab671fc4d9d77c84f9bd8aaa8`, tree `624edb18901e50f0ccf42960b59c57a119b07e8d`.

## 1. Decision and invariant

`proxy.rust-dataplane.enabled` remains the only mode boundary:

- `false`: the existing Go SQL dataplane and Go router run unchanged.
- `true`: the Rust SQL dataplane and the Rust route owner run together. There is no supported `Rust dataplane + Go route owner` combination after #223.

There is no second owner flag and no live owner transition. Changing `rust-dataplane.enabled` still requires a process restart. This preserves the existing operational fallback to the all-Go binary path without retaining two route owners inside the Rust dataplane.

Before a Rust listener may accept SQL, one process-local `RoutePlane` must hold the same control-runtime owner token as CP-CFG and CP-TOPO, have an initial config/namespace snapshot, have registered topology sources for every admitted namespace, and have started the owned migration worker for every admitted router incarnation. Failure of any of those conditions keeps listeners closed. Once ready, Go bridge availability is not a routing-admission condition.

The invariant for every Rust-mode SQL connection is:

> Exactly one Rust router incarnation resolves the user, opens the route session, reserves/settles the initial backend, owns all redirect/failover operations, and closes its ledger entry. No Go callback may select, finish, redirect, rehydrate, or close that route session.

A new additive `RUST_ROUTE_OWNER` control capability is a peer-compatibility assertion, not an owner switch. The bundled peers must negotiate it at initial Rust-mode startup; otherwise startup fails closed. After one compatible startup, a later bridge disconnect or rejected reconnect does not demote routing to Go or stop Rust SQL admission. Metering continues to use its durable local WAL; operator drain is unavailable until CP-ADMIN reconnects.

## 2. Non-goals

- Do not remove the all-Go path used when `rust-dataplane.enabled=false`.
- Do not add a Go/Rust route-owner toggle, per-namespace owner, live owner switch, or chained fallback.
- Do not rehydrate Rust route state into Go after a Go restart. Go is not an owner of Rust sessions.
- Do not rename or directly productionize `MigrationSimulation`; it is explicitly effectless test machinery.
- Do not move CP-METER, CP-ADMIN, public APIs, or VIP ownership into Rust in this issue.
- Do not reuse retired protobuf field numbers. Runtime route traffic is removed now; physical v1 schema tombstones remain until a protocol-v2 change explicitly removes/reserves them.

## 3. Current seam and target composition

### Current production path

`session_engine::BindingRouteChannel` sends `HandshakeResponseEvent`, waits for `HandshakeDecision`, sends `RouteRequest`, waits for `RouteAssignment`, and reports `RouteResult`. Go `controlbridge.RouterAdapter` owns the selector and active accounting. Rust's local `RouteEngine` is dropped after acquisition; Go retains the live route session and later sends `RedirectCommand`. Rust reports `RedirectResult`, `ConnectionEvent`, and reconciliation state.

`control-router::Router`, `Selector`, `Reservation`, `Redirect`, and `ForceClose` already contain the selection, exact-token settlement, retry, accounting, failover, and migration semantics accepted by #147. `MigrationSimulation` owns a real router and worker but deliberately has no production effect sink.

### Target production path

Introduce one binary-composed `RoutePlane` with these owned components:

1. `NamespaceRouterRegistry`
   - Watches the revisioned `ConfigNamespaceSource` and CP-TOPO handle.
   - Builds one `Arc<Router>` per exact namespace incarnation with the process `ModuleContext` and matching `MetricOverlayHandle`.
   - Atomically publishes a read-only admission map.
   - Withdraws a removed/replaced incarnation from new admission immediately and marks it `RetiredDraining`. Its `Arc<Router>`, topology-source lease, and owned migration worker stay alive while any existing `RouteLease` from that incarnation exists.
   - A `RetiredDraining` router admits no new selectors/reservations, but continues the same rebalance, redirect, failover, and timeout-close behavior for its existing sessions over its last-successful inventory and subsequent globally applicable topology/health publications. Namespace-specific binding is frozen to the retired incarnation; global backend state is not frozen.
   - After its last lease and exact token settle, the registry joins that incarnation's worker and only then releases its router and topology-source lease.

2. `UserNamespaceResolver`
   - Runs after the client handshake response has been decoded and before a route session is opened.
   - Only a nonempty configured `frontend.user` is a named identity. A nonempty client user matches that identity exactly; if none matches, it resolves namespace `default`, or returns MySQL 1105 / SQLSTATE `HY000` / `failed to find a namespace` when `default` is absent.
   - Duplicate nonempty user identities across namespaces are rejected atomically. This deliberately fails closed where the current Go map walk is nondeterministic; it is an explicit compatibility divergence requiring confirmation in Section 11.
   - Empty configured user fields never make configuration invalid. For an empty client user, the resolver inspects the raw candidate set rather than relying only on CP-CFG's `NamespaceConfig::serving()` identity projection: exactly one empty-user namespace wins; with several, `default` wins if one of them is `default`; with several and no empty-user `default`, the connection is rejected with MySQL 1105 rather than rejecting the configuration. With no empty-user namespace, ordinary `default` fallback applies.
   - The resolver returns the namespace name plus its exact `NamespaceIncarnation`; `NamespaceRouterRegistry` must prove that pair is still current when opening the selector.
   - An established session never rebinds on config hot change. It retains its original namespace/router incarnation and physical backend. A retired incarnation admits no new session, but its retained router continues normal rebalance/failover/redirect/timeout-close for existing leases until normal close or CP-ADMIN drain.

3. `LocalRouteChannel` / `RouteLease`
   - `LocalRouteChannel` implements the existing `dataplane::RouteChannel` over `control_router::Selector` so `RouteEngine` keeps its established dial budgets, exclusions, error mapping, and retry loop.
   - `request_route` captures the immutable client/listener data. `next_assignment` calls `Selector::next` and retains the exact opaque `Reservation`. `report_result` matches the assignment id and calls `Selector::finish` exactly once; a failed dial leaves the selector ready for the next candidate.
   - After successful acquisition, `RouteEngine::into_parts` returns the local channel. It is converted into a session-long `RouteLease` instead of being dropped. The lease retains the selector/router incarnation and local command registration.
   - `RouteLease::drop` unregisters the command target and closes the selector session. This is the final backstop for pending reservation, active ownership, pending redirect, and force-close accounting.

4. `RouteCommandDispatcher`
   - Replaces the simulation `CommandQueue` at the production effect boundary. The scheduler still prepares under the router lock, then performs only nonblocking `try_send` into a bounded per-session FIFO.
   - The registry key is an unforgeable pair `(router incarnation, opaque route session)`, not the externally supplied connection id. A public connection id is diagnostic only.
   - `Redirect` maps to the existing safe-boundary redirect engine (`PrepareRedirect` / internal commit / backend swap). `ForceClose` maps directly to the Rust session owner; neither crosses the Go bridge.
   - The sink clones a session sender under a short registry lock, releases that lock, and only then performs nonblocking `try_send`; it never calls back into a router while its lock is held. Lease teardown unregisters first, drains/moves every queued envelope and terminal guard into an unlocked local list, releases the registry/FIFO critical section, then drops or settles those guards and calls `Router::close`. No guard destructor or `finish_*` call may run while a registry or FIFO lock is held, so neither `registry -> router` nor `fifo -> router` can invert the scheduler's `router -> try_send` order.
   - Settlement happens outside all registry/FIFO critical sections through the exact captured token. Concurrent offer versus unregister/session-exit is a required M8 stress case, not an assumed ordering.
   - A `Full`/`Closed` `try_send` returns an envelope with no committed pending operation. The returned envelope/guard is moved beyond the router critical section before destruction and is disarmed; the scheduler records cooldown while it still owns the router state. Consequently no terminal guard can call the router recursively from the router lock either.

The Rust binary composition order becomes: claim control owner -> start/wait CP-CFG -> start/wait CP-TOPO and metrics overlay -> build/wait `RoutePlane` -> build the dataplane snapshot/listeners and session owner with an `Arc<RoutePlane>` -> open SQL admission. `tiproxy-rs` and/or `dataplane` gains a normal dependency on `control-router`; `api-replay` remains dev-only.

## 4. Handshake behavior

Rust mode no longer sends or waits for a Go handshake decision. Rust validates the decoded metadata, resolves the user locally, and uses the route plane. To preserve the current default-handler wire behavior, the local implementation advertises `SupportedServerCapabilities`; before user resolution, server-version selection reads `ServerVersion()` from the router of the namespace named `default`, then falls back to `pnet.ServerVersion` when that namespace/router is missing or returns empty. TLS/listener policy comes from the locally composed dataplane/config/topology state. None of these values depends on bridge availability.

The production TiProxy composition currently uses the default Go handshake handler. A non-default Go `HandshakeHandler` cannot remain on the Rust admission path because bridge loss would again block new connections and could change the namespace after Rust resolved it. Therefore:

- Rust mode supports the production default handshake policy implemented locally. The replay-only `StaticHandshakeHandler` is not a production compatibility promise.
- When `rust-dataplane.enabled=true`, a nonnil `sctx.Handler` (or any equivalent non-default Go handshake handler) fails startup as unsupported before listeners open.
- The same custom handler remains available in all-Go mode.

Porting a specific custom policy into a typed Rust hook can be a separate feature; #223 does not preserve an arbitrary Go callback across the ownership boundary.

## 5. Initial route and redirect lifecycle

### Initial acquisition

1. Decode the client response and resolve `(namespace, incarnation)` locally.
2. Open a selector from that exact namespace router; register its local command sender before it can become active.
3. `Selector::next` is the sole source of candidate eligibility and exclusions. The channel must not apply a second bridge-era exclusion list; any nonempty external exclusion input in Rust-owner mode is rejected as a composition error rather than silently producing different candidates. T2 proves that `RouteEngine` supplies an empty `excluded_backend_ids` on the initial request and every re-request; if an existing call site supplies a legitimate nonempty value, T2 removes that input at the call site rather than relying on a runtime rejection.
4. For each candidate, retain its exact `Reservation`, dial under existing per-attempt/total budgets, then settle `finish(false)` or `finish(true)` once.
5. A local timeout/cancellation before result delivery is covered by the route lease drop; no pending reservation may outlive the session task.
6. On success, retain the lease for the whole physical session. Backend metadata continues to initialize TLS, PROXY, auth, metering, keepalive, and logs as today.

### Redirect

- A scheduler offer is admitted only if `try_send` succeeds. `Full` or `Closed` means **no pending operation, cooldown recorded** and the scheduler may reconsider it in a later round. No accepted command is silently dropped.
- The session FIFO admits at most one redirect token because the router ledger rejects another while one is pending. The session engine additionally keys execution by the exact token and ignores a duplicate delivery.
- On successful backend handshake and safe swap, `finish_redirect(token, true)` transfers active accounting once.
- Dial, handshake, unsafe-state, cross-keyspace, or deadline failure leaves the old backend active and calls `finish_redirect(token, false)` once.
- A redirect dequeued after its deadline is not executed and is settled false. An admitted envelope dropped because its receiver/session disappears owns an RAII terminal guard: after all FIFO/registry locks are released, it settles redirect false unless the session's route-lease drop has already closed it. Duplicate/late completion is `Settlement::Ignored`.
- Session abnormal exit drops the route lease, which closes the active entry and releases a pending redirect. A later token completion is ignored.

### Force close

- A full/closed session FIFO means **no pending operation, cooldown recorded** for `ForceClose`; the worker may retry on a later tick while the ledger still shows an active session. A racing session exit removes that ledger entry through the lease.
- Once admitted, force close has no expiry: the session executes the local close even if delayed behind an in-flight safe boundary.
- Physical session termination calls `observe_close` with the exact token. Route-lease drop is the backstop; duplicate or late observation is ignored.

These rules make the command effect at-most-once and the accounting terminal exactly-once/ignored-on-duplicate. Queue rejection never creates an unsettled operation.

## 6. Bridge message disposition

“Phase 1” means Rust has taken ownership and the live matrix is running, while old adapter source remains for diagnosis. “Phase 2” is the separate deletion PR after Phase 1 passes.

| Message/family | Phase 1 Rust-owner runtime | Phase 2 repository disposition | Residual owner/reason |
|---|---|---|---|
| `Hello`, `HelloAck`, `Heartbeat`, `ProtocolError` | Keep. Negotiate `RUST_ROUTE_OWNER`; transport health is observable but not route authority. | Keep. | Shared transport. |
| `StateSnapshot`, `SnapshotResult` | Keep only while needed for residual static/dataplane facts. With `RUST_ROUTE_OWNER`, Go must send empty backend/namespace lists and Rust rejects nonempty lists. SQL admission is driven by local CP-CFG/CP-TOPO state and does not expire after bridge loss. | Keep the minimal residual snapshot adapter; tombstone backend/namespace fields pending protocol v2. | Static handshake/listener/TLS compatibility and snapshot acknowledgement; no routing input. |
| `HandshakeResponseEvent`, `HandshakeDecision`, `HandshakeResult` | Stop producing/awaiting them in Rust mode. Receiving one in the route-owner capability is a nonfatal protocol violation with zero callback/effect. | Delete RouterAdapter handlers and Rust correlated-response code; keep v1 tags/types deprecated as wire tombstones. | Route-coupled; no CP-METER/ADMIN reason to retain. |
| `RouteRequest`, `RouteAssignment`, `RouteResult` | Zero production traffic. Any received message is rejected/ignored without route mutation and counted as a legacy-route violation. | Delete Go producer/consumer adapter paths, `BindingRouteChannel`, wire conversion, response expectations, and route-request reconciliation. Keep numeric v1 tombstones until v2. | Fully retired by Rust in-process selection/reservation. |
| `ConnectionEvent` | Stop route/accounting publication. Rust metrics and metering use their dedicated channels. | Delete RouterAdapter connection lifecycle/accounting handlers and Rust route event journal. Keep v1 tombstone. | Route-coupled; CP-ADMIN drain enumerates Rust sessions locally. |
| `RedirectCommand`, `RedirectResult` | Zero production traffic; Rust scheduler dispatches local exact tokens. Legacy inbound commands cannot reach a session. | Delete Go redirect issuance/result handling and Rust redirect command gate/wire result code. Keep v1 tombstones. | Fully retired. |
| `CloseCommand`, `CloseResult` | Zero production traffic for route failover/orphan repair; Rust `ForceClose` is local. | Delete the route/orphan close bridge path and stop negotiating `PER_CONNECTION_CLOSE`. Keep v1 tombstones. | CP-ADMIN keeps scoped `DrainCommand`, not per-route close. |
| `DrainCommand`, `DrainResult` | Keep unchanged. They may share a session FIFO but never call the router or settle a route token. | Keep. | CP-ADMIN/operator drain. |
| `MetricsBatch` | Keep; route-owner metrics are added to the existing closed catalog. Bridge loss may defer/drop best-effort export but not routing. | Keep. | Observability. |
| `MeteringBatch`, `MeteringAck` | Keep unchanged with durable local WAL and absolute-source identity. Bridge loss buffers/replays under existing bounds; a true durable-metering fatal condition still stops admission. | Keep. | CP-METER. |
| `ReconcileRequest`, `ReconcileSnapshot` | Retain only the residual envelope. `connections=[]`, `last_connection_event_sequence=0`, and response `connections=[]` are mandatory in route-owner mode. Keep `known/applied_generation`, metrics/metering watermarks where still consumed, and `last_drain_command_sequence` for Go issuer restart. Reconcile must not create, finish, redirect, rehydrate, or close a route session. | Delete RouterAdapter reconciliation/orphan code. Replace delegation with a small residual CP-METER/CP-ADMIN/snapshot handler. Keep v1 fields as zero/empty tombstones until a future owner-specific v2 split. Stop negotiating `RECONCILE_CONNECTIONS` and `RECONCILE_SESSION_REHYDRATION`. | CP-ADMIN drain sequence; CP-METER legacy/compatibility watermark; snapshot/metrics acknowledgement only. |

Phase 1 installs the residual Go handler instead of constructing `RouterAdapter` for Rust mode and deletes/replaces the periodic `bridge.adapter.ResolveOrphans` loop. The source file remains available only for legacy bridge tests/comparison and Phase 1 diagnosis. Go `ScoreBasedRouter`/health-observer objects may still exist for the all-Go public/API/metrics composition, but the Rust-mode evidence must prove zero Go selector calls or route effects and zero Go-owned Rust connection-map entries.

## 7. Live source-error completion

This is a Phase 1 CP-TOPO -> CP-ROUTE input sub-slice and a prerequisite to calling the matrix complete.

The live network discovery/health producer must publish a qualified `ObserverError` generation under the same source, namespace-incarnation, and stale-update fences used for successful snapshots. Its semantics must match the accepted `api-replay` behavior:

- A current source error blocks a new initial `Selector::next` reservation with its typed class. It does not invent a blanket pause for retained callbacks: migration/failover/timeout-close behavior over the last successful inventory remains exactly the #147 api-replay behavior, including timeout closure while an observer error is current.
- The last successful routing inventory, health metadata, server version, lookup, existing assignment, exact token settlement, and session lifecycle remain available.
- A successful later result clears the error.
- An authoritative successful empty result is different from a polling error and replaces inventory as empty.
- A stale/duplicate error cannot replace a newer success or another source incarnation.
- Only the closed, redacted error identity catalog is published; arbitrary diagnostics do not enter routing state.

This slice closes the README's explicit “network discovery retains last success but does not forward the failed poll” limitation. It is not bridge work: CP-TOPO produces the fenced input locally and CP-ROUTE consumes it locally.

## 8. Live protocol matrix

The acceptance matrix has 36 logical cells: nine scenario rows by four protocol columns. Every logical cell uses a real Rust dataplane process and real TiDB backends, not api-replay or a mock selector.

Protocol columns:

- `P`: plain MySQL.
- `T`: frontend and backend TLS.
- `X`: inbound and outbound PROXY v2, including preserved address/TLV behavior.
- `C`: compression; a cell passes only when both zlib and zstd sub-runs pass.

Thus the minimum physical count is 45 runs (three single variants plus two compression sub-runs per row). The existing combined `tls-proxy-zstd` variant is an additional cross-feature sentinel for rows M1, M7, and M9, giving 48 minimum physical runs without pretending those sentinels are new logical requirements.

| Row | Scenario (run under P/T/X/C) | Cell-specific pass condition |
|---|---|---|
| M1 | Baseline admission, nonempty/empty-user/default resolution, initial dial retry, SQL traffic, normal close | Correct namespace/cluster/keyspace/backend for every Section 3 empty-user branch; failed reservations settle; one active owner after success; query succeeds; CP-METER totals equal accepted SQL across initial retry and normal close; final ledger zero. |
| M2 | Namespace/config hot change and namespace replacement/removal | New sessions use the new exact incarnation; existing sessions keep the old binding. After replacement, a backend failure proves the retained old router still redirects/fails over/closes its existing lease while admitting no new sessions. Duplicate nonempty identity is rejected atomically as the approved divergence; empty user fields remain valid config and use the connection-level rule; missing default returns the exact approved error. |
| M3 | Topology generation rotation: add/remove/reorder backend, label/locality/version changes | Only current generation influences new selection; stale publication has zero effect; current backend removal follows the defined failover path; retained lease/token settlement remains valid; advertised server version exactly matches the current Go default-handler rule, including `pnet.ServerVersion` override/fallback. |
| M4 | Health rotation plus live source error, authoritative empty, and recovery | Current error blocks new initial selection while existing SQL and retained lookup/settlement continue; retained failover timeout closure still works; empty success yields no backend; later healthy success clears the error; stale error cannot roll back recovery. |
| M5 | Resource/Location metrics generation rotation, stale/wrong-source/no-data cases | Only routing-bound current metrics influence selection/migration; stale/wrong-source data has zero effect; a no-data round uses the accepted retained-history semantics. Evidence must contain real nonempty health and CPU/memory inputs for the live Resource/Location claim; otherwise the cell is incomplete, not pass. |
| M6 | No backend, listener-port routing conflict, OS listener bind conflict, unsupported custom Go handshake handler, correction and recovery | Exact client-visible no-backend vocabulary; routing conflict reserves nothing and mutates no counts; bind failure rolls startup back without a partial listener; `enabled=true` plus nonnil `sctx.Handler` fails before any listener opens; correcting config/topology permits a fresh session without restarting the Rust owner where the change is reloadable. |
| M7 | Redirect/rebalance/failover: success, refused/cross-keyspace/unsafe, target dial/handshake failure, timeout force close, and CP-ADMIN drain overlap | Success swaps exactly once; every failure keeps the old backend usable and settles false; cross-keyspace never dials; failover timer/health generation is bound; drain racing a pending redirect or force close has one deterministic terminal outcome and closes the SQL session once; CP-METER totals remain conserved across a successful redirect; final counts zero. |
| M8 | Local terminal robustness: duplicate/lost completion injection, command FIFO full/closed, redirect expiry, session crash, and concurrent offer versus unregister | Test-only fault seam never changes production defaults. Duplicate terminals are ignored; an intentionally dropped local completion is recovered by RAII/session close or fails the session closed; queue rejection is `no pending operation, cooldown recorded`; a stress/barrier test forces offer against unregister/session-exit and proves no registry/FIFO/router lock inversion, no guard drop under a lock, no duplicate migration, and no unsettled token. |
| M9 | Route-bridge disconnect; Go-only restart; Rust-only restart; whole-process restart, in both quiet and in-flight states | Bridge disconnect and Go restart do not interrupt existing SQL, redirect/failover lifecycle, or new Rust-mode admission. CP-ADMIN drain after reconnect uses its restored watermark and closes each targeted Rust session once. Rust restart disconnects old SQL exactly once, starts with an empty route ledger, rebuilds local sources, and admits fresh sessions; no ghost owner survives. Whole restart leaves no stale port/lease/WAL identity collision. |

M9's bridge-disconnect interval must exceed the old 30-second last-good grace. New connections must still succeed after the grace, proving route admission no longer depends on the bridge. The test also checks that bridge loss does not silently disable an already due local redirect/force-close. CP-METER WAL and CP-ADMIN reconnect results are audited separately; a deliberately injected durable-metering fatal is not classified as a routing failure.

## 9. Global pass criteria and evidence

Every cell must satisfy all of these gates:

1. Correct client-visible result and scenario-specific generation/target assertion.
2. Exactly one `RoutePlane` router-incarnation/session identity per admitted connection; no namespace rebind.
3. Every reservation, redirect, and force-close token ends `Applied` once or `Ignored` only for an asserted duplicate/late terminal; final reserved/active/incoming/outgoing and unsettled-operation counts are zero after cleanup.
4. A bridge frame tap records zero `Handshake*`, `Route*`, `ConnectionEvent`, `Redirect*`, and `Close*` route traffic, and zero nonempty routing fields in reconcile, for the complete Rust-mode run.
5. The Go residual handler records zero `RouterAdapter` constructions, Go selector calls/effects for Rust sessions, route finishes, redirect issues, orphan rehydrates, and route closes. Go router/observer objects retained for all-Go public/API/metrics duties need not be absent, but must receive zero Rust connection identities or calls. Injecting any retired route body produces a protocol-violation counter and zero side effects.
6. Bounded queues remain within configured limits; full/closed/expired outcomes match Section 5 and cannot block the SQL forwarding loop.
7. No panic, task leak, duplicate listener, residual child process, unclosed socket, leaked router incarnation, or unflushed terminal ledger at teardown.
8. Exact commit/tree, build hashes, config, protocol variant, source generations, process lineages/restart steps, bridge-body counts, route-ledger before/after snapshots, and test result are written to a machine-readable manifest.

The runner is first-failure-stop and never changes production behavior to obtain a pass. A failed cell is preserved and not replaced by a rerun; a repair requires a new exact tree and a fresh full matrix. Unit/focused coverage, `make rust-lint`, `make rust-test`, `make rust-build`, Go retained-path tests, and exact-head independent review are additional gates, not substitutes for the live cells.

## 10. Delivery plan

### Phase 1 — Rust takeover and live qualification

Use four reviewable checkpoints on one #223 implementation line:

1. **T1: local authority inputs** — user/namespace validator and resolver, namespace-router registry with retained topology-source leases, production `MetricCollector::bind_for_routing` wiring, live source-error publication/consumption, readiness and incarnation tests.
2. **T2: local initial route** — `LocalRouteChannel`, session-long `RouteLease`, local handshake decision, removal of bridge route acquisition from the Rust production path, and initial retry/accounting fault tests.
3. **T3: local migration lifecycle** — production command dispatcher, scheduler worker (including retained-incarnation migration), redirect/force-close terminal guards drained and settled only outside registry/FIFO locks, direct session execution, Rust restart cleanup, and bridge-independent supervision.
4. **T4: ownership fence and qualification** — Go residual handler with RouterAdapter absent, `bridge.adapter.ResolveOrphans` removed/replaced, capability/tombstone enforcement, bridge tap/single-owner metrics, ADR/README/inventory update, 36-cell logical matrix plus physical sub-runs and independent artifact review.

Do not call the cutover complete at T2: initial routing without local migration, live source errors, and bridge-independent teardown is not an owner implementation.

### Phase 2 — separate deletion PR

After the exact Phase 1 tree passes the complete matrix and is reviewed/merged:

- delete `pkg/controlbridge/router_adapter.go` and its Rust-dataplane adapter-only tests/composition;
- delete `BindingRouteChannel`, correlated handshake/route responses, route portions of `control_dispatch`/`control_commands`/`session_control`, and legacy route event/reconcile journals;
- delete Go bridge redirect/orphan/per-route-close paths while retaining the all-Go `pkg/balance/router` implementation;
- reduce `CompositeControlHandler` to snapshot/static, CP-METER, metrics, CP-ADMIN drain, transport, and residual zero-routing reconcile;
- stop advertising the three retired reconcile/close capabilities;
- keep deprecated v1 protobuf tags/types as non-actionable tombstones and document that physical schema removal/tag reservation is a protocol-v2 task;
- rerun bridge-tap negative tests and retained all-Go/Rust-mode smoke tests to prove deletion did not reintroduce a hidden fallback.

Phase 2 must be reviewable as pure dead-path deletion plus residual-handler simplification. It must not contain new routing semantics or be used to repair a Phase 1 matrix failure.

## 11. Confirmation points

Human confirmation of this design specifically accepts these behavior choices:

1. no separate owner flag; `rust-dataplane.enabled=true` means Rust route owner;
2. all-Go remains the restart-level fallback via `enabled=false`;
3. Rust mode supports local/default handshake policy and fails startup for an arbitrary custom Go handshake handler;
4. duplicate **nonempty** user identities fail configuration atomically instead of preserving Go's nondeterministic map-walk behavior; empty configured users remain valid and follow the connection-level rule in Section 3;
5. existing sessions retain their namespace/router incarnation across hot change rather than rebinding, while that retired router keeps rebalance/failover/redirect/timeout-close active for those sessions;
6. route-related v1 runtime paths are deleted, while their numeric schema entries remain tombstones until protocol v2;
7. Phase 1 must pass the complete bridge-independent live matrix before the separate deletion PR begins.
