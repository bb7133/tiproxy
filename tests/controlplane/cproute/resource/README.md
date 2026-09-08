# Composed Resource/Location routing evidence

Run `make controlplane-cproute-resource-evidence`. The independent
`resource-routing` CI job runs this complete entrypoint, including compilation
of every mutation and a restored baseline. The older CP-ROUTE (46 mutations),
CP-METRICS factor (95 Go observations/30 mutations), collector, applied-source,
data-core and CP-002/003/004/TOPO entrypoints remain required.

## Runtime boundary

`Router::new_with_factors` explicitly enables Resource/Location selection.
`Router::new` retains its Connection-only staged behavior, including typed
`Unsupported` evidence. Production dataplane/manifest composition is still off
until the integration slice; timed balancing/migration is separate work.

Candidates retain actual C/R/H and the namespace's `BackendSourceSnapshot`.
Only `Sources` can construct static empty inputs, after observing its applied
Static mode. Dynamic inputs come from `MetricCollector::bind_for_routing` and
are paired with the exact routing object and config-issued factor incarnation.
Absent, foreign, unmatched, or retired metrics mean empty inputs with no cache
lineage. They never independently reject a reserve. This follows the existing
Go missing-query behavior, including its distinction between an entirely empty
CPU query and a nonempty query missing an individual backend.

Selection, factor-cache commit, and pending accounting use the existing single
ledger mutex. A current metric snapshot fences the synchronous evaluation and
reservation; a lost input fence causes reevaluation with empty inputs. Final
C/R/H, namespace, mode, process and lifecycle checks still authorize the effect.
Already-issued attempts retain their original settlement owners.

Resource/Location share one config-issued opaque incarnation. Each accepted
transition into/out of Connection changes it synchronously at config
publication, even when a watch receiver misses the intermediate value. The
automatic collector owns six queries, resets both Prometheus and backend
history when the incarnation changes, and fences old round publication,
snapshots, and owner HTTP responses. It preserves the actual owner worker.
Router cache continuity also checks this incarnation. Unrelated config changes
and Resource/Location switches preserve continuity.

## Observations

- The actual Go config/factor/`Group.Route` implementation produces the expected
  choices and pending deltas; real `setFactors` registers six queries, preserves
  them across Resource/Location, and removes/recreates them across Connection.
- Owned real etcd, SQL greetings, backend/status HTTP, Prometheus HTTP, topology,
  health, metrics collector and router reserve select the matching Go backend
  for Resource, Location, business labels, missing/restored inputs and retries.
  Active and pending counts remain distinct.
- A cold router with one label match retains both healthy backends in the factor
  pool. Removing the label and then omitting that backend's CPU sample proves
  the first reservation populated its CPU cache.
- A current foreign metric donor paired with a genuine foreign C/R/H candidate
  is discarded; no DTO is used as routing authority.
- Holding actual Prometheus responses while R changes leaves reservations
  available. Completing collection restores metric-based selection.
- A barrier runs after six queries are read, under the ledger lock, before the
  final metric fence. Retiring the real collector here must reserve using empty
  inputs. Connection also continues with the collector stopped.
- Real static SQL greeting health authorizes static empty inputs; namespace ABA
  and stale C reject new effects while old pending attempts still settle.
- Unit boundaries cover coalesced config policy changes, source identities,
  query/history/export cleanup, old-round publication, and owner HTTP capture
  and final writes.

The mutation entry compiles 23 isolated variants and requires each named
assertion to fail. One deliberately coupled variant disables both independent
resource-cache retirement signals to verify the cold-start outcome. Compilation
failures, unrelated panics, absent tests, and surviving variants fail the gate.
Each live run owns and stops its embedded-etcd fixture; HTTP/module lifetimes
are owned by the test. No SQL payload crosses a control-protocol bridge.
