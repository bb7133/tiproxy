# Router API differential implementation

The four acceptance/inventory files are unchanged from frozen a9c497c3,
confirmed in message 53119a02. Their endpoint is the completion criterion.

The initial implementation connects one common input to the real Go router,
factor policy and selector, and the real Rust module sources, router and
selector. The adapters never receive oracle outputs. They report public
results and client assignments; the comparator independently reconstructs the
logical connection ledger from Next/Finish/close results and checks public
connection accounting. Ambiguous choices must belong to the declared legal
set; uniquely specified choices and error classes must match.

Run the synthetic adapter check:

```sh
python3 tests/controlplane/cproute/api-differential/run.py \
  tests/controlplane/cproute/api-differential/smoke.json --output /tmp/router-api-new-run
```

Use a new output directory for each run. The runner preserves both raw outputs,
input hash, source identity and command logs. CI runs it in one 45-minute job.
Synthetic adapter checks count as zero recorded traces and zero corpus rounds.

Go replay drains its background loop after the real Init and delivers inputs
synchronously to the exact production health/config handlers. Rust replay uses
the existing topology module fixture and real clients to deliver source values.
Both then call their actual public selector and accounting APIs. This is input
scheduling in a test adapter, not a duplicate routing implementation. No internal
caller capture is attached. Recording will use the live Go loop and actual
TiDB/PD/Prometheus sources, preserving values at these external boundaries.

Implementation is limited to three increments of the same replacement PR:

1. Common input validation, Go/Rust API adapters and basic selection/retry/
   Finish/close comparison. This initial smoke has 19 events; it verifies empty
   initialization, two-backend selection/retry, unique selection after removal,
   invalid config rejection and the final empty connection ledger.
2. External health/config/metric/error inputs, migration/close callbacks,
   rehydration and clock scheduling; live recorder using the existing test
   environment; finish the same comparator's eight mutation checks.
3. Record and freeze all 18 real traces; run the fixed three focused suites,
   six fixed distribution comparisons and K=3 corpus rounds on the candidate
   tree. Diagnose actual failures without replacing traces or changing limits.

Current acceptance counts: recordings 0/18, rounds 0/3, focused suites 0/3,
comparator mutants 0/8. The initial adapter rejects unsupported operations;
it does not silently treat missing implementation as a passing observation.
Old instrumentation deletion stays in a separate PR after replacement
acceptance. No old per-getter, caller-envelope or per-boundary fault work is
part of these increments.
