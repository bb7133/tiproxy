#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compiling collector mutations must fail the named runtime assertion, then restore."""
import os
from pathlib import Path
import shutil
import tempfile
from collector import baseline, compile_binary, observe


def replace(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f"mutation anchor must be unique: {before!r}: {source.count(before)}")
    return source.replace(before, after)


def within(source, function, before, after):
    start = source.index(function)
    end = source.index("\n    }", start)
    return source[:start] + replace(source[start:end], before, after) + source[end:]


def main():
    repo = Path(__file__).resolve().parents[3]
    collector = "control-topology/src/metric_collector.rs"
    collect = "control-topology/src/metric_collector/collect.rs"
    service = "control-topology/src/metric_collector/service.rs"
    owner = "control-topology/src/metric_collector/owner.rs"
    peers = "control-topology/src/metric_owner.rs"
    authority = "control-etcd/src/authority.rs"
    session = "control-etcd/src/session.rs"
    history = "control-topology/src/metrics/history.rs"
    scoped = "collector_real_scoped_cleanup_and_retained_http"
    mixed = "collector_real_go_rust_owner_history_and_peer_replacement"
    prom = "collector_real_prom_round_labels_empty_and_delayed_source"
    binding = "collector_binding_and_final_generation_publication"
    response = "collector_response_retirement_at_write_boundary"
    batch = "collector_backend_batch_joins_errors_panics_and_revocation"
    cases = []

    def case(name, path, before, after, test, marker, live=True):
        cases.append((name, path, lambda source: replace(source, before, after), test, marker, live))

    case("retained-authority-ignores-scope", authority,
         "base_live && self.scope.is_live()", "base_live", scoped, "COLLECTOR_SCOPE_DIRECT_AUTHORITY")
    case("keepalive-ignores-expired-scope", session,
         "} else if !scope.is_live() {", "} else if !scope.is_live() && false {",
         scoped, "COLLECTOR_SCOPE_KEEPALIVE_RETIRES")
    case("early-scope-revoke-skips-lease-cleanup", session,
         "if lease_id != 0\n                && let Err(source)",
         "if lease_id != 0 && self.authority.retains_local_ownership()\n                && let Err(source)",
         scoped, "COLLECTOR_SCOPE_REMOTE_CLEANUP_REQUIRED")
    case("partial-failed-batch-completes", collect,
         "tasks.shutdown().await;\n            return Err(error);", "tasks.shutdown().await;\n            let _ = error; return Ok(());",
         batch, "COLLECTOR_BACKEND_PANIC_NOT_COMPLETED", False)
    case("canceled-children-not-joined", collect,
         "tasks.shutdown().await;\n            return Err(error);", "return Err(error);",
         "collector_batch_waits_for_canceled_child_destructor", "COLLECTOR_CANCEL_JOIN_BEFORE_RETURN", False)
    case("backend-concurrency-limit-dropped", collect,
         "while tasks.len() < 100 {", "while tasks.len() < 101 {", batch, "COLLECTOR_BACKEND_MAX_100", False)
    case("purge-before-missing-fallback", collect,
         "let missing = history.missing(rules, &all);",
         "history.purge(rules, now_nanos()? / 1_000_000);\n    let missing = history.missing(rules, &all);",
         mixed, "COLLECTOR_MISSING_BEFORE_PURGE")
    case("requires-every-rule-to-suppress-fallback", history,
         "!rules.iter().any(|rule| {", "!rules.iter().all(|rule| {", mixed, "COLLECTOR_ANY_RULE_PREVENTS_FALLBACK")
    case("exports-unselected-backends", collect,
         "let labels: Vec<_> = selected", "let labels: Vec<_> = all", mixed, "COLLECTOR_GO_CONSUMES_RUST_SELECTED_HISTORY")
    case("peer-address-equality-requalifies-aba", peers,
         "current.members == members",
         "current.members.len() == members.len() && current.members.iter().all(|(zone, record)| members.get(zone).is_some_and(|other| record.value == other.value))",
         mixed, "COLLECTOR_OBSERVED_PEER_REPLACEMENT_REVOKES")
    case("peer-not-rechecked-after-http", collect,
         "let observed = observe_owners(capture, cluster, &mut state.observation).await?;",
         "let observed = Arc::clone(&peers);", mixed, "COLLECTOR_PEER_RECHECK_AFTER_HELD_HTTP")
    case("failed-completed-round-keeps-old-backend-map", collect,
         "reader.complete_backend(history.results(rules, cluster, updated), succeeded);",
         "if succeeded { reader.complete_backend(history.results(rules, cluster, updated), succeeded); }",
         mixed, "COLLECTOR_COMPLETED_ERROR_REPLACES_BACKEND_MAP")
    case("successful-empty-prom-falls-back", collect,
         "Ok(results) => {", "Ok(results) if results.values().all(QueryResult::is_empty) => {}\n        Ok(results) => {",
         prom, "COLLECTOR_PROM_EMPTY_NO_FALLBACK")

    def persistent_component(source):
        source = replace(source, "let mut results = BTreeMap::new();",
            "static COMPONENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);\n    let mut results = BTreeMap::new();")
        source = replace(source, "for expression in rule.spec().expressions() {",
            'for expression in rule.spec().expressions() { if COMPONENT.load(std::sync::atomic::Ordering::SeqCst) && expression.contains("job=") { continue; }')
        return replace(source, "if matches!(&last, Ok(result) if !result.is_empty()) {\n                break;",
            'if matches!(&last, Ok(result) if !result.is_empty()) { if expression.contains("component=") { COMPONENT.store(true, std::sync::atomic::Ordering::SeqCst); }\n                break;')
    cases.append(("component-choice-persists-between-rounds", collect, persistent_component, prom,
                  "COLLECTOR_PROM_LABEL_RESETS_EACH_ROUND", True))
    case("first-round-waits-for-interval", collect,
         "ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);",
         "ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip); ticks.tick().await;",
         "collector_real_immediate_first_round", "COLLECTOR_IMMEDIATE_FIRST_READ")
    case("final-work-check-skipped", collector,
         "work.with_current(put).unwrap_or(false)", "{ let _ = work; put() }",
         scoped, "COLLECTOR_UNCERTAIN_FINAL_WORK_REJECTED")
    cases.append(("uncertainty-discards-retained-http", authority,
        lambda source: within(source, "pub fn with_retained<T>",
            "ElectionState::Leader | ElectionState::Uncertain", "ElectionState::Leader"),
        scoped, "COLLECTOR_HTTP_UNCERTAIN_RETAINED", True))
    case("listener-exit-keeps-serving", service,
         "impl Drop for ServingGuard {\n    fn drop(&mut self) {\n        self.0.close();",
         "impl Drop for ServingGuard {\n    fn drop(&mut self) {\n        let _ = &self.0;",
         scoped, "COLLECTOR_LISTENER_DROP_REVOKES")
    case("collector-drop-keeps-serving", collector,
         "impl Drop for MetricCollector {\n    fn drop(&mut self) {\n        self.shared.serving.close();",
         "impl Drop for MetricCollector {\n    fn drop(&mut self) {\n        let _ = &self.shared;",
         binding, "COLLECTOR_DROP_SERVING_REVOKED", False)
    case("empty-http-response-skips-final-serving-check", service,
         "self.is_live().then(write)", "Some(write())", response,
         "COLLECTOR_EMPTY_RESPONSE_FINAL_SERVING_CHECK", False)
    case("scope-ignores-parent-stop", owner,
         "            && !*self.external_stop.borrow()\n", "", mixed,
         "COLLECTOR_STOP_DIRECT_SCOPE_WITHDRAWAL")

    def no_final_source(source):
        return within(within(source, "fn publish(",
            "capture\n                    .with_current(|| {", "(|| {"), "fn publish(",
            "                    })\n                    .unwrap_or(false)", "                    })()")
    cases.append(("final-applied-source-check-skipped", collector, no_final_source, binding,
                  "COLLECTOR_STALE_PUBLICATION", False))

    with tempfile.TemporaryDirectory(prefix="cpmetric-collector-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        environment = dict(os.environ, CARGO_TARGET_DIR=os.environ.get("CARGO_TARGET_DIR", str(root / "target")))
        paths = {path for _, path, *_ in cases}
        originals = {path: (root / "rust/crates" / path).read_text() for path in paths}
        baseline(root, environment)
        failures = []
        for name, path, mutate, test, marker, live in cases:
            file = root / "rust/crates" / path
            try:
                file.write_text(mutate(originals[path]))
                binary = compile_binary(root, environment)
                result = observe(binary, test, live, environment)
                if result.returncode != 101 or marker not in result.stdout or "test result: FAILED." not in result.stdout:
                    raise RuntimeError(f"collector mutation did not fail its named assertion: {name}\n{result.stdout}")
                print(f"CP-METRIC-COLLECTOR compiling mutation killed: {name}", flush=True)
            except Exception as error:
                failures.append(f"{name}: {error}")
                print(f"CP-METRIC-COLLECTOR mutation failed validation: {name}: {error}", flush=True)
            finally:
                file.write_text(originals[path])
        baseline(root, environment)
        if failures:
            raise RuntimeError("collector mutation validation failed:\n" + "\n".join(failures))
        print(f"CP-METRIC-COLLECTOR {len(cases)}/{len(cases)} compiling mutations killed; restored baseline passed", flush=True)


if __name__ == "__main__":
    main()
