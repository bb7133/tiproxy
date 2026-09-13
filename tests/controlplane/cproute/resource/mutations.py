#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile private mutations; require specific assertions, then restore and rerun."""
import os
from pathlib import Path
import shutil
import tempfile

import live

CONFIG = "crates/control-config/src/source.rs"
COLLECTOR = "crates/control-topology/src/metric_collector.rs"
COLLECT = "crates/control-topology/src/metric_collector/collect.rs"
SERVICE = "crates/control-topology/src/metric_collector/service.rs"
SOURCE = "crates/control-router/src/authority.rs"
SELECTOR = "crates/control-router/src/selector.rs"


def main():
    cases = []
    def add(name, path, before, after, family, marker):
        cases.append((name, [(path, before, after)], family, marker))
    add("policy-aba-reused", CONFIG, "if self.resource_incarnation.enabled == previous.resource_incarnation.enabled {\n            self.resource_incarnation = previous.resource_incarnation.clone();\n        }", "self.resource_incarnation.identity = Arc::clone(&previous.resource_incarnation.identity);", "config", "COMPOSE_COALESCED_CONNECTION_ABA")
    add("resource-location-recreated", CONFIG, "if self.resource_incarnation.enabled == previous.resource_incarnation.enabled {", "if false {", "config", "COMPOSE_RESOURCE_LOCATION_CONTINUITY")
    add("policy-identity-compared-by-value", CONFIG, "Arc::ptr_eq(&self.identity, &other.identity)", "*self.identity == *other.identity", "config", "COMPOSE_COALESCED_CONNECTION_ABA")
    add("resource-queries-missing", COLLECTOR, ".filter(|_| lifetime.incarnation.enabled())", ".filter(|_| false && lifetime.incarnation.enabled())", "queries", "COMPOSE_AUTOMATIC_SIX_QUERIES")
    add("connection-keeps-queries", COLLECTOR, ".filter(|_| lifetime.incarnation.enabled())", ".filter(|_| true || lifetime.incarnation.enabled())", "queries", "COMPOSE_CONNECTION_UNSUBSCRIBES")
    add("prom-history-survives-policy", COLLECT, "self.reader = ReaderState::default();", "// old reader retained", "queries", "COMPOSE_PROM_HISTORY_PURGED")
    add("backend-history-survives-policy", COLLECT, "self.reader = ReaderState::default();\n            self.history = History::default();", "self.reader = ReaderState::default();", "queries", "COMPOSE_BACKEND_HISTORY_PURGED")
    add("owner-export-survives-policy", COLLECT, "self.reader = ReaderState::default();\n            self.history = History::default();\n            self.export = Arc::from([]);", "self.reader = ReaderState::default();\n            self.history = History::default();", "queries", "COMPOSE_OWNER_EXPORT_PURGED")
    add("query-lineage-survives-policy", COLLECT, "self.lineage = Arc::new(());\n            self.reader = ReaderState::default();", "self.reader = ReaderState::default();", "queries", "COMPOSE_QUERY_NEW_LINEAGE")
    add("stale-policy-round-published", COLLECTOR, "if !result.queries_current() {", "if false && !result.queries_current() {", "queries", "COMPOSE_POLICY_STALE_ROUND_REJECTED")
    add("snapshot-ignores-query-retirement", COLLECTOR, "result.queries_current()\n                    && result.gate.is_live()", "result.gate.is_live()", "queries", "COMPOSE_POLICY_RETIRES_SNAPSHOT")
    add("snapshot-final-query-fence-bypassed", COLLECTOR, ".all(|result| result.gate.is_live() && result.queries_current())", ".all(|result| result.gate.is_live())", "queries", "COMPOSE_POLICY_FINAL_INPUT_FENCE")
    add("owner-response-captures-retired-query", SERVICE, "result.gate.is_live()\n                && result.queries_current()", "result.gate.is_live()", "service", "COMPOSE_OWNER_CAPTURE_QUERY_FENCE")
    add("owner-write-ignores-query-retirement", SERVICE, "result.gate.is_live() && result.queries_current()", "result.gate.is_live()", "service", "COMPOSE_OWNER_WRITE_QUERY_FENCE")
    add("overlay-accepts-foreign-policy", COLLECTOR, "|| !incarnation.same_as(&self.shared.source.resource_incarnation())", "|| false && !incarnation.same_as(&self.shared.source.resource_incarnation())", "queries", "COMPOSE_OVERLAY_FOREIGN_POLICY")
    add("static-empty-not-source-qualified", SOURCE, "candidate.backend.mode() == control_topology::BackendSourceMode::Static", "candidate.backend.mode() == control_topology::BackendSourceMode::Dynamic", "static", "COMPOSE_STATIC_ACTUAL_EMPTY_SOURCE")
    add("missing-metrics-block-reserve", SELECTOR, "select(None, &crate::factors::Queries::new())", "Err(RouteError::NoBackend)", "missing", "fixture: NoBackend")
    add("resource-path-not-composed", SELECTOR, "|| (self.factors_enabled && candidate.config.resource_incarnation().enabled())", "|| (false && self.factors_enabled && candidate.config.resource_incarnation().enabled())", "live", "COMPOSE_REAL_RESOURCE_PREFERS_HEALTH")
    add("consumer-uses-foreign-current-R", SELECTOR, "metrics.filter(|metrics| Arc::ptr_eq(&candidate.routing, metrics.source().routing()))", "metrics.filter(|metrics| true || Arc::ptr_eq(&candidate.routing, metrics.source().routing()))", "live", "COMPOSE_FOREIGN_CURRENT_R_DATA_IGNORED")
    add("reserve-final-metric-fence-bypassed", SELECTOR, "metrics.with_current(|| select(Some(metrics), &queries))", "Some(select(Some(metrics), &queries))", "live", "COMPOSE_FINAL_INPUT_FENCE_RESERVES_EMPTY")
    add("label-prefilter-changes-CPU-pool", SELECTOR, "input.healthy\n                    && !excluded.contains(&input.id.as_ref())", "input.healthy && input.label_matches\n                    && !excluded.contains(&input.id.as_ref())", "live", "COMPOSE_LABEL_REMAINS_IN_FACTOR_POOL")
    add("retry-exclusion-ignored", SELECTOR, "&& !excluded.contains(&input.id.as_ref())", "&& (true || !excluded.contains(&input.id.as_ref()))", "missing", "COMPOSE_RETRY_EXCLUSION")
    # Policy and metric lineage both retire caches. Disable both deliberately
    # to test the actual cold-start outcome rather than a redundant guard.
    cases.append(("resource-cache-survives-both-retirement-signals", [
        (SELECTOR, "factors.core.clear_resources();", "// policy cache reset bypassed"),
        (SELECTOR, "factors.core.clear_cluster(&cluster);", "let _ = &cluster;"),
    ], "live", "COMPOSE_REAL_QUERY_ABA_COLD_CPU"))
    # Check every anchor before starting any expensive isolated compilation.
    for name, edits, _, _ in cases:
        sources = {}
        for filename, before, after in edits:
            original = sources.setdefault(filename, (live.ROOT / "rust" / filename).read_text())
            if original.count(before) != 1:
                raise RuntimeError(f"composition mutation anchor changed: {name}: {original.count(before)}")
            sources[filename] = original.replace(before, after, 1)
    print(f"CP-ROUTE-COMPOSE {len(cases)} mutation anchors verified", flush=True)
    selected = os.environ.get("CPROUTE_RESOURCE_MUTATION")
    if selected:
        cases = [case for case in cases if case[0] == selected]
        if not cases:
            raise RuntimeError("unknown composition mutation")
    with tempfile.TemporaryDirectory(prefix="cproute-resource-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(live.ROOT / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        fixture = Path("tests/controlplane/cp004/testdata/full.toml")
        (root / fixture).parent.mkdir(parents=True)
        shutil.copyfile(live.ROOT / fixture, root / fixture)
        environment = dict(os.environ, CARGO_TARGET_DIR=os.environ.get("CARGO_TARGET_DIR", str(root / "target")))
        live.baseline(root, environment)
        for name, edits, family, marker in cases:
            originals = {}
            try:
                for filename, before, after in edits:
                    path = root / "rust" / filename
                    original = path.read_text()
                    originals.setdefault(path, original)
                    if original.count(before) != 1:
                        raise RuntimeError(f"composition mutation anchor changed: {name}: {original.count(before)}")
                    path.write_text(original.replace(before, after, 1))
                binaries = live.compile_binaries(root, environment)
                if family == "live":
                    result = live.observe(binaries["control_router"], environment)
                else:
                    binary, selection = {
                        "config": ("source", "resource_incarnation_"),
                        "queries": ("control_topology", "routing_queries_retire_"),
                        "service": ("control_topology", "routing_query_retirement_"),
                        "static": ("control_router", "composed_static_"),
                        "missing": ("control_router", "composed_missing_"),
                    }[family]
                    result = live.run(binaries[binary], selection, environment)
                if result.returncode != 101 or "test result: FAILED" not in result.stdout or marker not in result.stdout:
                    raise RuntimeError(f"composition mutation did not kill its observation: {name}\n" + result.stdout)
                print(f"CP-ROUTE-COMPOSE compiling mutation killed: {name}", flush=True)
            finally:
                for path, original in originals.items():
                    path.write_text(original)
        live.baseline(root, environment)
        print(f"CP-ROUTE-COMPOSE {len(cases)}/{len(cases)} compiling mutations killed; restored baseline passed", flush=True)


if __name__ == "__main__":
    main()
