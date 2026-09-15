#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile isolated factor mutations and kill the specific Go/live observations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import live

ROUTER = "crates/control-router/src/"
TOPOLOGY = "crates/control-topology/src/"
RESOURCE = ROUTER + "factors/window.rs"
TIME = ROUTER + "factors/resource.rs"
PHASES = ROUTER + "factors/phases.rs"
FACTORS = ROUTER + "factors.rs"
SELECTOR = ROUTER + "selector.rs"
COLLECTOR = TOPOLOGY + "metric_collector.rs"
COLLECT = TOPOLOGY + "metric_collector/collect.rs"


def compile_binaries(root, environment):
    result = subprocess.run(["cargo", "test", "--locked", "--offline", "--no-run", "--message-format=json",
        "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-router", "-p", "control-topology", "--lib"],
        env=environment, text=True, capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError("factor mutation did not compile:\n" + result.stderr + result.stdout)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    binaries = {item["target"]["name"]: item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact" and item.get("executable")}
    if set(binaries) != {"control_router", "control_topology"}:
        raise RuntimeError(f"unexpected factor artifacts: {binaries}")
    return binaries


def run(binary, selection, environment):
    return subprocess.run([binary, selection, "--nocapture", "--test-threads=1"], env=environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)


def main():
    original_root = live.ROOT
    if not Path(os.environ["CPMETRICS_FACTOR_OUTPUT"]).is_file():
        raise RuntimeError("run the complete factor entrypoint first")
    # name, source, before, after, observation family, selected Go case, failure marker
    cases = [
        ("cpu-ewma", RESOURCE, "avg * 0.5 + latest * 0.5", "avg * 0.4 + latest * 0.6", "core", "cpu-ewma", "FACTOR_"),
        ("cpu-missing-default", RESOURCE, "return (1.0, 1.0);", "return (0.0, 0.0);", "core", "two-cluster-global-fresh-stale-cache", "FACTOR_"),
        ("cpu-snapshot-count-includes-pending", RESOURCE, "connections: input.physical(),", "connections: input.score_count(),", "core", "cpu-pending-active-only-snapshot", "FACTOR_"),
        ("cpu-extrapolation-excludes-pending", RESOURCE, "input.score_count().difference(value.connections)", "input.physical().difference(value.connections)", "core", "cpu-pending-active-only-snapshot", "FACTOR_"),
        ("cpu-idle-estimate-reset", RESOURCE, "per = self.usage_per_conn;", "per = 0.001;", "core", "cpu-idle-per-connection-reuse", "FACTOR_"),
        ("strict-expiry", TIME, "* 1_000_000_000 < nanos(now)", "* 1_000_000_000 <= nanos(now)", "core", "cpu-global-expiry-strict", "FACTOR_"),
        ("cpu-per-sample-expiry", RESOURCE, "v.time.expired(now, 120)", "query.time().expired(now, 120)", "core", "two-cluster-global-fresh-stale-cache", "FACTOR_"),
        ("cpu-equal-sample-replaced", RESOURCE, "!old.before(time)", "old != time && !old.before(time)", "core", "cpu-equal-sample-time-keeps-cache", "FACTOR_"),
        ("cpu-empty-keeps-score", RESOURCE, "let Some(query) = window.query(QueryId::Cpu)?.filter(|q| !q.empty()) else {\n            return Ok(false);", "let Some(query) = window.query(QueryId::Cpu)?.filter(|q| !q.empty()) else {\n            return Ok(true);", "core", "cpu-empty-contributes-zero", "FACTOR_"),
        ("cpu-global-expiry-ignored", RESOURCE, "Ok(!query.time().stale(now, 120))", "Ok(true)", "core", "cpu-global-expiry-strict", "FACTOR_"),
        ("memory-high-threshold-inclusive", RESOURCE, "usage > 0.75", "usage >= 0.75", "core", "memory-value-0.75", "FACTOR_"),
        ("memory-history-window", RESOURCE, "delta < 10 * NS", "delta < 11 * NS", "core", "memory-history-min-10000", "FACTOR_"),
        ("memory-oom-adjustment", RESOURCE, "horizon as f64 / latest * 0.6", "horizon as f64 / latest * 0.5", "core", "memory-horizon-threshold-0.340000001", "FACTOR_"),
        ("health-missing-abnormal", RESOURCE, "let (Some(failure), Some(total)) = (failure, total) else {\n        return 0;", "let (Some(failure), Some(total)) = (failure, total) else {\n        return 2;", "core", "health-backend-missing-default-normal", "FACTOR_"),
        ("health-failure-threshold-strict", RESOURCE, "ratio >= threshold", "ratio > threshold", "core", "health-pd-5-10", "FACTOR_"),
        ("health-zero-total-normal", RESOURCE, "if total == 0.0 {\n        return 2;", "if total == 0.0 {\n        return 0;", "core", "health-pd-1-0", "FACTOR_"),
        ("cpu-bit-width", FACTORS, "Self::Cpu => 5,", "Self::Cpu => 4,", "core", "order-resource", "FACTOR_"),
        ("resource-factor-order", FACTORS, "Factor::Health,\n            Factor::Memory,\n            Factor::Cpu,\n            Factor::Location,", "Factor::Location,\n            Factor::Health,\n            Factor::Memory,\n            Factor::Cpu,", "core", "order-resource", "FACTOR_"),
        ("prefer-idle-minimum-only", PHASES, "if count <= 0.0001 {", "if false && count <= 0.0001 {", "core", "connection-clamp", "FACTOR_"),
        ("ledger-owner-compared-by-id", FACTORS, ".is_some_and(|owner| Arc::ptr_eq(owner, &stored.identity))", ".is_some_and(|_owner| true)", "account", "", "FACTOR_ACCOUNT_ABA_NO_REUSE"),
        ("lineage-compared-by-value", COLLECTOR, "Arc::ptr_eq(&self.0, &other.0)", "*self.0 == *other.0", "lineage", "", "FACTOR_LINEAGE_OPAQUE_IDENTITY"),
        ("prom-lineage-follows-unused-owner", COLLECT, "if self.reader.source() == crate::metrics::Source::Backend {", "if true {", "lineage", "", "FACTOR_PROM_UNUSED_OWNER_CONTINUITY"),
        ("backend-owner-keeps-lineage", COLLECT, "if self.reader.source() == crate::metrics::Source::Backend {", "if false {", "lineage", "", "FACTOR_BACKEND_OWNER_COLD_START"),
        ("ordinary-round-cold-starts", COLLECT, "lineage: Arc::clone(&self.lineage),", "lineage: Arc::new(()),", "lineage", "", "FACTOR_ROUND_NOT_LINEAGE"),
        ("router-cross-lineage-reuse", SELECTOR, "factors.core.clear_cluster(&cluster);", "let _ = &cluster;", "live", "", "FACTOR_CROSS_LINEAGE_NO_CACHE_REUSE"),
        ("prom-source-aba-keeps-lineage", COLLECT, "if state.reader.source() != crate::metrics::Source::Prometheus {", "if false {", "live", "", "FACTOR_SOURCE_ABA_NEW_LINEAGE"),
        ("metric-final-boundary-bypassed", SELECTOR, "metrics\n            .with_current(|| {", "Some((|| {", "live-boundary", "", "FACTOR_OLD_ROUND_REJECTED"),
    ]
    cases.append(("unrelated-cluster-clears-health", FACTORS, "let label = control_topology::metrics::cluster_label(cluster);", "self.history.health_queries.clear(); let label = control_topology::metrics::cluster_label(cluster);", "account", "", "FACTOR_UNCHANGED_CLUSTER_RETAINS_HEALTH"))
    cases.extend([
        ("factor-consumer-ignores-H-local", SELECTOR, "local: candidate.health.get(&backend.source.backend_id).local,", "local: false,", "live", "", "FACTOR_REAL_H_LOCAL"),
        ("factor-consumer-accepts-foreign-R", SELECTOR, "if !Arc::ptr_eq(&candidate.routing, metrics.source().routing()) {", "if false && !Arc::ptr_eq(&candidate.routing, metrics.source().routing()) {", "live", "", "FACTOR_FOREIGN_CURRENT_R_REJECTED"),
    ])
    selected = os.environ.get("CPMETRICS_FACTOR_MUTATION")
    if selected:
        cases = [case for case in cases if case[0] == selected]
        if not cases:
            raise RuntimeError("unknown factor mutation selection")
    with tempfile.TemporaryDirectory(prefix="cpmetrics-factor-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(original_root / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        environment = dict(os.environ, CARGO_TARGET_DIR=str(original_root / "rust/target"))
        def baseline():
            binaries = compile_binaries(root, environment)
            core = run(binaries["control_router"], "factors::tests::", environment)
            lineage = run(binaries["control_topology"], "factor_lineage_", environment)
            actual = live.observe(binaries["control_router"], environment)
            if core.returncode or "observations passed: 95" not in core.stdout or lineage.returncode or "1 passed; 0 failed" not in lineage.stdout or actual.returncode or live.MARKER not in actual.stdout:
                raise RuntimeError("factor isolated baseline/restoration failed:\n" + core.stdout + lineage.stdout + actual.stdout)
            print("CP-METRIC-FACTORS isolated baseline passed", flush=True)
        baseline()
        for name, filename, before, after, family, row, marker in cases:
            path = root / "rust" / filename
            original = path.read_text()
            # Equal sample tests pin CPU independently of memory's same guard.
            count = 2 if name == "cpu-equal-sample-replaced" else 1
            if original.count(before) != count:
                raise RuntimeError(f"mutation anchor count changed: {name}: {original.count(before)} != {count}")
            changed = original.replace(before, after, 1)
            if family == "live-boundary":
                end = "            })\n            .ok_or(RouteError::StaleCandidate)?"
                if changed.count(end) != 1:
                    raise RuntimeError("metric boundary end anchor changed")
                changed = changed.replace(end, "            })())\n            .ok_or(RouteError::StaleCandidate)?", 1)
            try:
                path.write_text(changed)
                binaries = compile_binaries(root, environment)
                if family.startswith("live"):
                    result = live.observe(binaries["control_router"], environment)
                elif family == "lineage":
                    result = run(binaries["control_topology"], "factor_lineage_", environment)
                else:
                    scoped = dict(environment)
                    if row:
                        scoped["CPMETRICS_FACTOR_CASE"] = row
                    result = run(binaries["control_router"], "factors::tests::", scoped)
                if result.returncode != 101 or "test result: FAILED" not in result.stdout or marker not in result.stdout or (row and row not in result.stdout):
                    raise RuntimeError(f"factor mutation did not kill its required observation: {name}\n" + result.stdout)
                print(f"CP-METRIC-FACTORS compiling mutation killed: {name}", flush=True)
            finally:
                path.write_text(original)
        baseline()
        print(f"CP-METRIC-FACTORS {len(cases)}/{len(cases)} compiling mutations killed; restored baseline passed", flush=True)


if __name__ == "__main__":
    main()
