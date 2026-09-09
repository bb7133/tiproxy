#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compiling faults must fail their named real-Go or runtime boundary."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import live

def main():
    repo = Path(__file__).resolve().parents[4]
    with tempfile.TemporaryDirectory(prefix="cproute-balance-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        target = repo / "rust/target"
        env = dict(os.environ, CARGO_TARGET_DIR=str(target), CPROUTE_ARRIVAL_OUTPUT=str(root / "arrival.tsv"))
        def run(binary, selection):
            return subprocess.run([binary, selection, "--nocapture", "--test-threads=1"],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        def baseline():
            binary = live.compile_binary(root, env)
            for selection in ["shared_go_factor_observations", "shared_go_physical_arrival_order", "balance_plan_"]:
                r = run(binary, selection)
                if r.returncode or "0 passed" in r.stdout:
                    raise RuntimeError("balance baseline failed:\n" + r.stdout)
            r = live.observe(binary, env)
            if r.returncode or live.MARKER not in r.stdout:
                raise RuntimeError("balance live baseline failed:\n" + r.stdout)
        baseline()
        source = root / "rust/crates/control-router/src"
        cases = [
            ("physical-zero", "factors/balance.rs", [("sorted[i].0.counts.active() > 0", "true", 1)], "shared_go_factor_observations"),
            ("score-zero", "factors/balance.rs", [("sorted[i].0.counts.connection_score() > 0", "true", 1)], "shared_go_factor_observations"),
            ("best-unrouteable", "factors/phases.rs", [("!row(0).routeable", "false", 1)], "shared_go_factor_observations"),
            ("source-order", "factors/phases.rs", [("(1..n).rev()", "(1..n)", 1)], "shared_go_factor_observations"),
            ("inverted-priority", "factors/phases.rs", [("from < to", "false", 1)], "shared_go_factor_observations"),
            ("negative-equal-veto", "factors/phases.rs", [("answer.advice == BalanceAdvice::Negative", "(from > to && answer.advice == BalanceAdvice::Negative)", 1)], "shared_go_factor_observations"),
            ("strict-cutoff", "factors/phases.rs", [("answer.count > 0.0001", "answer.count >= 0.0001", 1)], "shared_go_factor_observations"),
            ("arrival-prepend", "ledger.rs", [("target.physical.push(redirect.session.sequence);", "target.physical.insert(0, redirect.session.sequence);", 1)], "shared_go_physical_arrival_order"),
            ("arrival-id-sort", "ledger.rs", [("target.physical.push(redirect.session.sequence);", "target.physical.push(redirect.session.sequence); target.physical.sort_unstable();", 1)], "shared_go_physical_arrival_order"),
            ("arrival-source-not-removed", "ledger.rs", [("source\n                .physical\n                .retain(|id| *id != redirect.session.sequence);", "", 1)], "shared_go_physical_arrival_order"),
            ("arrival-close-not-removed", "ledger.rs", [("account.physical.retain(|id| *id != session.sequence);", "", 1)], "shared_go_physical_arrival_order"),
            ("balance-healthy-only", "selector/balance.rs", [("let mut inputs = state.factor_inputs(group, candidate);", "let mut inputs = state.factor_inputs(group, candidate); inputs.retain(|input| input.healthy);", 1)], "balance_plan_retains_unhealthy_physical_source"),
            ("balance-ignore-fail-list", "selector/balance.rs", [("input.healthy &= ignore_failed", "input.healthy &= true || ignore_failed", 1)], "balance_plan_fail_list"),
            ("balance-all-failed-guard", "selector/balance.rs", [("let ignore_failed = !routeable.is_empty()", "let ignore_failed = false && !routeable.is_empty()", 1)], "balance_plan_fail_list"),
            ("balance-refusal-cache", "selector/balance.rs", [("state.factors.insert(group, factors);", "if prepared.is_ok() { state.factors.insert(group, factors); }", 1)], "balance_plan_cross_keyspace"),
            ("balance-final-metric-fence", "selector/balance.rs", [("metrics.with_current(|| select(Some(metrics), &queries))", "Some(select(Some(metrics), &queries))", 1)], "live"),
        ]
        originals = {file: (source / file).read_text() for _,file,_,_ in cases}
        missed = []
        for name, file, changes, selection in cases:
            path = source / file
            original = originals[file]
            # The shared file also contains preferred(); preserve this catalog
            # as faults in the balance walk only.
            start = original.index("pub(crate) fn balance") if file == "factors/phases.rs" else 0
            end = original.index("pub(crate) fn ticket") if file == "factors/phases.rs" else len(original)
            changed = original[start:end]
            for before, after, count in changes:
                if changed.count(before) < count:
                    raise RuntimeError(f"missing mutation anchor {name}: {before}")
                changed = changed.replace(before, after, count)
            path.write_text(original[:start] + changed + original[end:])
            binary = live.compile_binary(root, env) # compile failure is not a kill
            r = live.observe(binary, env) if selection == "live" else run(binary, selection)
            marker = "BALANCE_EMPTY_SOURCE" if selection == "live" else "FAILED"
            if r.returncode != 101 or marker not in r.stdout:
                missed.append(name)
                print(f"CP-ROUTE balance mutation MISSED: {name}\n{r.stdout}", flush=True)
            else:
                print(f"CP-ROUTE balance mutation killed: {name}", flush=True)
            path.write_text(original)
        baseline()
        if missed:
            raise RuntimeError(f"undetected balance mutations: {missed}")
        print(f"CP-ROUTE balance restored baseline passed: {len(cases)} mutations", flush=True)

if __name__ == "__main__":
    main()
