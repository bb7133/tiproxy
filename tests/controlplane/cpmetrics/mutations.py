#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile copied production mutations; each must fail its named evidence row."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    repo = Path(__file__).resolve().parents[3]
    for part in ["RULE", "HISTORY", "SOURCE", "MERGE", "PROM", "BACKEND"]:
        if not Path(os.environ[f"CPMETRICS_{part}_OUTPUT"]).is_file():
            raise RuntimeError("run the complete CP-METRICS entrypoint first")
    with tempfile.TemporaryDirectory(prefix="cpmetrics-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        environment = dict(os.environ, CARGO_TARGET_DIR=os.environ.get("CARGO_TARGET_DIR", str(root / "target")))
        # Select the data core, excluding module::tests::metrics runtime tests.
        command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-topology", "--lib", "metrics::tests::"]
        def run(arguments):
            return subprocess.run(command + arguments, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        def baseline():
            result = run(["--", "--nocapture"])
            if result.returncode or "CP-METRICS actual-Go observations passed: 152" not in result.stdout:
                raise RuntimeError("isolated baseline/restoration failed or missing Go evidence:\n" + result.stdout)
        baseline()
        base = root / "rust/crates/control-topology/src"
        originals = {name: (base / name).read_text() for name in ["metrics.rs", "metrics/rules.rs", "metrics/history.rs", "metrics/decode.rs"]}
        cases = [
            ("prom-range-step-is-not-fifteen-seconds", "metrics/rules.rs", "Ok(Some((start, end_ms, 15_000)))", "Ok(Some((start, end_ms, 10_000)))", "catalog-cpu"),
            ("cluster-update-uses-minimum", "metrics.rs", ".max(result.updated_nanos)", ".min(result.updated_nanos)", "two-cluster-max-update"),
            ("cluster-label-not-overwritten", "metrics/decode.rs", "result.attach_cluster(cluster);", "let _ = cluster;", "attach-0"),
            ("cpu-subsecond-interval", "metrics/rules.rs", "seconds < 1.0", "seconds < 0.9", "range-cpu-4"),
            ("cpu-reset-accepted", "metrics/rules.rs", "if pair.value > last.value", "if false", "range-cpu-5"),
            ("counter-values-rounded", "metrics/rules.rs", "checked_add(point.value as i64)", "checked_add(point.value.round() as i64)", "metric-failure_pd-4"),
            ("equal-history-replaces-local", "metrics/history.rs", "new.timestamp_ms > old.timestamp_ms", "new.timestamp_ms >= old.timestamp_ms", "owner-merge-0"),
            ("history-appends-instead-of-replaces", "metrics/history.rs", "*previous = incoming;", "previous.extend(incoming);", "owner-merge-1"),
            ("every-rule-needed-for-missing-fallback", "metrics/history.rs", "!rules.iter().any(|rule|", "!rules.iter().all(|rule|", "missing-2"),
            ("expiry-boundary-kept", "metrics/history.rs", "i128::from(retention_ms) > i128::from(now_ms)", "i128::from(retention_ms) >= i128::from(now_ms)", "purge-0"),
            ("aggregate-error-rolls-back-map", "metrics/history.rs", "self.backend = results;", "if succeeded { self.backend = results; }", "real-go-source-sequence"),
            ("empty-prom-retains-old-results", "metrics/history.rs", "self.prom = results;", "if results.is_empty() { return; } self.prom = results;", "real-go-source-sequence"),
            ("owner-shares-unselected-history", "metrics/history.rs", "selected.contains(backend.as_str())", "true || selected.contains(backend.as_str())", "owner-filter-1"),
            ("history-fields-case-sensitive", "metrics/history.rs", 'key.eq_ignore_ascii_case("Step1History")', 'key == "Step1History"', "owner-decode-4"),
            ("timestamp-fraction-truncated-to-two", "metrics/decode.rs", "fraction.chars().take(3)", "fraction.chars().take(2)", "owner-decode-3"),
            ("raw-history-skips-before-range", "metrics/history.rs", "if !value.is_nan() {\n                history.step2.push", "if value.is_nan() { continue; } if !value.is_nan() {\n                history.step2.push", "history_raw_sample_survives_missing_range_until_a_valid_cpu_interval ... FAILED"),
            ("wire-output-limit-bypassed", "metrics/history.rs", "if bytes.len() > super::MAX_BYTES.saturating_sub(self.0.len())", "if false", "owner_output_stops_before_exceeding_wire_byte_limit ... FAILED"),
        ]
        for name, filename, before, after, required in cases:
            original = originals[filename]
            if original.count(before) != 1:
                raise RuntimeError(f"mutation anchor must be unique: {name}: {original.count(before)}")
            (base / filename).write_text(original.replace(before, after))
            compiled = run(["--no-run"])
            if compiled.returncode:
                raise RuntimeError(f"mutation did not compile: {name}\n{compiled.stdout}")
            tested = run(["--", "--nocapture"])
            if tested.returncode != 101 or "test result: FAILED" not in tested.stdout or required not in tested.stdout:
                raise RuntimeError(f"mutation failed to kill its required row: {name}\n{tested.stdout}")
            (base / filename).write_text(original)
            print(f"CP-METRICS compiling mutation killed: {name}", flush=True)
        baseline()
        print(f"CP-METRICS {len(cases)}/{len(cases)} compiling mutations killed; restored baseline passed", flush=True)


if __name__ == "__main__":
    main()
