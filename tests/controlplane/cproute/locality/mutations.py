#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile mutations of the production health-round locality; a runtime regression must fail.

Usage: mutations.py <go-locality.tsv>  (a fresh actual-Go observation, asserted
inside the Rust shared observation test for every mutation).
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    expected = Path(sys.argv[1]).resolve()
    repo = Path(__file__).resolve().parents[4]
    with tempfile.TemporaryDirectory(prefix="cproute-locality-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # The isolated build shares a target directory across runs for dependency
        # reuse. copytree preserves source mtimes, so a workspace crate could
        # otherwise be judged "fresh" against a fingerprint left by a previous
        # (mutated) build and its stale artifact reused. Touch every workspace
        # source so the workspace crates are always rebuilt; registry
        # dependencies stay cached.
        for source in (root / "rust/crates").rglob("*.rs"):
            os.utime(source, None)
        # Keep the isolated build under the repository target directory so the
        # dependency artifacts are reused across runs (and by the CI cache); the
        # mutated sources themselves live only in the temporary copy.
        target = repo / "rust/target/cproute-locality-mutations"
        environment = dict(
            os.environ,
            CARGO_TARGET_DIR=str(target),
            CPROUTE_LOCALITY_FIXTURE=str(repo / "tests/controlplane/cproute/locality/rounds.json"),
            CPROUTE_LOCALITY_EXPECTED=str(expected),
            CPROUTE_LOCALITY_OUTPUT=str(root / "rust-locality.tsv"),
        )
        command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-topology", "--lib"]
        def run(arguments):
            return subprocess.run(command + arguments, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        def baseline():
            result = run([])
            if result.returncode:
                raise RuntimeError("isolated baseline failed:\n" + result.stdout)
        baseline()
        source = root / "rust/crates/control-topology/src/health_loop.rs"
        original = source.read_text()
        cases = [
            ("disabled-round-marks-local", [
                ('    if generation.networks.is_none() {\n        let health = source\n            .backends\n            .backends\n            .iter()\n            .map(|backend| {\n                (\n                    Arc::clone(&backend.backend_id),\n                    BackendHealth {\n                        healthy: true,\n                        server_version: None,\n                        local: false,\n                    },',
                 '    if generation.networks.is_none() {\n        let health = source\n            .backends\n            .backends\n            .iter()\n            .map(|backend| {\n                (\n                    Arc::clone(&backend.backend_id),\n                    BackendHealth {\n                        healthy: true,\n                        server_version: None,\n                        local: true,\n                    },')]),
            ("empty-zone-compares-as-zone", [
                ('        None | Some("") => true,', '        None => true,')]),
            ("zone-compare-case-insensitive", [
                ('.is_some_and(|value| value == zone)', '.is_some_and(|value| value.eq_ignore_ascii_case(zone))')]),
            ("unlabelled-backend-local-under-zone", [
                ('.is_some_and(|value| value == zone)', '.is_none_or(|value| value == zone)')]),
            ("zone-read-after-round-not-captured", [
                ('    // Captured ONCE, before any probe is constructed (Go `checkHealth`).\n    let proxy_zone = locality.proxy_zone();\n', ''),
                ('    // Locality is ROUND-owned (Go `setLocal` after `Check`): stamp every verdict\n',
                 '    let proxy_zone = locality.proxy_zone();\n    // Locality is ROUND-owned (Go `setLocal` after `Check`): stamp every verdict\n')]),
            ("zone-read-per-probe-construction", [
                ('    let proxy_zone = locality.proxy_zone();\n', '    let mut proxy_zone = locality.proxy_zone();\n'),
                ('        let backend_id = Arc::clone(&backend.backend_id);\n        let future = probe(\n',
                 '        proxy_zone = locality.proxy_zone();\n        let backend_id = Arc::clone(&backend.backend_id);\n        let future = probe(\n')]),
        ]
        for name, replacements in cases:
            changed = original
            for before, after in replacements:
                if changed.count(before) != 1:
                    raise RuntimeError(f"mutation anchor must be unique: {name}: {before!r} x{changed.count(before)}")
                changed = changed.replace(before, after)
            source.write_text(changed)
            compiled = run(["--no-run"])
            if compiled.returncode:
                raise RuntimeError(f"mutation must compile: {name}\n{compiled.stdout}")
            tested = run([])
            if tested.returncode != 101 or "test result: FAILED" not in tested.stdout:
                raise RuntimeError(f"mutation survived or did not complete regression tests: {name}\n{tested.stdout}")
            source.write_text(original)
            print(f"CP-ROUTE locality mutation killed: {name}", flush=True)
        baseline()


if __name__ == "__main__":
    main()
