#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile mutations of the production static-source/mode authority; a runtime regression must fail.

Usage: mutations.py <go-static.tsv>  (a fresh actual-Go observation, asserted
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
    with tempfile.TemporaryDirectory(prefix="cproute-static-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        # The isolated build shares a target directory across runs for dependency
        # reuse. copytree preserves source mtimes, so a workspace crate could
        # otherwise be judged "fresh" against a fingerprint left by a previous
        # (mutated) build and its stale artifact reused. Touch every workspace
        # source so the workspace crates are always rebuilt; registry
        # dependencies stay cached.
        for source in (root / "rust/crates").rglob("*.rs"):
            os.utime(source, None)
        # Isolated build under the repository target directory so dependency
        # artifacts are reused (and cached by CI); mutated sources live only in
        # the temporary copy.
        target = Path(os.environ.get("CARGO_TARGET_DIR", repo / "rust/target/cproute-static-mutations"))
        environment = dict(
            os.environ,
            CARGO_TARGET_DIR=str(target),
            CPROUTE_STATIC_FIXTURE=str(repo / "tests/controlplane/cproute/static/modes.json"),
            CPROUTE_STATIC_EXPECTED=str(expected),
            CPROUTE_STATIC_OUTPUT=str(root / "rust-static.tsv"),
        )
        command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-topology", "--lib"]
        def run(arguments):
            return subprocess.run(command + arguments, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
        def baseline():
            result = run([])
            if result.returncode:
                raise RuntimeError("isolated baseline failed:\n" + result.stdout)
        baseline()
        base = root / "rust/crates/control-topology/src"
        originals = {name: (base / name).read_text() for name in ["module.rs", "static_source.rs", "backend_health.rs"]}
        cases = [
            ("rejected-generation-publishes-pending-config-mode", "module.rs", [
                ("        let outcome = self\n            .reconfigure(children, active_plan, snapshot, owner, health, statics)\n            .await;\n",
                 "        let outcome = self\n            .reconfigure(children, active_plan, snapshot, owner, health, statics)\n            .await;\n        if outcome.is_err() {\n            let pending = if snapshot.topology().is_ok_and(|t| t.backend_clusters.is_empty()) { BackendSourceMode::Static } else { BackendSourceMode::Dynamic };\n            statics.apply_mode(Some(pending));\n            self.mode.publish(pending);\n        }\n")]),
            ("namespaces-reconciled-only-on-accepted-generations", "module.rs", [
                ("        statics.reconcile(\n            snapshot,\n            owner,\n            &self.health_runtime,\n            &self.source,\n            self.mode.applied(),\n        );\n        let outcome = self\n            .reconfigure(children, active_plan, snapshot, owner, health, statics)\n            .await;",
                 "        let outcome = self\n            .reconfigure(children, active_plan, snapshot, owner, health, statics)\n            .await;\n        if outcome.is_ok() {\n            statics.reconcile(snapshot, owner, &self.health_runtime, &self.source, self.mode.applied());\n        }")]),
            ("mode-revoked-only-at-publish", "module.rs", [
                ("        let mode_changes = self.mode.applied() != Some(next_mode);\n        if mode_changes {\n            self.mode.revoke();\n        }\n",
                 "        let mode_changes = self.mode.applied() != Some(next_mode);\n")]),
            ("static-parked-after-epoch-publish", "module.rs", [
                ("            statics.apply_mode(Some(next_mode));\n            self.mode.publish(next_mode);",
                 "            self.mode.publish(next_mode);\n            statics.apply_mode(Some(next_mode));")]),
            ("mode-identity-by-value-not-epoch", "static_source.rs", [
                ("        if !Arc::ptr_eq(&snapshot.epoch, &current) || !snapshot.epoch.is_live() {",
                 "        if snapshot.epoch.mode != current.mode || !current.is_live() {")]),
            ("namespace-not-checked-at-the-source", "static_source.rs", [
                ("        if !Arc::ptr_eq(&snapshot.bundle, &self.bundle) || !self.namespace_current() {",
                 "        if !Arc::ptr_eq(&snapshot.bundle, &self.bundle) {"),
                ("        if !self.namespace_current() {\n            return None;\n        }\n        let epoch = Arc::clone(&self.mode.borrow());",
                 "        let epoch = Arc::clone(&self.mode.borrow());")]),
            ("inactive-static-keeps-probing", "static_source.rs", [
                ("        if !self.active {\n            return;\n        }\n        self.active = false;\n        self.feeder.withdraw();",
                 "        if !self.active {\n            return;\n        }")]),
            ("empty-dynamic-discovery-falls-back-to-static", "static_source.rs", [
                ("        let (routing, health) = self.side(&epoch);\n        let r = routing.current()?;",
                 "        let (routing, health) = if self.dynamic.0.current().is_some_and(|r| r.backends.backends.is_empty()) { &self.stationary } else { self.side(&epoch) };\n        let r = routing.current()?;")]),
            ("producer-reused-across-incarnations", "static_source.rs", [
                ("                .is_some_and(|producer| producer.incarnation().same_as(&incarnation))",
                 "                .is_some()")]),
            ("static-health-fabricated-without-probe", "static_source.rs", [
                ("                Some(Arc::new(map))", "None")]),
            ("static-backend-runs-the-status-stage", "backend_health.rs", [
                ("        // stage still dials its `addr`).\n        if ip.is_empty() {", "        // stage still dials its `addr`).\n        if false {")]),
        ]
        for name, filename, replacements in cases:
            changed = originals[filename]
            for before, after in replacements:
                if changed.count(before) != 1:
                    raise RuntimeError(f"mutation anchor must be unique: {name}: {before!r} x{changed.count(before)}")
                changed = changed.replace(before, after)
            (base / filename).write_text(changed)
            compiled = run(["--no-run"])
            if compiled.returncode:
                raise RuntimeError(f"mutation must compile: {name}\n{compiled.stdout}")
            tested = run([])
            if tested.returncode != 101 or "test result: FAILED" not in tested.stdout:
                raise RuntimeError(f"mutation survived or did not complete regression tests: {name}\n{tested.stdout}")
            (base / filename).write_text(originals[filename])
            print(f"CP-ROUTE static-source mutation killed: {name}", flush=True)
        baseline()


if __name__ == "__main__":
    main()
