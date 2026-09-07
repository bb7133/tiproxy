#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compiling authority mutations must fail named rows against actual etcd."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request


def main():
    repo = Path(__file__).resolve().parents[3]
    connection = json.loads(Path(os.environ["CP003_CONNECTION_FILE"]).read_text())
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def reset():
        # A rejected uncertainty mutation may leave etcd stopped; a held-RPC
        # mutation may leave its transparent proxy gate closed.
        for path in ["/release-cleanup", "/start"]:
            try:
                with http.open(urllib.request.Request(connection["control_url"] + path, method="POST"), timeout=10):
                    pass
            except urllib.error.HTTPError as error:
                if path != "/start" or error.code != 409:
                    raise

    with tempfile.TemporaryDirectory(prefix="cpauthority-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
        command = ["cargo", "build", "--locked", "--offline", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-etcd", "--example", "cpauthority_observer"]

        def compile_candidate():
            result = subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            if result.returncode:
                raise RuntimeError("candidate did not compile:\n" + result.stdout)

        def observe():
            reset()
            return subprocess.run([str(root / "target/debug/examples/cpauthority_observer")], env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)

        def baseline():
            compile_candidate()
            result = observe()
            if result.returncode or "CP-AUTHORITY all live rows passed" not in result.stdout:
                raise RuntimeError("isolated baseline/restoration failed:\n" + result.stdout)

        base = root / "rust/crates/control-etcd/src"
        originals = {name: (base / name).read_text() for name in ["authority.rs", "session.rs"]}
        # Bypass the complete publication guard while preserving its mutex.
        # Omitting only still_current leaves phase/identity checks effective.
        publication_start = originals["authority.rs"].index("        if !self.still_current()")
        publication_end = originals["authority.rs"].index("        Some(publish())", publication_start)
        publication_guard = originals["authority.rs"][publication_start:publication_end]
        cases = [
            ("shutdown-revokes-after-rpcs", "session.rs", "self.authority.retire();\n        let mut first_error", "let mut first_error", "shutdown-revokes-before-rpc-release"),
            ("drop-does-not-revoke", "session.rs", "self.authority.retire();\n    }\n}\n", "// mutation: no Drop retirement\n    }\n}\n", "session-drop-revokes"),
            ("terminal-change-only-notifies-watch", "session.rs", "self.authority.transition(snapshot.state);", "if !matches!(snapshot.state, ElectionState::Retired | ElectionState::Stopped) { self.authority.transition(snapshot.state); }", "retirement-without-watch-consumer"),
            ("uncertainty-keeps-old-work", "authority.rs", "if phase != ElectionState::Leader {", "if !matches!(phase, ElectionState::Leader | ElectionState::Uncertain) {", "uncertain-revokes-work-only"),
            ("recovery-revives-old-work", "authority.rs", "self.shared.is_live() && self.interval.gate.is_live()", "self.shared.is_live() && (self.interval.gate.is_live() || self.shared.state.try_lock().is_ok_and(|state| state.phase == ElectionState::Leader))", "recovery-does-not-revive-permit"),
            ("original-owner-not-checked", "authority.rs", "self.owner.is_current() && self.retirement.is_live()", "self.retirement.is_live()", "original-process-owner"),
            ("publication-does-not-recheck", "authority.rs", publication_guard, "        let _ = &state;\n", "uncertain-publication-rejected"),
            ("early-revoke-skips-remote-cleanup", "session.rs", "if clean_up {", "if clean_up && self.authority.retains_local_ownership() {", "remote-cleanup-removes-lease"),
        ]
        try:
            baseline()
            for name, filename, before, after, required in cases:
                original = originals[filename]
                if original.count(before) != 1:
                    raise RuntimeError(f"mutation anchor must be unique: {name}: {original.count(before)}")
                candidate = original.replace(before, after)
                if name == "shutdown-revokes-after-rpcs":
                    anchor = "        self.clear_transport_handles();\n        self.update_snapshot(|snapshot| {\n            snapshot.state = ElectionState::Stopped;"
                    if candidate.count(anchor) != 1:
                        raise RuntimeError("late retirement anchor is not unique")
                    candidate = candidate.replace(anchor, "        self.authority.retire();\n" + anchor)
                (base / filename).write_text(candidate)
                compile_candidate()
                result = observe()
                if result.returncode != 1 or f"CP-AUTHORITY row failed: {required}" not in result.stdout:
                    raise RuntimeError(f"mutation failed its required evidence: {name}\n{result.stdout}")
                (base / filename).write_text(original)
                print(f"CP-AUTHORITY compiling mutation killed: {name}", flush=True)
            baseline()
            print(f"CP-AUTHORITY {len(cases)}/{len(cases)} compiling mutations killed; restored baseline passed", flush=True)
        finally:
            reset()


if __name__ == "__main__":
    main()
