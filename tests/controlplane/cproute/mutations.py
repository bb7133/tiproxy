#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile mutations of production selector code; runtime regression must fail."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    repo = Path(__file__).resolve().parents[3]
    with tempfile.TemporaryDirectory(prefix="cproute-selector-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
        # Fresh actual-Go observations are asserted inside the Rust runtime
        # tests, so new policy mutations must compile and fail a real test.
        for kind, fixture in [("COMPOSITION", "eligibility"), ("RETRY", "retry")]:
            environment[f"CPROUTE_{kind}_FIXTURE"] = str(repo / f"tests/controlplane/cproute/composition/{fixture}.json")
            environment[f"CPROUTE_{kind}_OUTPUT"] = str(root / f"go-{kind}.tsv")
        observed = subprocess.run(["go", "test", "./pkg/balance/router", "-run", "^TestCPRoute(Composition|Retry)Observation$", "-count=1"],
            cwd=repo, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        if observed.returncode:
            raise RuntimeError("Go composition observation failed:\n" + observed.stdout)
        for kind in ["COMPOSITION", "RETRY"]:
            environment[f"CPROUTE_{kind}_EXPECTED"] = environment[f"CPROUTE_{kind}_OUTPUT"]
            environment[f"CPROUTE_{kind}_OUTPUT"] = str(root / f"rust-{kind}.tsv")
        command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-router", "--lib"]
        def run(arguments):
            result = subprocess.run(command + arguments, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            return result
        def baseline():
            result = run([])
            if result.returncode:
                raise RuntimeError("isolated baseline failed:\n" + result.stdout)
        baseline()
        base = root / "rust/crates/control-router/src"
        originals = {name: (base / name).read_text() for name in ["authority.rs", "ledger.rs", "selector.rs", "policy.rs", "retry.rs"]}
        cases = [
            ("skip-current-config", "authority.rs", [
                ('|| !Arc::ptr_eq(&candidate.config, &self.source.current())', '')]),
            ("skip-current-health", "authority.rs", [
                ('|| !self\n                .health\n                .still_current_for(&candidate.health, &candidate.routing, &self.routing)', '')]),
            ("reset-account-on-source-refresh", "selector.rs", [
                ('backend.source = source.clone();', 'backend.account = self.ledger.add_account()?; backend.source = source.clone();')]),
            ("terminal-selects-latest-owner", "ledger.rs", [
                ('self.accounts.get_mut(&reservation.account.sequence) else', 'self.accounts.last_entry().map(|entry| entry.into_mut()) else'),
                ('if !Arc::ptr_eq(&account.identity, &reservation.account) {', 'if false {')]),
            ("duplicate-terminal-settles-active", "ledger.rs", [
                ('let Ok(Stage::Pending(pending)) = self.stage(&reservation.session)', 'let Ok(Stage::Pending(pending) | Stage::Active(pending)) = self.stage(&reservation.session)')]),
            ("closed-session-retains-pending-authority", "ledger.rs", [
                ('self.sessions.remove(&session.sequence) else', 'self.sessions.get(&session.sequence).cloned() else')]),
            ("resource-silently-uses-connection", "authority.rs", [
                ('return Err(RouteError::Unsupported(Unsupported::ResourcePolicy));', '')]),
            ("namespace-content-as-identity", "authority.rs", [
                ('|| !self\n                .namespace_origin\n                .same_namespace_incarnation(config, self.namespace.name.as_ref())', '')]),
            ("label-isolation-skipped", "policy.rs", [
                ('policy.label_name.is_empty()', 'true || policy.label_name.is_empty()')]),
            ("pod-name-is-full-address", "policy.rs", [
                ('pod: pod_name(address).into()', 'pod: address.into()')]),
            ("fail-list-safeguard-always-ignores", "selector.rs", [
                ('(ignore_failed || !backend.routing_identity.failed(policy))', '(true || ignore_failed || !backend.routing_identity.failed(policy))')]),
            ("fail-list-all-failed-safeguard-removed", "selector.rs", [
                ('(ignore_failed || !backend.routing_identity.failed(policy))', '(false || !backend.routing_identity.failed(policy))')]),
            ("retry-exclusions-in-fail-list-denominator", "selector.rs", [
                ('&& label_matches(policy, &backend.source.backend.labels)', '&& label_matches(policy, &backend.source.backend.labels) && !excluded.contains(&backend.source.backend_id.as_ref())')]),
            ("status-filter-skipped", "selector.rs", [
                ('&& backend.healthy', '&& true')]),
            ("port-conflict-resets-retry-cycle", "retry.rs", [
                ('Err(RouteError::NoBackend)', 'Err(RouteError::NoBackend | RouteError::PortConflict)')]),
            ("selector-settles-other-session", "retry.rs", [
                ('if !reservation.belongs_to(&self.session)', 'if false')]),
            ("assignment-locality-always-true", "selector.rs", [
                ('let local = candidate.health.get(&backend.source.backend_id).local;', 'let local = true;')]),
            ("assignment-locality-always-false", "selector.rs", [
                ('let local = candidate.health.get(&backend.source.backend_id).local;', 'let local = false;')]),
            ("assignment-locality-from-current-config", "selector.rs", [
                ('let local = candidate.health.get(&backend.source.backend_id).local;',
                 'let local = candidate.policy.proxy_labels.iter().find(|(name, _)| name.as_ref() == "zone").is_none_or(|(_, zone)| zone.is_empty() || backend.source.backend.labels.get("zone").is_some_and(|value| value == zone.as_ref()));')]),
        ]
        for name, filename, replacements in cases:
            changed = originals[filename]
            for before, after in replacements:
                if before not in changed:
                    raise RuntimeError(f"mutation anchor absent: {name}: {before}")
                changed = changed.replace(before, after)
            (base / filename).write_text(changed)
            compiled = run(["--no-run"])
            if compiled.returncode:
                raise RuntimeError(f"mutation must compile: {name}\n{compiled.stdout}")
            tested = run([])
            if tested.returncode != 101 or "test result: FAILED" not in tested.stdout:
                raise RuntimeError(f"mutation survived or did not complete regression tests: {name}\n{tested.stdout}")
            (base / filename).write_text(originals[filename])
            print(f"CP-ROUTE selector mutation killed: {name}", flush=True)
        baseline()


if __name__ == "__main__":
    main()
