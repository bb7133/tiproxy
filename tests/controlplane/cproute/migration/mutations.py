#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compiling migration faults must fail a named lifecycle/authority regression."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    repo = Path(__file__).resolve().parents[4]
    with tempfile.TemporaryDirectory(prefix="cproute-migration-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        # Shared Cargo caches key freshness by mtime; copied sources must rebuild.
        for fresh_source in ((root / "rust")).rglob("*.rs"):
            fresh_source.touch()
        target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
        # Optional local acceleration. The caller must provide an IDLE target;
        # CI uses a fresh target. Never modify or build in the seed directory.
        seed = os.environ.get("CPROUTE_MIGRATION_TARGET_SEED")
        if seed:
            cp = ["cp", "-cR"] if sys.platform == "darwin" else ["cp", "-a", "--reflink=auto"]
            subprocess.run(cp + [seed, str(target)], check=True)
        env = dict(os.environ, CARGO_TARGET_DIR=str(target),
                   CPROUTE_MIGRATION_OUTPUT=str(root / "observed.tsv"))
        command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-router", "--lib"]
        def run(args):
            return subprocess.run(command + args, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        def baseline():
            r = run([])
            if r.returncode:
                raise RuntimeError("baseline failed:\n" + r.stdout)
        baseline()
        source = root / "rust/crates/control-router/src"
        originals = {name: (source / name).read_text() for name in ["ledger.rs", "selector.rs", "factors.rs"]}
        # Inline the actual helper into its guard-owning caller for this fault.
        # Dropping the helper's &mut State would not release the mutex at all.
        selector = originals["selector.rs"]
        helper = selector.split("    fn offer_redirect_locked(", 1)[1].split("    fn prepare_offer_locked(", 1)[0]
        helper = helper.split(") -> Result<bool, RouteError> {", 1)[1].rsplit("    }", 1)[0]
        unlock_offer = helper.replace("self.prepare_offer_locked(state,", "self.prepare_offer_locked(&mut state,")
        unlock_offer = unlock_offer.replace("        let accepted = match sender.try_send", "        drop(state);\n        let accepted = match sender.try_send", 1)
        unlock_offer = unlock_offer.replace("        state.ledger.admit_redirect", "        let mut state = self.lock();\n        state.ledger.admit_redirect", 1)
        # Restrict edits to one method so the fault's semantic boundary is explicit.
        cases = [
            ("success-does-not-move-physical", "ledger.rs", "pub(crate) fn finish_redirect", "fn release_redirect", [("if success {", "if false {", 1)], "redirect_transfers_score_then_physical_and_failure_returns_only_score"),
            ("failure-does-not-return-score", "ledger.rs", "pub(crate) fn finish_redirect", "fn release_redirect", [("self.release_redirect(redirect);", "if success { self.release_redirect(redirect); }", 1)], "redirect_transfers_score_then_physical_and_failure_returns_only_score"),
            ("redirect-charged-as-initial-reservation", "ledger.rs", "pub(crate) fn admit_redirect", "pub(crate) fn finish_redirect", [(".incoming += 1", ".reserved += 1", 1)], "redirect_transfers_score_then_physical_and_failure_returns_only_score"),
            ("terminal-uses-latest-owner", "ledger.rs", "pub(crate) fn finish_redirect", "fn release_redirect", [(".get_mut(&redirect.source.sequence)", ".last_entry().map(|entry| entry.into_mut())", 1)], "redirect_transfers_score_then_physical_and_failure_returns_only_score"),
            ("terminal-ignores-operation-sequence", "ledger.rs", "pub(crate) fn finish_redirect", "fn release_redirect", [("pending.sequence != redirect.sequence", "false", 1)], "redirect_old_same_pair_terminal_cannot_settle_new_operation"),
            ("success-adds-cooldown", "ledger.rs", "pub(crate) fn finish_redirect", "fn release_redirect", [("active.failed_at = None;", "active.failed_at = Some(redirect.issued_at);", 1)], "redirect_transfers_score_then_physical_and_failure_returns_only_score"),
            ("failure-cooldown-starts-at-terminal", "ledger.rs", "pub(crate) fn finish_redirect", "fn release_redirect", [("Some(redirect.issued_at)", "Some(now)", 1)], "redirect_delayed_failure_does_not_restart_issuance_cooldown"),
            ("rejected-offer-consumes-sequence", "ledger.rs", "pub(crate) fn admit_redirect", "pub(crate) fn finish_redirect", [("if admitted {\n            self.next_redirect += 1;", "self.next_redirect += 1;\n        if admitted {", 1)], "redirect_rejected_offer_records_cooldown_without_consuming_watermark_or_capacity"),
            ("final-offer-skips-source-validation", "selector.rs", "fn prepare_offer_locked", "pub(crate) fn finish_redirect", [("self.sources.validate(&prepared.candidate)?;", "", 4)], "migration_final_lock_rechecks_config_routing_and_health"),
            # The helper body is statements, so it can only be spliced where a
            # statement sequence is legal. The caller assigns the call to a
            # binding and then publishes from the same guard, so the whole
            # three-line sequence is replaced: inline the body, then publish
            # under a freshly taken guard because the inlined body has already
            # dropped and re-acquired the original one.
            ("offer-releases-lock-before-commit", "selector.rs", "pub(crate) fn offer_redirect", "fn offer_redirect_locked", [("""let result =
                self.offer_redirect_locked(&mut state, prepared, sender, now, &mut rejected);
            self.publish_migrations(state.ledger.drain_migrations());
            result""", "let result = {" + unlock_offer + "};\n            self.publish_migrations(self.lock().ledger.drain_migrations());\n            result", 1)], "migration_immediate_terminal_waits_for_accepted_ledger_commit"),
            ("connection-factor-uses-physical", "factors.rs", "fn score(", "fn advice_values(", [("connections: input.counts.connection_score(),", "connections: if factor == Factor::Connection { input.counts.active() } else { input.counts.connection_score() },", 1)], "redirect_connection_factor_reads_transferred_score_not_physical_count"),
            ("outgoing-score-zero-pruned", "ledger.rs", "pub(crate) fn prune", "fn account(", [("self.counts(identity) != Some(Accounting::default())", "self.counts(identity).map(Accounting::connection_score) != Some(0)", 1)], "redirect_transfers_score_then_physical_and_failure_returns_only_score"),
        ]
        requested = set(sys.argv[1:])
        unknown = requested - {case[0] for case in cases}
        if unknown:
            raise RuntimeError(f"unknown migration mutations: {sorted(unknown)}")
        cases = [case for case in cases if not requested or case[0] in requested]
        for name, file, begin, end, changes, expected in cases:
            original = originals[file]
            start = original.index(begin)
            finish = original.index(end, start)
            part = original[start:finish]
            for before, after, count in changes:
                if part.count(before) < count:
                    raise RuntimeError(f"anchor absent: {name}: {before}")
                part = part.replace(before, after, count)
            path = source / file
            path.write_text(original[:start] + part + original[finish:])
            compiled = run(["--no-run"])
            if compiled.returncode:
                raise RuntimeError(f"mutation must compile: {name}\n{compiled.stdout}")
            tested = run([])
            if tested.returncode != 101 or f"{expected} ... FAILED" not in tested.stdout:
                raise RuntimeError(f"mutation missed required test: {name}\n{tested.stdout}")
            if name == "offer-releases-lock-before-commit" and "MIGRATION_TERMINAL_BEFORE_COMMIT" not in tested.stdout:
                raise RuntimeError(f"mutation missed commit-order assertion: {name}\n{tested.stdout}")
            path.write_text(original)
            print(f"CP-ROUTE migration mutation killed: {name}", flush=True)
        baseline()
        print("CP-ROUTE migration restored baseline passed", flush=True)


if __name__ == "__main__":
    main()
