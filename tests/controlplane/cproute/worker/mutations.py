#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile each fault; require its named semantic assertion and restore baseline."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import live

# Each mutation is confined to an owned copy. Compiler failures never count.
CASES = [
    ("rate-ceil", "scheduler.rs", "(TICK.as_nanos() - 1)", "TICK.as_nanos()", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("rate-twenty-ms", "scheduler.rs", "interval < TICK * 2", "interval <= TICK * 2", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("rate-equal-deadline", "scheduler.rs", "since(last) >= interval", "since(last) > interval", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("queue-extra-slot", "scheduler.rs", "entries.len() >= self.capacity", "entries.len() > self.capacity", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("refusal-record-boundary", "scheduler.rs", "since(last) >= Duration::from_secs(10)", "since(last) > Duration::from_secs(10)", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("rejected-offer-advances-watermark", "selector/scheduler.rs", "Ok(false)\n                                | Err(", "Ok(false) => { state.schedules.entry(*group).or_default().accepted(now); }, Err(", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("close-uses-old-balance-clock", "selector/scheduler.rs", "let now = clock.close_now();", "let now = clock.balance_now();", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("close-needs-redirect-capability", "selector/scheduler.rs", "self.close_timed_out(&mut state, candidate, sender, stop, clock)", "if redirects_enabled { self.close_timed_out(&mut state, candidate, sender, stop, clock) } else { Ok(()) }", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("close-rejection-admitted", "selector/scheduler.rs", "if sender.try_send(close.clone()).is_ok() {", "if sender.try_send(close.clone()).is_ok() || true {", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("close-admission-settles", "selector/scheduler.rs", "state.ledger.admit_close(close);", "state.ledger.admit_close(close.clone()); state.ledger.observe_close(&close);", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("failover-first-time-reset", "selector/scheduler.rs", "backend.failover_since.get_or_insert(now);", "backend.failover_since = Some(now);", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("failover-never-clears", "selector/scheduler.rs", "backend.failover_since = None;", "", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("failover-all-failed-guard", "selector/scheduler.rs", "let ignore = !routeable.is_empty()", "let ignore = false && !routeable.is_empty()", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("first-group-only", "selector/scheduler.rs", "for group in &groups {", "for group in groups.iter().take(1) {", "worker_visits_every_group", "WORKER_ALL_GROUPS"),
    ("cancel-scan-ignored", "selector/scheduler.rs", "if stopped(stop) || accepted >= budget {", "if accepted >= budget {", "worker_cancellation_stops", "WORKER_CANCEL_SCAN"),
    ("closing-can-redirect", "ledger.rs", "if active.closing.is_some() {", "if false && active.closing.is_some() {", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("pending-can-redirect", "ledger.rs", "if active.redirect.is_some() {", "if false && active.redirect.is_some() {", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("cooldown-equal-deadline", "ledger.rs", "since(failed) < Duration::from_secs(3)", "since(failed) <= Duration::from_secs(3)", "shared_go_worker_clock_events", "WORKER_GO_CLOCK"),
    ("close-wrong-sequence", "ledger.rs", "pending.sequence != close.sequence", "false && pending.sequence != close.sequence", "worker_close_tokens", "WORKER_CLOSE_SEQUENCE"),
    ("close-sequence-exhaustion", "ledger.rs", "self.next_close\n            .checked_add(1)\n            .ok_or(LedgerError::Exhausted)?;", "", "worker_close_tokens", "WORKER_CLOSE_EXHAUSTED"),
    ("ticker-immediate", "simulation_worker.rs", "tokio::time::Instant::now() + crate::scheduler::TICK", "tokio::time::Instant::now()", "worker_ticker_delays", "WORKER_FIRST_TICK"),
    ("ticker-burst", "simulation_worker.rs", "tokio::time::MissedTickBehavior::Skip", "tokio::time::MissedTickBehavior::Burst", "worker_ticker_delays", "WORKER_MISSED_SKIP"),
    ("source-notifications-ignored", "simulation_worker.rs", "self.router.refresh_failover(&candidate, now)", "{ let _ = now; Ok(()) }", "worker_source_notifications", "WORKER_SOURCE_NOTIFY"),
    ("metric-final-fence", "selector/balance.rs", "metrics.with_current(|| select(Some(metrics), &queries))", "Some(select(Some(metrics), &queries))", "live", "WORKER_REAL_FALLBACK_ADMISSION"),
]

def main():
    repo = Path(__file__).resolve().parents[4]
    with tempfile.TemporaryDirectory(prefix="cproute-worker-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        target = root / "target"
        seed = os.environ.get("CPROUTE_WORKER_TARGET_SEED")
        if seed:
            cp = ["cp", "-cR"] if sys.platform == "darwin" else ["cp", "-a", "--reflink=auto"]
            subprocess.run(cp + [seed, str(target)], check=True)
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        def run(binary, selection):
            return subprocess.run([binary, selection, "--nocapture", "--test-threads=1"],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        def baseline():
            binary = live.compile_binary(root, env)
            r = run(binary, "worker_")
            if r.returncode or "0 passed" in r.stdout:
                raise RuntimeError("worker restored/unit baseline failed:\n" + r.stdout)
            r = live.observe(binary, env)
            if r.returncode or live.MARKER not in r.stdout:
                raise RuntimeError("worker live baseline failed:\n" + r.stdout)
        baseline()
        source = root / "rust/crates/control-router/src"
        missed = []
        for name, file, before, after, selection, marker in CASES:
            path = source / file
            original = path.read_text()
            if before not in original:
                raise RuntimeError(f"missing mutation anchor {name}: {before}")
            try:
                path.write_text(original.replace(before, after, 1))
                binary = live.compile_binary(root, env)
                r = live.observe(binary, env) if selection == "live" else run(binary, selection)
                if r.returncode != 101 or marker not in r.stdout:
                    missed.append(name)
                    print(f"CP-ROUTE worker mutation MISSED: {name}\n{r.stdout}", flush=True)
                else:
                    print(f"CP-ROUTE worker mutation killed: {name}", flush=True)
            finally:
                path.write_text(original)
        baseline()
        if missed:
            raise RuntimeError(f"undetected worker mutations: {missed}")
        print(f"CP-ROUTE worker restored baseline passed: {len(CASES)} mutations", flush=True)

if __name__ == "__main__":
    main()
