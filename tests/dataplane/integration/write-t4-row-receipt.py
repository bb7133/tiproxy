#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Write a fail-closed evidence receipt for a completed T4 M1-M8 row."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any


ZERO_LEDGER_KEYS = (
    "sessions",
    "reserved",
    "active",
    "incoming",
    "outgoing",
    "unsettled_redirects",
    "unsettled_closes",
)
RETIRED_AUDIT_KEYS = (
    "state_backends",
    "state_namespaces",
    "reconcile_request_connections",
    "reconcile_request_event_sequences",
    "reconcile_snapshot_connections",
    "reconcile_snapshot_event_sequences",
)
REQUIRED_PHASES = (
    "harness-start",
    "etcdctl-resolved",
    "mtr005-complete",
    "namespace-bootstrap-start",
    "namespace-bootstrap-complete",
)
REQUIRED_PROCESS_ROLES = {
    "tiup-main",
    "tiup-secondary",
    "control-tap",
    "rust-main",
    "ingress-faultproxy",
    "go-ka",
    "control-tap-ka",
    "rust-ka",
}
ROW_CONTRACTS = {
    "M1": "baseline admission, authentication, retry recovery, and normal close",
    "M2": "namespace replacement and per-connection namespace resolution",
    "M3": "topology/config generation rotation and current-generation selection",
    "M4": "health rotation, cross-keyspace refusal, and recovery",
    "M5": "nonempty production health and CPU/memory route inputs",
    "M6": "listener conflicts, no-backend parity, and recovery",
    "M7": "redirect migration, state preservation, and cross-keyspace guard",
    "M8": "local terminal uniqueness and zero unsettled operations",
}


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing evidence: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON evidence {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"evidence is not a JSON object: {path.name}")
    return value


def require_text(path: Path, *patterns: str) -> str:
    if not path.is_file():
        raise ValueError(f"missing evidence: {path.name}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise ValueError(f"empty evidence: {path.name}")
    for pattern in patterns:
        if pattern not in text:
            raise ValueError(f"{path.name} does not contain required observation: {pattern}")
    return text


def validate_ledger(path: Path) -> dict[str, Any]:
    state = load_json(path)
    if state.get("status") != "OK":
        raise ValueError(f"{path.name} status is not OK")
    ledger = state.get("route_ledger")
    if not isinstance(ledger, dict):
        raise ValueError(f"{path.name} has no route ledger")
    nonzero = {key: ledger.get(key) for key in ZERO_LEDGER_KEYS if ledger.get(key) != 0}
    if nonzero:
        raise ValueError(f"{path.name} has nonzero route state: {nonzero}")
    if not isinstance(ledger.get("router_incarnations"), int) or ledger["router_incarnations"] < 1:
        raise ValueError(f"{path.name} has no router incarnation")
    generations = state.get("source_generations")
    if not isinstance(generations, dict) or not generations:
        raise ValueError(f"{path.name} has no source generations")
    if any(not isinstance(value, int) or value < 0 for value in generations.values()):
        raise ValueError(f"{path.name} has invalid source generations: {generations}")
    inputs = state.get("route_inputs")
    if not isinstance(inputs, dict):
        raise ValueError(f"{path.name} has no route inputs")
    return {
        "router_incarnations": ledger["router_incarnations"],
        "zero_keys": list(ZERO_LEDGER_KEYS),
        "source_generations": generations,
        "route_inputs": inputs,
    }


class PendingMeteringAck(ValueError):
    """An otherwise valid live snapshot has a suffix of unacknowledged batches."""


def validate_route_audit(path: Path) -> dict[str, Any]:
    state = load_json(path)
    audit = state.get("route_audit")
    if not isinstance(audit, dict):
        raise ValueError(f"{path.name} has no route audit")
    legacy = audit.get("legacy_body_counts")
    if not isinstance(legacy, dict) or not legacy:
        raise ValueError(f"{path.name} has no retired-body catalog")
    nonzero = {name: count for name, count in legacy.items() if count != 0}
    nonzero.update({name: audit.get(name) for name in RETIRED_AUDIT_KEYS if audit.get(name) != 0})
    if nonzero:
        raise ValueError(f"{path.name} observed retired route state: {nonzero}")
    if audit.get("protocol_errors") != 0 or audit.get("fatal_protocol_errors") != 0:
        raise ValueError(f"{path.name} observed protocol errors")
    events = audit.get("metering_events")
    if not isinstance(events, list) or not events:
        raise ValueError(f"{path.name} has no ordered metering events")
    if [event.get("ordinal") for event in events] != list(range(1, len(events) + 1)):
        raise ValueError(f"{path.name} metering ordinals are not contiguous")
    batches = [event for event in events if event.get("kind") == "batch"]
    acknowledgements = [event for event in events if event.get("kind") == "ack"]
    batch_sequences = [event.get("sequence") for event in batches]
    acknowledgement_sequences = [event.get("sequence") for event in acknowledgements]
    # With native Rust metering (CP-ADMIN 5c/5d onward) the residual bridge
    # emits no metering batches, so an empty batch/ack sequence is legal. Only
    # verify batch contiguity and the producer fingerprint when the residual
    # bridge actually produced metering events.
    if batch_sequences != list(range(1, len(batch_sequences) + 1)):
        raise ValueError(f"{path.name} metering batch sequence is not contiguous")
    if (
        audit.get("metering_batches") != len(batches)
        or audit.get("metering_acks") != len(acknowledgements)
    ):
        raise ValueError(f"{path.name} metering counters disagree with ordered events")
    metered = batches + acknowledgements
    fingerprint = None
    if metered:
        fingerprints = {event.get("producer_fingerprint") for event in metered}
        if len(fingerprints) != 1:
            raise ValueError(f"{path.name} producer fingerprint changed: {fingerprints}")
        fingerprint = next(iter(fingerprints))
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise ValueError(f"{path.name} producer fingerprint is not SHA-256 hex")
    elif [event.get("kind") for event in events] != ["reconcile_request", "reconcile_snapshot"]:
        # Native metering emits no batches/acks, but the final audit must still
        # carry the complete reconcile_request -> reconcile_snapshot pair. An
        # incomplete reconcile (e.g. a missing snapshot) still fails closed.
        raise ValueError(
            f"{path.name} native-metering audit is not a complete "
            "reconcile_request->reconcile_snapshot pair: "
            f"{[event.get('kind') for event in events]}"
        )
    if state.get("connect_count", 0) < 1 or state.get("forwarded", 0) < 1:
        raise ValueError(f"{path.name} was not on the live control path")
    if state.get("armed") is not False or state.get("held") is not False:
        raise ValueError(f"{path.name} retained a control fault at row completion")
    if acknowledgement_sequences != batch_sequences:
        error = f"{path.name} metering acknowledgements do not conserve batches"
        if acknowledgement_sequences == batch_sequences[:len(acknowledgements)]:
            # Only a missing suffix may settle while the live tap keeps recording.
            # The receipt writer still rejects it; only the capture loop retries.
            raise PendingMeteringAck(error)
        raise ValueError(error)
    return {
        "legacy_body_counts": legacy,
        "protocol_errors": 0,
        "fatal_protocol_errors": 0,
        "metering_batches": len(batches),
        "metering_acks": len(acknowledgements),
        "max_metering_sequence": batch_sequences[-1] if batch_sequences else 0,
        "producer_fingerprint": fingerprint,
        "connect_count": state["connect_count"],
        "forwarded": state["forwarded"],
    }


def capture_route_audit(url: str, output: Path, *, timeout: float = 5.0,
                        fetch=None, clock=time.monotonic, sleep=time.sleep) -> None:
    """Capture a conserved M1-M8 audit before either control peer is stopped.

    This is a live sampling barrier, not a failed-cell rerun. Keep the first
    sample even when its in-flight ACK arrives later. Protocol/identity/counter
    failures are terminal; a permanently missing ACK fails at the deadline.
    """
    first = output.with_name(output.stem + "-first.json")
    if output.exists() or first.exists():
        raise ValueError(f"refusing to overwrite audit capture: {output.name}")
    if fetch is None:
        def fetch(remaining):
            return subprocess.run(
                ["curl", "--noproxy", "*", "--fail", "--silent", "--show-error",
                 "--max-time", str(min(1.0, remaining)), url],
                check=True, stdout=subprocess.PIPE, timeout=remaining,
            ).stdout

    deadline = clock() + timeout
    previous_events = []
    samples = 0
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise ValueError(f"{output.name} ACK conservation timed out after {timeout}s")
        raw = fetch(remaining)
        output.write_bytes(raw)
        samples += 1
        if samples == 1:
            first.write_bytes(raw)
        if clock() >= deadline:
            raise ValueError(f"{output.name} audit capture exceeded {timeout}s")
        events = load_json(output).get("route_audit", {}).get("metering_events", [])
        if events[:len(previous_events)] != previous_events:
            raise ValueError(f"{output.name} audit history changed while waiting for ACK")
        previous_events = events
        try:
            result = validate_route_audit(output)
        except PendingMeteringAck:
            sleep(min(0.1, max(0.0, deadline - clock())))
            continue
        print(f"T4 route tap {output.name}: conserved {result['metering_batches']} "
              f"batches/ACKs after {samples} sample(s); initial snapshot retained")
        return


def validate_phases(path: Path) -> list[str]:
    if not path.is_file():
        raise ValueError(f"missing evidence: {path.name}")
    phases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            raise ValueError(f"malformed phase receipt: {line!r}")
        phases.append(fields[1])
    selected = [phase for phase in phases if phase in REQUIRED_PHASES]
    if selected != list(REQUIRED_PHASES):
        raise ValueError(f"required T4 phases are missing, duplicated, or out of order: {phases}")
    return phases


def validate_lineage(path: Path, row: str, variant: str) -> dict[str, Any]:
    lineage = load_json(path)
    if lineage.get("row") != row or lineage.get("variant") != variant:
        raise ValueError(f"process lineage identity mismatch: {lineage}")
    events = lineage.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("process lineage has no events")
    observed_platform = lineage.get("platform")
    if not isinstance(observed_platform, str) or not observed_platform:
        raise ValueError("process lineage has no platform identity")
    roles = {event.get("role") for event in events if event.get("event") == "start"}
    missing = sorted(REQUIRED_PROCESS_ROLES - roles)
    if missing:
        raise ValueError(f"process lineage is missing roles: {missing}")
    return {
        "event_count": len(events),
        "platform": observed_platform,
        "started_roles": sorted(roles),
    }


def positive_route_inputs(path: Path, require_cpu: bool) -> dict[str, int]:
    state = load_json(path)
    if state.get("status") != "OK":
        raise ValueError(f"{path.name} status is not OK")
    inputs = state.get("route_inputs")
    if not isinstance(inputs, dict):
        raise ValueError(f"{path.name} has no route inputs")
    keys = ["observations", "health_input_backends", "healthy_backends", "memory_series"]
    if require_cpu:
        keys.append("cpu_series")
    invalid = {
        key: inputs.get(key)
        for key in keys
        if not isinstance(inputs.get(key), int) or inputs[key] < 1
    }
    if invalid:
        raise ValueError(f"{path.name} has incomplete live route inputs: {invalid}")
    return {key: int(inputs[key]) for key in sorted(inputs) if isinstance(inputs[key], int)}


def validate_row_specific(
    run: Path, row: str, after: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    if row == "M1":
        require_text(run / "drop-next.out", "ERROR 2013")
        require_text(run / "auth-matrix.err", "ERROR 1045")
        return {"drop_next_error": 2013, "authentication_rejection_error": 1045}, [
            "drop-next.out",
            "auth-matrix.err",
        ]
    if row == "M2":
        files = ["ns-alpha-etcd.log", "ns-beta-etcd.log", "ns-default-etcd.log"]
        for name in files:
            if require_text(run / name).strip() != "OK":
                raise ValueError(f"{name} did not record a successful namespace write")
        return {"namespace_writes": ["ns-alpha", "ns-beta", "default"]}, files
    if row == "M3":
        files = [
            "ka-etcd-mig01-swap.log",
            "ka-etcd-mig01-reset.log",
            "ka-proxy-mig01-swap.json",
            "ka-proxy-mig01-reset.json",
        ]
        for name in files[:2]:
            if require_text(run / name).strip() != "OK":
                raise ValueError(f"{name} did not record a successful config write")
        swap = load_json(run / files[2]).get("fail-backend-list")
        reset = load_json(run / files[3]).get("fail-backend-list")
        if (
            not isinstance(swap, list)
            or not swap
            or not isinstance(reset, list)
            or not reset
            or swap == reset
        ):
            raise ValueError("M3 swap/reset configs do not prove a topology rotation")
        return {"swap_fail_list": swap, "reset_fail_list": reset}, files
    if row == "M4":
        files = [
            "ka-etcd-ka-cross-keyspace.log",
            "ka-etcd-ka-restore.log",
            "ka-rust-cross-keyspace-health.json",
        ]
        for name in files[:2]:
            if require_text(run / name).strip() != "OK":
                raise ValueError(f"{name} did not record a successful health/config write")
        inputs = positive_route_inputs(run / files[2], require_cpu=False)
        return {"recovered_route_inputs": inputs}, files
    if row == "M5":
        name = "t4-m5-route-inputs.json"
        inputs = positive_route_inputs(run / name, require_cpu=True)
        return {"production_route_inputs": inputs}, [name]
    if row == "M6":
        require_text(run / "tiproxy-conflict.out", "address already in use")
        require_text(
            run / "tiproxy-rs-conflict.out",
            '"error_class":"startup_failed"',
            "Address already in use",
        )
        require_text(
            run / "t4-no-backend.out",
            "ERROR 1105 (HY000)",
            "No available TiDB instances, please make sure TiDB is available",
        )
        return {
            "go_bind_conflict": "rejected",
            "rust_bind_conflict": "rejected",
            "no_backend_error": 1105,
        }, ["tiproxy-conflict.out", "tiproxy-rs-conflict.out", "t4-no-backend.out"]
    if row == "M7":
        migration = require_text(run / "mig01-session.out", "MIGBASE|", "MIGTRY")
        old_session = require_text(run / "ka-session.out", "BASE|", "CHK|")
        migration_rows = [
            line.split("|")
            for line in migration.splitlines()
            if line.startswith(("MIGBASE|", "MIGTRY"))
        ]
        if len(migration_rows) < 2:
            raise ValueError("M7 migration evidence has fewer than two observations")
        baseline, migrated = migration_rows[0], migration_rows[-1]
        if (
            len(baseline) < 5
            or len(migrated) < 5
            or baseline[2] == migrated[2]
            or baseline[3:] != migrated[3:]
        ):
            raise ValueError(
                "M7 migration did not preserve database/user state across a backend change"
            )
        session_rows = [
            line.split("|")
            for line in old_session.splitlines()
            if line.startswith(("BASE|", "CHK|"))
        ]
        if len(session_rows) != 2 or session_rows[0][1:] != session_rows[1][1:]:
            raise ValueError("M7 cross-keyspace guard did not preserve the old session identity")
        return {
            "migration_backend_changed": True,
            "migration_state_preserved": True,
            "cross_keyspace_session_preserved": True,
        }, ["mig01-session.out", "ka-session.out"]
    if row == "M8":
        counts = {}
        files = ["tiproxy-rs.log", "tiproxy-rs-ka.log"]
        for name in files:
            text = require_text(run / name, '"event":"connection_closed"')
            connection_ids = []
            for line in text.splitlines():
                # Rust log lines carry the Go `[ts] [LEVEL] ` header (or the
                # zap object shape) in front of / around the JSON body.
                body = line[line.find("{"):] if "{" in line else ""
                try:
                    event = json.loads(body)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "connection_closed":
                    connection_ids.append(event.get("connection_id"))
            if not connection_ids or len(connection_ids) != len(set(connection_ids)):
                raise ValueError(
                    f"{name} has missing or duplicate connection terminals: "
                    f"{connection_ids}"
                )
            counts[name] = len(connection_ids)
        final_ledger = after["zero_keys"]
        return {
            "unique_connection_terminals": counts,
            "zero_final_ledger_keys": final_ledger,
        }, files
    raise ValueError(f"unsupported row: {row}")


def write_receipt(run: Path, row: str, variant: str) -> Path:
    if row not in ROW_CONTRACTS:
        raise ValueError("generic T4 receipt writer accepts only M1 through M8")
    if not run.is_dir():
        raise ValueError(f"run directory does not exist: {run}")
    output = run / f"t4-row-{row}.json"
    if output.exists():
        raise ValueError(f"refusing to overwrite row receipt: {output.name}")

    before_name = "t4-ledger-before.json"
    after_name = "t4-ledger-after.json"
    route_name = "t4-route-audit-final.json"
    route_ka_name = "t4-route-audit-ka-final.json"
    phases_name = "t4-phase-receipts.tsv"
    lineage_name = "t4-process-lineage.json"
    before = validate_ledger(run / before_name)
    after = validate_ledger(run / after_name)
    route = validate_route_audit(run / route_name)
    route_ka = validate_route_audit(run / route_ka_name)
    phases = validate_phases(run / phases_name)
    lineage = validate_lineage(run / lineage_name, row, variant)
    row_assertions, row_evidence = validate_row_specific(run, row, after)

    receipt = {
        "schema": 1,
        "row": row,
        "result": "pass",
        "variant": variant,
        "platform": lineage["platform"],
        "contract": ROW_CONTRACTS[row],
        "assertions": {
            "ledger_before": before,
            "ledger_after": after,
            "route_audit": route,
            "route_audit_ka": route_ka,
            "phase_receipts": phases,
            "process_lineage": lineage,
            "row_specific": row_assertions,
        },
        "evidence": {
            "ledger_before": before_name,
            "ledger_after": after_name,
            "route_audit": route_name,
            "route_audit_ka": route_ka_name,
            "phase_receipts": phases_name,
            "process_lineage": lineage_name,
            "row_specific": row_evidence,
        },
    }
    with output.open("x", encoding="utf-8") as destination:
        json.dump(receipt, destination, sort_keys=True, indent=2)
        destination.write("\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--row")
    parser.add_argument("--variant")
    parser.add_argument("--capture-url", help="capture a live M1-M8 final route audit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.capture_url:
            if args.output is None or any((args.run_dir, args.row, args.variant)):
                parser.error("--capture-url requires --output and no row arguments")
            capture_route_audit(args.capture_url, args.output)
            return 0
        if not all((args.run_dir, args.row, args.variant)) or args.output:
            parser.error("receipt mode requires --run-dir, --row and --variant")
        output = write_receipt(args.run_dir, args.row, args.variant)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"T4 row receipt refused: {error}\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
