#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Actual Go comparison, real composed reserves and policy/HTTP boundary tests."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("factor_live", ROOT / "tests/controlplane/cpmetrics/factors/live.py")
factor_live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factor_live)
MARKER = "CP-ROUTE-COMPOSE actual Resource/Location reservations and query lifecycle passed"


def compile_binaries(root, environment):
    result = subprocess.run(["cargo", "test", "--locked", "--offline", "--no-run", "--message-format=json",
        "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-config", "-p", "control-router", "-p", "control-topology"],
        env=environment, text=True, capture_output=True, timeout=600)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if result.returncode:
        messages = "\n".join(item["message"].get("rendered", item["message"]["message"])
            for item in artifacts if item.get("reason") == "compiler-message")
        raise RuntimeError("composition candidate did not compile:\n" + result.stderr + messages)
    wanted = {"control_router", "control_topology", "source"}
    binaries = {item["target"]["name"]: item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] in wanted}
    if set(binaries) != wanted:
        raise RuntimeError(f"unexpected composition test artifacts: {binaries}")
    return binaries


def run(binary, selection, environment):
    return subprocess.run([binary, selection, "--nocapture", "--test-threads=1"], env=environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)


def observe(binary, environment):
    return factor_live.observe(binary, environment, "composed_real_")


def baseline(root, environment):
    if not Path(environment["CPROUTE_RESOURCE_OUTPUT"]).is_file():
        raise RuntimeError("actual Go Group.Route output is required")
    binaries = compile_binaries(root, environment)
    rows = [
        (run(binaries["source"], "resource_incarnation_", environment), "1 passed; 0 failed"),
        (run(binaries["control_topology"], "routing_quer", environment), "2 passed; 0 failed"),
        (run(binaries["control_router"], "composed_", environment), "3 passed; 0 failed"),
        (observe(binaries["control_router"], environment), MARKER),
    ]
    for result, marker in rows:
        if result.returncode or marker not in result.stdout:
            raise RuntimeError("composition baseline/restoration failed:\n" + result.stdout)
        print(result.stdout, flush=True)
    print("CP-ROUTE-COMPOSE baseline/restoration passed", flush=True)
    return binaries


if __name__ == "__main__":
    baseline(ROOT, dict(os.environ))
