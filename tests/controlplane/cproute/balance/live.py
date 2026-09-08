#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile the candidate and own real etcd/topology/health/collector inputs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("factor_live", ROOT / "tests/controlplane/cpmetrics/factors/live.py")
factor_live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factor_live)
MARKER = "CP-ROUTE-BALANCE real producer preparation and fences passed"

def compile_binary(root, env):
    r = subprocess.run(["cargo", "test", "--locked", "--offline", "--no-run", "--message-format=json",
        "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-router", "--lib"],
        env=env, text=True, capture_output=True, timeout=600)
    artifacts = [json.loads(line) for line in r.stdout.splitlines() if line.startswith("{")]
    if r.returncode:
        raise RuntimeError("balance candidate did not compile:\n" + r.stdout + r.stderr)
    binaries = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("executable") and a["target"]["name"] == "control_router"]
    if len(binaries) != 1:
        raise RuntimeError(f"unexpected balance artifacts: {binaries}")
    return binaries[0]

def observe(binary, env):
    return factor_live.observe(binary, env, "balance_real_")

def baseline(root, env):
    binary = compile_binary(root, env)
    r = observe(binary, env)
    if r.returncode or "1 passed; 0 failed" not in r.stdout or MARKER not in r.stdout:
        raise RuntimeError("balance runtime failed:\n" + r.stdout)
    print(r.stdout, flush=True)
    return binary

if __name__ == "__main__":
    baseline(ROOT, dict(os.environ))
