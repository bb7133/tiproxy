#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile current factor code and own a real embedded-etcd fixture per run."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collector import ready, stop

ROOT = Path(__file__).resolve().parents[4]
MARKER = "CP-METRIC-FACTORS real producer ledger continuity and authority passed"


def compile_binary(environment):
    result = subprocess.run(["cargo", "test", "--locked", "--offline", "--no-run", "--message-format=json",
        "--manifest-path", str(ROOT / "rust/Cargo.toml"), "-p", "control-router", "--lib"],
        env=environment, text=True, capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError("factor candidate did not compile:\n" + result.stderr + result.stdout)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    binaries = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact"
                and item.get("executable") and item["target"]["name"] == "control_router"]
    if len(binaries) != 1:
        raise RuntimeError(f"expected one factor binary, got {binaries}")
    return binaries[0]


def observe(binary, environment):
    with tempfile.TemporaryDirectory(prefix="cpmetric-factor-live-") as directory:
        temp = Path(directory)
        environment = dict(environment, CP003_CONNECTION_FILE=str(temp / "connection.json"))
        fixture = None
        with (temp / "fixture.log").open("w+") as log:
            try:
                fixture = subprocess.Popen([environment["CPMETRICS_FACTOR_FIXTURE_BIN"],
                    "-connection-file", environment["CP003_CONNECTION_FILE"], "-data-dir", str(temp / "etcd")],
                    env=environment, stdout=log, stderr=subprocess.STDOUT)
                ready(temp / "connection.json", fixture)
                result = subprocess.run([binary, "factor_real_", "--ignored", "--nocapture", "--test-threads=1"],
                    env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
                if result.returncode:
                    log.seek(0)
                    result.stdout += "\nfixture tail:\n" + log.read()[-3000:]
                return result
            finally:
                stop(fixture)


def baseline(environment):
    result = observe(compile_binary(environment), environment)
    if result.returncode or "1 passed; 0 failed" not in result.stdout or MARKER not in result.stdout:
        raise RuntimeError("factor live baseline/restoration failed:\n" + result.stdout)
    print(result.stdout, flush=True)


if __name__ == "__main__":
    baseline(dict(os.environ))
