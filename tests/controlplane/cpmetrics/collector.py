#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Owned real etcd + actual Go BackendReader peer for each collector observation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
LIVE_MARKERS = [
    "actual Go Rust owner history", "immediate first round", "Prom rounds",
    "scoped cleanup and retained HTTP", "real module lifecycle",
]


def ready(path, process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                # os.WriteFile creates the file before writing its complete JSON.
                # Readiness is a decoded description, not mere path existence.
                pass
        if process.poll() is not None:
            raise RuntimeError(f"fixture exited before readiness: {process.returncode}")
        time.sleep(0.025)
    raise RuntimeError("fixture readiness deadline exceeded")


def request(url, method="GET"):
    with HTTP.open(urllib.request.Request(url, method=method), timeout=5) as response:
        return response.read()


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def observe(binary, test, live, environment):
    command = [str(binary), test, "--nocapture", "--test-threads=1"]
    if not live:
        return subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=60)
    command.append("--ignored")
    with tempfile.TemporaryDirectory(prefix="cpmetric-collector-live-") as directory:
        root = Path(directory)
        fixture = peer = None
        control = go_control = None
        result = None
        environment = dict(environment, CP003_CONNECTION_FILE=str(root / "connection.json"),
                           CPMETRICS_COLLECTOR_PEER_FILE=str(root / "peer.json"))
        with (root / "fixture.log").open("w+") as fixture_log, (root / "peer.log").open("w+") as peer_log:
            try:
                fixture = subprocess.Popen([environment["CPMETRICS_COLLECTOR_FIXTURE_BIN"],
                    "-connection-file", environment["CP003_CONNECTION_FILE"], "-data-dir", str(root / "etcd")],
                    env=environment, stdout=fixture_log, stderr=subprocess.STDOUT)
                control = ready(root / "connection.json", fixture)["control_url"]
                peer = subprocess.Popen([environment["CPMETRICS_COLLECTOR_GO_BIN"],
                    "-test.run=^TestCPMetricsCollectorPeer$", "-test.timeout=90s"],
                    env=environment, stdout=peer_log, stderr=subprocess.STDOUT)
                go_control = ready(root / "peer.json", peer)["control_url"]
                result = subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, timeout=60)
                return result
            except Exception:
                fixture_log.seek(0)
                peer_log.seek(0)
                print("fixture diagnostics:\n" + fixture_log.read()[-6000:] + peer_log.read()[-6000:], flush=True)
                raise
            finally:
                # Failed candidates can leave etcd stopped or cleanup/history held.
                if control:
                    for path in ["/release-cleanup", "/start"]:
                        try:
                            request(control + path, "POST")
                        except urllib.error.HTTPError as error:
                            if path != "/start" or error.code != 409:
                                print(f"fixture reset failed: {path}: HTTP {error.code}", flush=True)
                        except OSError:
                            pass
                if go_control:
                    try:
                        request(go_control + "/release-history")
                        request(go_control + "/stop")
                        peer.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                stop(peer)
                stop(fixture)
                if peer is not None and peer.returncode not in (0, -15):
                    peer_log.seek(0)
                    print(peer_log.read(), flush=True)
                if result is not None and result.returncode == 0 and peer is not None and peer.returncode != 0:
                    raise RuntimeError(f"Go peer did not complete cleanly: {peer.returncode}")


def compile_binary(root, environment):
    result = subprocess.run(["cargo", "test", "--no-run", "--locked", "--offline", "--message-format=json",
        "--manifest-path", str(root / "rust/Cargo.toml"), "-p", "control-topology", "--lib"],
        env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    if result.returncode:
        raise RuntimeError("collector candidate did not compile:\n" + result.stderr + result.stdout)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    binaries = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact"
        and item.get("executable") and item["target"]["name"] == "control_topology"]
    if len(binaries) != 1:
        raise RuntimeError(f"expected exactly one collector binary, got {binaries}")
    return binaries[0]


def baseline(root, environment):
    binary = compile_binary(root, environment)
    unit = observe(binary, "collector_", False, environment)
    if unit.returncode or "7 passed; 0 failed" not in unit.stdout:
        raise RuntimeError("collector unit baseline/restoration failed:\n" + unit.stdout)
    live = observe(binary, "collector_real_", True, environment)
    if live.returncode or "5 passed; 0 failed" not in live.stdout or any(
        f"CP-METRIC-COLLECTOR {marker} passed" not in live.stdout for marker in LIVE_MARKERS
    ):
        raise RuntimeError("collector live baseline/restoration failed:\n" + live.stdout)
    print(unit.stdout + live.stdout, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    baseline(args.root, dict(os.environ))
