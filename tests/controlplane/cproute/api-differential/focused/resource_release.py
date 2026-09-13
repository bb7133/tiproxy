#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Resource-release focused suite runner (API differential contract section 4).

Runs the Go and Rust native resource-release tests against the shared case table
(resource-release.json), collects each engine's manifest and writes one suite
manifest. The suite passes only when both engines ran every declared case for the
declared cycle count with no violations and both negative controls detected a leak.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent


def run(cmd, env, cwd):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, env=env).returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    spec_path = HERE / "resource-release.json"
    spec = json.loads(spec_path.read_text())
    engines = {
        "go": (["go", "test", "-race", "-count=1", "-run", "^TestAPIResourceRelease$", "./pkg/balance/router"], ROOT),
        "rust": (["cargo", "test", "--locked", "-p", "control-router", "--lib", "--",
                  "tests::resource_release::api_resource_release", "--exact", "--ignored"], ROOT / "rust"),
    }
    summary = {"suite": spec["suite"], "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
               "cycles": spec["cycles"], "cases": spec["cases"], "engines": {}}
    ok = True
    for engine, (cmd, cwd) in engines.items():
        out = (args.output / f"{engine}.json").resolve()
        if out.exists():
            out.unlink()
        env = dict(os.environ, CPROUTE_RESOURCE_OUTPUT=str(out))
        rc = run(cmd, env, cwd)
        result = json.loads(out.read_text()) if out.exists() else None
        problems = []
        if rc != 0:
            problems.append(f"test exited {rc}")
        if result is None:
            problems.append("no engine manifest")
        else:
            got = [c["case"] for c in result["cases"]]
            if got != spec["cases"]:
                problems.append(f"cases {got} != declared {spec['cases']}")
            if any(c["cycles"] != spec["cycles"] or c["violations"] for c in result["cases"]):
                problems.append("cycle count or violations")
            if not result.get("negative_control_detected"):
                problems.append("negative control did not detect a leak")
        summary["engines"][engine] = {"rc": rc, "problems": problems, "manifest": out.name}
        ok = ok and not problems
    summary["status"] = "passed" if ok else "failed"
    (args.output / "manifest.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
