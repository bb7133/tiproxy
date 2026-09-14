#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Build and run the API-boundary recorder (recorder README §5).

The recording build never edits the production tree: it uses `go build -overlay` with
generated copies of these files:

  pkg/proxy/backend/backend_conn_mgr.go   selector call sites -> apireplay.Open/Next/Finish/EndSelection
  pkg/balance/router/group.go             time.Now() -> replayNow()  (harness logical clock)
  pkg/balance/router/router_score.go      time.Now() -> replayNow()
  pkg/balance/factor/factor_{cpu,memory,health}.go  time.Now() -> replayclock.Now()
  pkg/proxy/backend/api_replay_overlay_marker.go    build attestation (new overlaid file)

Every substitution is anchored on the exact production text; a missing anchor aborts
(the overlay is regenerated from the current tree on every run, never cached).

  record.py overlay  --out DIR                    # write DIR/overlay.json (+ copies)
  record.py build    --out DIR                    # overlay + go build -tags apireplay
  record.py run      --out DIR -- <record flags>  # build + run the recorder binary
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
PKG = "./tests/controlplane/cproute/api-differential/recorder/cmd/record"
APIREPLAY = "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
OVERLAY_MARKER = "pkg/proxy/backend/api_replay_overlay_marker.go"

SUBSTITUTIONS = {
    "pkg/proxy/backend/backend_conn_mgr.go": [
        ("r, err := mgr.handshakeHandler.GetRouter(cctx, resp)\n\tif err != nil {\n\t\treturn nil, errors.Wrap(err, ErrProxyErr)\n\t}",
         "apiRoute := apireplay.BeginRoute()\n\tr, err := mgr.handshakeHandler.GetRouter(cctx, resp)\n\tif err != nil {\n\t\tapiRoute.End()\n\t\treturn nil, errors.Wrap(err, ErrProxyErr)\n\t}", 1),
        ("selector := r.GetBackendSelector(ci)", "selector, apiSession := apireplay.OpenRoute(apiRoute, r, ci)", 1),
        ("defer selector.CloseObservation()", "defer apireplay.EndSelection(&selector, apiSession)", 1),
        ("if backend, err = selector.Next(); err == router.ErrNoBackend {", "if backend, err = apireplay.Next(&selector, apiSession); err == router.ErrNoBackend {", 1),
        ("selector.Finish(mgr, err == nil)", "apireplay.Finish(&selector, apiSession, mgr, err == nil)", 1),
        ('\t"github.com/pingcap/tiproxy/pkg/balance/router"\n', '\t"github.com/pingcap/tiproxy/pkg/balance/router"\n\t"' + APIREPLAY + '"\n', 1),
    ],
    "pkg/balance/router/group.go": [("time.Now()", "replayNow()", None)],
    "pkg/balance/router/router_score.go": [("time.Now()", "replayNow()", None)],
}

for name in ("factor_cpu.go", "factor_memory.go", "factor_health.go", "factor_status.go"):
    SUBSTITUTIONS["pkg/balance/factor/" + name] = [
        ('"time"', '"time"\n\treplayclock "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/clock"', 1),
        ("time.Now()", "replayclock.Now()", None),
    ]


def substitute(rel, text):
    for old, new, count in SUBSTITUTIONS[rel]:
        n = text.count(old)
        if n == 0 or (count is not None and n != count):
            raise SystemExit(f"anchor mismatch in {rel}: {old!r} occurs {n} times (expected {count or '>=1'})")
        text = text.replace(old, new)
    return text


def overlay(out):
    out.mkdir(parents=True, exist_ok=True)
    replace = {}
    for rel in SUBSTITUTIONS:
        src = ROOT / rel
        dst = out / "overlay" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(substitute(rel, src.read_text()))
        replace[str(src)] = str(dst)
    marker = ROOT / OVERLAY_MARKER
    if marker.exists():
        raise SystemExit(f"overlay marker target unexpectedly exists: {marker}")
    marker_copy = out / "overlay" / OVERLAY_MARKER
    marker_copy.parent.mkdir(parents=True, exist_ok=True)
    marker_copy.write_text(
        "// Copyright 2026 PingCAP, Inc.\n"
        "// SPDX-License-Identifier: Apache-2.0\n\n"
        "package backend\n\n"
        f'import "{APIREPLAY}"\n\n'
        "func init() { apireplay.MarkOverlayInstalled() }\n"
    )
    replace[str(marker)] = str(marker_copy)
    path = out / "overlay.json"
    path.write_text(json.dumps({"Replace": replace}, indent=2) + "\n")
    return path


def build(out):
    path = overlay(out)
    binary = out / "record"
    env = os.environ.copy()
    # os.Getwd (and therefore the Go command) trusts a matching inherited PWD.
    # Keep it identical to the realpath used by every overlay key so a logical
    # symlink such as macOS /tmp cannot silently bypass all replacements.
    env["PWD"] = str(ROOT)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, env=env, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, env=env, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, env=env, text=True).strip())
    ldflags = f"-X main.sourceHead={head} -X main.sourceTree={tree} -X main.sourceDirty={str(dirty).lower()}"
    cmd = ["go", "build", "-ldflags", ldflags, "-tags", "apireplay", "-overlay", str(path), "-o", str(binary), PKG]
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)
    # The generated backend init marker is linked only when Go honored the
    # overlay. Execute it so a nominally successful but uninstrumented build
    # cannot reach a live environment.
    subprocess.run([str(binary), "-check-overlay"], cwd=ROOT, env=env, check=True)
    return binary


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["overlay", "build", "run"])
    ap.add_argument("--out", type=Path, required=True)
    args, rest = ap.parse_known_args()
    if args.command == "overlay":
        print(overlay(args.out))
        return
    binary = build(args.out)
    if args.command == "build":
        print(binary)
        return
    rest = [a for a in rest if a != "--"]
    env = os.environ.copy()
    env["PWD"] = str(ROOT)
    os.execve(str(binary), [str(binary), *rest], env)


if __name__ == "__main__":
    main()
