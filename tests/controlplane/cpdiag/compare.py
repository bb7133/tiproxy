#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exact comparison of the Go capture and the Rust replay for the diagnostics
gRPC service (CP-ADMIN slice 4b).

Every search is compared packet by packet (time, level, message) and on its
final status code, for the plaintext h2c side and the TLS side. The HTTP/1.1
`application/grpc` probe status must match on both sides. Fields the script
lists under "declared" name divergences the design document owns; they must
still differ, otherwise the declaration is stale."""
import json
import sys


def main() -> int:
    script_path, go_path, rust_path = sys.argv[1:4]
    script = json.load(open(script_path))
    go = json.load(open(go_path))
    rust = json.load(open(rust_path))
    declared = script.get("declared", {})
    failures = []
    notes = []
    compared = 0
    for side in ("plain", "tls"):
        go_side, rust_side = go[side], rust[side]
        go_searches = {row["name"]: row for row in go_side["searches"]}
        rust_searches = {row["name"]: row for row in rust_side["searches"]}
        for search in script["searches"]:
            name = search["name"]
            if name not in go_searches or name not in rust_searches:
                failures.append(f"{side}/{name}: missing (go={name in go_searches}, rust={name in rust_searches})")
                continue
            g, r = go_searches[name], rust_searches[name]
            if g["code"] != r["code"]:
                failures.append(f"{side}/{name}: code go={g['code']} rust={r['code']}")
                continue
            if g["packets"] != r["packets"]:
                shape_g = [len(p) for p in g["packets"]]
                shape_r = [len(p) for p in r["packets"]]
                if shape_g != shape_r:
                    failures.append(f"{side}/{name}: packet shape go={shape_g} rust={shape_r}")
                else:
                    for index, (pg, pr) in enumerate(zip(g["packets"], r["packets"])):
                        for jndex, (mg, mr) in enumerate(zip(pg, pr)):
                            if mg != mr:
                                failures.append(f"{side}/{name}: packet {index} message {jndex} go={mg!r} rust={mr!r}")
                                break
                        else:
                            continue
                        break
                continue
            compared += 1
        for field in ("http1_grpc_status", "server_info_code"):
            key = f"{side}.{field}"
            if go_side[field] != rust_side[field]:
                if key in declared:
                    notes.append(f"{key} [{declared[key]}]: go={go_side[field]} rust={rust_side[field]}")
                else:
                    failures.append(f"{key}: go={go_side[field]} rust={rust_side[field]}")
            elif key in declared:
                failures.append(f"{key}: declared divergence {declared[key]!r} no longer differs; remove the declaration")
            else:
                compared += 1
    for line in notes:
        print(f"DECLARED {line}")
    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print(f"PASS: {compared} identical CP-DIAG observations across plaintext h2c and TLS, {len(notes)} declared divergences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
