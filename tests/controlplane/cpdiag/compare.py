#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exact comparison of the Go capture and the Rust replay for the diagnostics
gRPC service (CP-ADMIN slices 4b and 4c).

Every search is compared packet by packet (time, level, message) and on its
final status code, for the plaintext h2c side and the TLS side. The HTTP/1.1
`application/grpc` probe status must match on both sides.

`ServerInfo` is compared per request type: the item inventory (type, name and
the ordered pair keys) must be identical, static values (hardware facts,
mount facts, interface facts, kernel settings) must be byte-identical, and
live values (load, usage, counters, rates, free space) must carry Go's exact
format on both sides. `system/sysctl` keys must match in order; values must
match except for keys the script lists as volatile. Divergences the design
document owns are declared per Go `GOOS` and must still occur, otherwise the
declaration is stale."""
import fnmatch
import json
import re
import sys

F2 = re.compile(r"^(-?\d+\.\d\d|NaN|[+-]Inf)$")
MHZ = re.compile(r"^\d+\.\d\dMHz$")
DEC = re.compile(r"^\d+$")
EXACT = "exact"


def classify(tp: str, name: str, keys, goos: str = ""):
    """Value class per key for one sysutil item, from its type and key set."""
    first = keys[0] if keys else ""
    if tp == "cpu" and first == "load1":
        return {k: F2 for k in keys}
    if tp == "cpu" and first == "user":
        return {k: F2 for k in keys}
    if tp == "cpu" and first == "cpu-arch":
        # Linux reports the live clock from /proc/cpuinfo, which moves with
        # frequency scaling between the Go capture and the Rust replay. Compare
        # its Go format and keep the cross-side ratio bounded (below) so a unit
        # or source mistake still fails; every other key stays byte-exact.
        # macOS keeps EXACT: Rust cannot read it there, which is a declared gap.
        if goos == "linux":
            return {k: (MHZ if k == "cpu-frequency" else EXACT) for k in keys}
        return {k: EXACT for k in keys}
    if tp == "memory" and name in ("virtual", "swap"):
        return {"total": EXACT, "used": DEC, "free": DEC, "used-percent": F2, "free-percent": F2}
    if tp == "memory" and name == "memory":
        return {"capacity": EXACT}
    if tp == "net" and first == "bytes-ent":
        return {k: DEC for k in keys}
    if tp == "net" and first == "read_count/s":
        return {k: F2 for k in keys}
    if tp == "net" and first == "mac":
        return {k: EXACT for k in keys}
    if tp == "disk":
        return {"fstype": EXACT, "opts": EXACT, "path": EXACT, "total": EXACT,
                "free": DEC, "used": DEC, "free-percent": F2, "used-percent": F2}
    if tp == "system":
        return {k: EXACT for k in keys}
    return None


class Declared:
    def __init__(self, entries):
        self.entries = entries
        self.used = [False] * len(entries)

    def find(self, kind, item=None, key=None):
        for index, entry in enumerate(self.entries):
            if entry["kind"] != kind:
                continue
            if item is not None and not fnmatch.fnmatchcase(item, entry.get("item", "")):
                continue
            if key is not None and entry.get("key") != key:
                continue
            self.used[index] = True
            return entry["owner"]
        return None

    def stale(self):
        return [entry for entry, used in zip(self.entries, self.used) if not used]


def compare_server_info(label, name, go_entry, rust_entry, declared, volatile, failures, notes, goos=""):
    identical = 0
    if go_entry["code"] != rust_entry["code"]:
        failures.append(f"{label}/{name}: code go={go_entry['code']} rust={rust_entry['code']}")
        return 0
    if name == "unknown":
        if go_entry["items"] or rust_entry["items"]:
            failures.append(f"{label}/{name}: an unknown type must answer no items")
            return 0
        return 1

    def index(items):
        table = {}
        for item in items:
            key = (item["tp"], item["name"], tuple(p["key"] for p in item["pairs"]))
            table.setdefault(key, []).append(item)
        return table

    go_items, rust_items = index(go_entry["items"]), index(rust_entry["items"])
    for key in sorted(set(go_items) | set(rust_items)):
        tp, item_name, keys = key
        item = f"{tp}/{item_name}"
        if key not in rust_items:
            owner = declared.find("missing", item=item)
            if owner:
                notes.append(f"{label}/{name}: {item} {list(keys)[:2]}... absent here [{owner}]")
            else:
                failures.append(f"{label}/{name}: Go item {item} with keys {list(keys)} is absent here")
            continue
        if key not in go_items:
            failures.append(f"{label}/{name}: item {item} with keys {list(keys)} has no Go counterpart")
            continue
        if len(go_items[key]) != len(rust_items[key]):
            failures.append(f"{label}/{name}: {item} appears go={len(go_items[key])} rust={len(rust_items[key])} times")
            continue
        classes = classify(tp, item_name, list(keys), goos)
        if classes is None:
            failures.append(f"{label}/{name}: {item} with keys {list(keys)} is not a known sysutil item")
            continue
        # Items sharing type, name and keys (bind mounts of one device) are
        # ordered arbitrarily by Go's unstable sort: pair them by value.
        by_values = lambda item: tuple(p["value"] for p in item["pairs"])
        for g, r in zip(sorted(go_items[key], key=by_values), sorted(rust_items[key], key=by_values)):
            g_pairs = {p["key"]: p["value"] for p in g["pairs"]}
            r_pairs = {p["key"]: p["value"] for p in r["pairs"]}
            if tp == "system" and item_name == "sysctl":
                g_keys = [p["key"] for p in g["pairs"]]
                r_keys = [p["key"] for p in r["pairs"]]
                if g_keys != r_keys:
                    only_go = [k for k in g_keys if k not in r_pairs][:5]
                    only_rust = [k for k in r_keys if k not in g_pairs][:5]
                    failures.append(f"{label}/{name}: sysctl keys differ (go={len(g_keys)} rust={len(r_keys)}; go-only {only_go}, rust-only {only_rust}, order/dups otherwise)")
                    continue
                differing = [k for k in g_keys if g_pairs[k] != r_pairs[k] and not any(v.match(k) for v in volatile)]
                if differing:
                    owner = declared.find("sysctl-values")
                    if owner:
                        notes.append(f"{label}/{name}: {len(differing)} of {len(g_keys)} sysctl values differ (e.g. {differing[:3]}) [{owner}]")
                    else:
                        failures.append(f"{label}/{name}: sysctl values differ for {differing[:8]}" + (f" (+{len(differing) - 8})" if len(differing) > 8 else ""))
                        continue
                identical += 1
                continue
            item_ok = True
            for k in keys:
                cls = classes.get(k)
                if cls is None:
                    failures.append(f"{label}/{name}: {item} key {k!r} is not in the sysutil catalog")
                    item_ok = False
                    continue
                gv, rv = g_pairs[k], r_pairs[k]
                if cls == EXACT:
                    if gv != rv:
                        owner = declared.find("value", item=item, key=k)
                        if owner:
                            notes.append(f"{label}/{name}: {item} {k} go={gv!r} rust={rv!r} [{owner}]")
                        else:
                            failures.append(f"{label}/{name}: {item} {k} go={gv!r} rust={rv!r}")
                            item_ok = False
                else:
                    for side_name, value in (("go", gv), ("rust", rv)):
                        if not cls.match(value):
                            failures.append(f"{label}/{name}: {item} {k} {side_name}={value!r} does not carry the Go format")
                            item_ok = False
                    if cls is MHZ and MHZ.match(gv) and MHZ.match(rv):
                        # Scaling moves this between captures; a unit or source
                        # mistake does not stay inside this band.
                        g_mhz, r_mhz = float(gv[:-3]), float(rv[:-3])
                        if not g_mhz or not 0.5 <= r_mhz / g_mhz <= 2.0:
                            failures.append(f"{label}/{name}: {item} {k} go={gv!r} rust={rv!r} are not the same clock")
                            item_ok = False
            if item_ok:
                identical += 1
    return identical


def main() -> int:
    script_path, go_path, rust_path = sys.argv[1:4]
    script = json.load(open(script_path))
    go = json.load(open(go_path))
    rust = json.load(open(rust_path))
    failures = []
    notes = []
    compared = 0
    goos = go.get("goos")
    if goos != rust.get("goos"):
        failures.append(f"goos: go={goos} rust={rust.get('goos')}")
    declared = Declared(script.get("server_info_declared", {}).get(goos, []))
    volatile = [re.compile(v) for v in script.get("server_info_volatile_sysctl", [])]
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
        if go_side["http1_grpc_status"] != rust_side["http1_grpc_status"]:
            failures.append(f"{side}.http1_grpc_status: go={go_side['http1_grpc_status']} rust={rust_side['http1_grpc_status']}")
        else:
            compared += 1
        for name in sorted(set(go_side["server_info"]) | set(rust_side["server_info"])):
            if name not in go_side["server_info"] or name not in rust_side["server_info"]:
                failures.append(f"{side}/server_info/{name}: missing on one side")
                continue
            compared += compare_server_info(f"{side}/server_info", name, go_side["server_info"][name],
                                            rust_side["server_info"][name], declared, volatile, failures, notes,
                                            goos)
    for entry in declared.stale():
        failures.append(f"declared divergence {entry['owner']!r} ({goos}) no longer occurs; remove the declaration")
    for line in notes:
        print(f"DECLARED {line}")
    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print(f"PASS: {compared} identical CP-DIAG observations across plaintext h2c and TLS on {goos}, {len(notes)} declared divergences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
