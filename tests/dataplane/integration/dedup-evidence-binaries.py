#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Deduplicate test-tool binaries inside a recorded qualification evidence tree.

The T4 qualification harness builds ``controldropper`` and ``faultproxy`` once per
physical cell (see run.sh), so a 48-cell artifact carried 96 tool files in total
(48 byte-identical copies of each, ~830 MB uncompressed) while every other
evidence file is under 1 MB. This is a packaging step only: it
runs after the matrix has been recorded and before the artifact is uploaded, and it
never changes how the harness builds or runs those tools.

For every file named in ``TOOL_NAMES`` below ``<root>/cells``:

* the first copy of each distinct content is moved to ``<root>/bins/<name>-<sha256>``,
* every copy is replaced in place by a ``<name>.sha256`` sidecar whose single line is
  ``<sha256>  bins/<name>-<sha256>`` (relative to ``<root>``), so
  ``cd <root> && sha256sum -c <cell>/<name>.sha256`` verifies the deduplicated file,
* ``<root>/bins-manifest.json`` records each binary's sha256, size and every path it
  replaced.

Nothing else is touched. The step is idempotent: a second run finds no tool files and
leaves the tree unchanged. ``--self-test`` exercises a deterministic positive case,
idempotency and a tamper-detection negative case without any product or network use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

TOOL_NAMES = ("controldropper", "faultproxy")
BINS_DIR = "bins"
MANIFEST = "bins-manifest.json"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dedup(root):
    root = os.path.abspath(root)
    cells = os.path.join(root, "cells")
    if not os.path.isdir(cells):
        raise SystemExit("no cells directory under %s" % root)
    bins = os.path.join(root, BINS_DIR)
    os.makedirs(bins, exist_ok=True)
    manifest_path = os.path.join(root, MANIFEST)
    manifest = {"schema": 1, "bins_dir": BINS_DIR, "binaries": {}}
    if os.path.exists(manifest_path):
        with open(manifest_path) as handle:
            manifest = json.load(handle)
    replaced = 0
    for dirpath, dirnames, filenames in os.walk(cells):
        dirnames.sort()
        for name in sorted(filenames):
            if name not in TOOL_NAMES:
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            digest = sha256_file(path)
            size = os.path.getsize(path)
            target_rel = "%s/%s-%s" % (BINS_DIR, name, digest)
            target = os.path.join(root, target_rel)
            if os.path.exists(target):
                if sha256_file(target) != digest:
                    raise SystemExit("existing %s does not match its name" % target_rel)
                os.remove(path)
            else:
                shutil.move(path, target)
            with open(path + ".sha256", "w") as handle:
                handle.write("%s  %s\n" % (digest, target_rel))
            entry = manifest["binaries"].setdefault(
                target_rel, {"name": name, "sha256": digest, "size": size, "replaced": []}
            )
            entry["replaced"].append(os.path.relpath(path, root))
            replaced += 1
    for entry in manifest["binaries"].values():
        entry["replaced"] = sorted(set(entry["replaced"]))
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return replaced, manifest


def verify(root):
    """Return the number of sidecars checked against the manifest's expected set.

    ``bins-manifest.json`` is the source of truth: every path it recorded as
    replaced must still carry a sidecar naming the right binary, each distinct
    binary is hashed once and must match its name, and no sidecar may exist that
    the manifest does not know about. A tree that was never deduplicated (no
    manifest and no sidecars) verifies trivially.
    """
    root = os.path.abspath(root)
    cells = os.path.join(root, "cells")
    present = set()
    for dirpath, _, filenames in os.walk(cells):
        for name in filenames:
            if name.endswith(".sha256") and name[: -len(".sha256")] in TOOL_NAMES:
                present.add(os.path.relpath(os.path.join(dirpath, name), root))
    manifest_path = os.path.join(root, MANIFEST)
    if not os.path.exists(manifest_path):
        if present:
            raise SystemExit("%d sidecars exist but %s is missing" % (len(present), MANIFEST))
        return 0
    with open(manifest_path) as handle:
        manifest = json.load(handle)
    expected = set()
    checked = 0
    for target_rel, entry in sorted(manifest["binaries"].items()):
        target = os.path.join(root, target_rel)
        if not os.path.isfile(target):
            raise SystemExit("manifest references missing %s" % target_rel)
        if sha256_file(target) != entry["sha256"] or not target_rel.endswith(entry["sha256"]):
            raise SystemExit("%s content does not match its manifest sha256" % target_rel)
        for replaced_rel in entry["replaced"]:
            sidecar_rel = replaced_rel + ".sha256"
            expected.add(sidecar_rel)
            sidecar = os.path.join(root, sidecar_rel)
            if not os.path.isfile(sidecar):
                raise SystemExit("missing sidecar %s recorded in %s" % (sidecar_rel, MANIFEST))
            with open(sidecar) as handle:
                line = handle.read().strip()
            if line != "%s  %s" % (entry["sha256"], target_rel):
                raise SystemExit("%s content does not match sidecar %s" % (target_rel, sidecar_rel))
            checked += 1
    unknown = present - expected
    if unknown:
        raise SystemExit("sidecars not recorded in %s: %s" % (MANIFEST, sorted(unknown)))
    return checked


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "evidence")
        cell_a = os.path.join(root, "cells", "M1-P-plain", "tiproxy-dp-rust-plain-1")
        cell_b = os.path.join(root, "cells", "M1-T-tls", "tiproxy-dp-rust-tls-2")
        diag_a = os.path.join(cell_a, "diagnostics", "run")
        for directory in (cell_a, cell_b, diag_a):
            os.makedirs(directory)
        blob_dropper = b"\x7fELF dropper " * 1000
        blob_fault = b"\x7fELF faultproxy " * 1000
        for directory in (cell_a, cell_b, diag_a):
            with open(os.path.join(directory, "controldropper"), "wb") as handle:
                handle.write(blob_dropper)
            with open(os.path.join(directory, "faultproxy"), "wb") as handle:
                handle.write(blob_fault)
        decoy = os.path.join(cell_a, "t4-route-audit-final.json")
        with open(decoy, "w") as handle:
            handle.write('{"decoy": true}\n')
        decoy_sha = sha256_file(decoy)

        replaced, manifest = dedup(root)
        assert replaced == 6, replaced
        assert sorted(os.listdir(os.path.join(root, BINS_DIR))) == [
            "controldropper-" + hashlib.sha256(blob_dropper).hexdigest(),
            "faultproxy-" + hashlib.sha256(blob_fault).hexdigest(),
        ]
        assert len(manifest["binaries"]) == 2
        assert all(len(v["replaced"]) == 3 for v in manifest["binaries"].values())
        for directory in (cell_a, cell_b, diag_a):
            for name in TOOL_NAMES:
                assert not os.path.exists(os.path.join(directory, name))
                assert os.path.isfile(os.path.join(directory, name + ".sha256"))
        assert sha256_file(decoy) == decoy_sha, "unrelated evidence must be untouched"
        assert verify(root) == 6
        # the sidecars are plain sha256sum -c lines relative to the evidence root
        checker = ["sha256sum", "-c", "--quiet"] if shutil.which("sha256sum") else ["shasum", "-a", "256", "-c", "-s"]
        subprocess.run(
            checker + [os.path.relpath(os.path.join(cell_b, "faultproxy.sha256"), root)],
            cwd=root,
            check=True,
        )
        # idempotent: a second pass finds nothing and leaves the manifest unchanged
        with open(os.path.join(root, MANIFEST)) as handle:
            before = handle.read()
        assert dedup(root)[0] == 0
        with open(os.path.join(root, MANIFEST)) as handle:
            assert handle.read() == before
        # negative: a sidecar the manifest still records must not silently vanish
        removed = os.path.join(cell_b, "controldropper.sha256")
        os.remove(removed)
        try:
            verify(root)
        except SystemExit as exc:
            assert "missing sidecar" in str(exc), exc
        else:
            raise AssertionError("missing sidecar was not detected")
        with open(removed, "w") as handle:
            handle.write("%s  %s/controldropper-%s\n" % (hashlib.sha256(blob_dropper).hexdigest(), BINS_DIR, hashlib.sha256(blob_dropper).hexdigest()))
        assert verify(root) == 6
        # negative: a tampered deduplicated binary must fail verification
        tampered = os.path.join(root, BINS_DIR, sorted(os.listdir(os.path.join(root, BINS_DIR)))[0])
        with open(tampered, "ab") as handle:
            handle.write(b"x")
        try:
            verify(root)
        except SystemExit as exc:
            assert "does not match its manifest sha256" in str(exc), exc
        else:
            raise AssertionError("tampered binary was not detected")
    print("dedup-evidence-binaries self-test: PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", help="qualification evidence root (contains cells/)")
    parser.add_argument("--verify", action="store_true", help="only verify existing sidecars")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.root:
        parser.error("root is required unless --self-test")
    if args.verify:
        print("verified %d deduplicated binary sidecars" % verify(args.root))
        return 0
    replaced, manifest = dedup(args.root)
    print(
        "deduplicated %d tool binaries into %d distinct files under %s/"
        % (replaced, len(manifest["binaries"]), BINS_DIR)
    )
    print("verified %d sidecars" % verify(args.root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
