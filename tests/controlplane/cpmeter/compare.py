#!/usr/bin/env python3
"""Compare production consumer/outbox results and bidirectional state handoff."""
import argparse
import copy
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(binary, directory, events, output):
    request = output.with_suffix(".input.json")
    request.write_text(json.dumps(events))
    with output.open("w") as stream:
        subprocess.run([str(binary), str(directory), str(request)], stdout=stream, check=True)
    return json.loads(output.read_text())


def compare(expected, actual):
    if expected != actual:
        for index, (left, right) in enumerate(zip(expected, actual)):
            if left != right:
                raise AssertionError(f"first divergent event {index}:\nGo={left}\nRust={right}")
        raise AssertionError("observation count mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    events = json.loads(Path(__file__).with_name("events.json").read_text())
    with tempfile.TemporaryDirectory(prefix="tiproxy-cpmeter-") as temporary:
        root = Path(temporary)
        seed = root / "seed"
        run(args.go, seed, [], args.output / "seed.json")
        for name in ("go", "rust", "handoff", "rollback"):
            shutil.copytree(seed, root / name)
        baseline = run(args.go, root / "go", events, args.output / "go.json")
        candidate = run(args.rust, root / "rust", events, args.output / "rust.json")
        compare(baseline, candidate)
        for name, first, second in (("handoff", args.go, args.rust), ("rollback", args.rust, args.go)):
            cut = 7
            before = run(first, root / name, events[:cut], args.output / f"{name}-before.json")
            after = run(second, root / name, events[cut:], args.output / f"{name}-after.json")
            compare(baseline, before + after)
        # Simulate a crash after sealing the real Go aggregate, before upload.
        # Both owners resume the exact same immutable pending-window fixture.
        for name in ("export-go", "export-rust"):
            shutil.copytree(root / "go", root / name)
            state_file = root / name / "run/metering-outbox.json"
            state = json.loads(state_file.read_text())
            state["pending"] = {"timestamp": 60, "data": state["data"]}
            state["data"] = []
            state_file.write_text(json.dumps(state))
        go_export = run(args.go, root / "export-go", [{"export": True}], args.output / "go-export.json")
        rust_export = run(args.rust, root / "export-rust", [{"export": True}], args.output / "rust-export.json")
        compare(go_export, rust_export)
        def objects(name):
            directory = root / name / "objects"
            result = {}
            for path in directory.rglob("*.json.gz"):
                value = json.loads(gzip.decompress(path.read_bytes()))
                value["data"].sort(key=lambda record: record["cluster_id"])
                result[str(path.relative_to(directory))] = value
            assert result, "export produced no objects"
            return result
        go_objects, rust_objects = objects("export-go"), objects("export-rust")
        compare(go_objects, rust_objects)
        (args.output / "go-objects.json").write_text(json.dumps(go_objects, indent=2))
        (args.output / "rust-objects.json").write_text(json.dumps(rust_objects, indent=2))
        wrap_events = json.loads(Path(__file__).with_name("events-wrap.json").read_text())
        for name in ("wrap-go", "wrap-rust"):
            shutil.copytree(seed, root / name)
        wrap_go = run(args.go, root / "wrap-go", wrap_events, args.output / "go-wrap.json")
        wrap_rust = run(args.rust, root / "wrap-rust", wrap_events, args.output / "rust-wrap.json")
        compare(wrap_go, wrap_rust)
        mutated = copy.deepcopy(candidate)
        mutated[-1]["outbox"]["data"][0]["cross_az_bytes"] += 1
        try:
            compare(baseline, mutated)
        except AssertionError:
            pass
        else:
            raise AssertionError("lost-byte mutation survived")
    print(f"PASS: {len(events)} Go/Rust observations, Go→Rust handoff, Rust→Go rollback, byte mutation rejected; Go SDK/native gzip object parity; 6 wrap/overflow/restart observations")


if __name__ == "__main__":
    main()
