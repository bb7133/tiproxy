#!/usr/bin/env python3
"""Compare production consumer/outbox results and bidirectional state handoff."""
import argparse
import copy
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
        mutated = copy.deepcopy(candidate)
        mutated[-1]["outbox"]["data"][0]["cross_az_bytes"] += 1
        try:
            compare(baseline, mutated)
        except AssertionError:
            pass
        else:
            raise AssertionError("lost-byte mutation survived")
    print(f"PASS: {len(events)} Go/Rust observations, Go→Rust handoff, Rust→Go rollback, byte mutation rejected")


if __name__ == "__main__":
    main()
