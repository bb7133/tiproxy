#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <binary> <version> <commit> <build-time>" >&2
    exit 2
fi

binary=$1
expected="tiproxy-rs $2 (commit $3, built $4)"
actual=$($binary --version)

if [[ "$actual" != "$expected" ]]; then
    echo "unexpected version output" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
fi

echo "$actual"
