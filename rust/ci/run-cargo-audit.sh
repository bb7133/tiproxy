#!/usr/bin/env bash

set -euo pipefail

rust_dir=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}

# cargo-audit discovers the reviewed policy only at <workspace>/.cargo/audit.toml.
cd "$rust_dir"
cargo audit --file Cargo.lock
