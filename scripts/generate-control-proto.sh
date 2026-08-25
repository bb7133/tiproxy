#!/usr/bin/env bash

# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tool_dir="$repo_root/bin/control-codegen"

buf_version=v1.72.0
protoc_gen_go_version=v1.36.11
protoc_gen_prost_version=0.5.0

mkdir -p "$tool_dir"

if [[ ! -x "$tool_dir/buf" ]] || [[ $("$tool_dir/buf" --version) != "${buf_version#v}" ]]; then
    GOBIN="$tool_dir" GOTOOLCHAIN=go1.25.12 \
        go install "github.com/bufbuild/buf/cmd/buf@$buf_version"
fi

if [[ ! -x "$tool_dir/protoc-gen-go" ]] || \
    [[ $("$tool_dir/protoc-gen-go" --version) != "protoc-gen-go ${protoc_gen_go_version#v}" ]]; then
    GOBIN="$tool_dir" GOTOOLCHAIN=go1.25.12 \
        go install "google.golang.org/protobuf/cmd/protoc-gen-go@$protoc_gen_go_version"
fi

if [[ ! -x "$tool_dir/protoc-gen-prost" ]] || \
    ! "$tool_dir/protoc-gen-prost" --version 2>&1 | grep -Fq "$protoc_gen_prost_version"; then
    CARGO_INSTALL_ROOT="$repo_root/bin/control-codegen-rust" \
        cargo install protoc-gen-prost --version "$protoc_gen_prost_version" --locked
    cp "$repo_root/bin/control-codegen-rust/bin/protoc-gen-prost" "$tool_dir/protoc-gen-prost"
fi

cd "$repo_root"
"$tool_dir/buf" lint
"$tool_dir/buf" generate
gofmt -w pkg/controlbridge/pb/control.pb.go
rust_generated=rust/crates/control-proto/src/generated/tiproxy.dataplane.v1.rs
if ! grep -Fq "Copyright 2026 PingCAP" "$rust_generated"; then
    generated_tmp=$(mktemp "${TMPDIR:-/tmp}/tiproxy-control-proto.XXXXXX")
    {
        echo '// Copyright 2026 PingCAP, Inc.'
        echo '// SPDX-License-Identifier: Apache-2.0'
        echo
        sed -n '1,$p' "$rust_generated"
    } >"$generated_tmp"
    mv "$generated_tmp" "$rust_generated"
fi
GOTOOLCHAIN=go1.25.12 go run ./pkg/controlbridge/pb/cmd/golden
cargo run --locked --manifest-path rust/Cargo.toml --package control-proto --example write_golden
