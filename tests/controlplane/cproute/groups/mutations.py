#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Mutate copied production Rust; require successful execution and disagreement."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    repo = Path(__file__).resolve().parents[4]
    baseline = Path(sys.argv[1]).read_bytes()
    crate = repo / "rust/crates/control-routing"
    workspace = (repo / "rust/Cargo.toml").read_text()
    package = workspace.split("[workspace.package]", 1)[1].split("[workspace.dependencies]", 1)[0]
    lints = workspace[workspace.index("[workspace.lints.rust]"):]
    # This zero-dependency crate can run in an isolated workspace without
    # copying/mutating the repository or rebuilding unrelated domain crates.
    with tempfile.TemporaryDirectory(prefix="cproute-group-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(crate, root / "control-routing")
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["control-routing"]\nresolver = "3"\n'
            + '[workspace.package]' + package + lints
        )
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
        subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", str(root / "Cargo.toml")], check=True, env=environment)
        source = root / "control-routing/src/group.rs"
        original = source.read_text()
        command = ["cargo", "run", "--locked", "--offline", "--quiet", "--manifest-path", str(root / "Cargo.toml"),
                   "-p", "control-routing", "--example", "group_observer", "--", str(Path(__file__).parent)]

        def observe():
            # A compile failure/crash is a failed gate, never a killed mutation.
            return subprocess.run(command, check=True, stdout=subprocess.PIPE, env=environment).stdout

        if observe() != baseline:
            raise RuntimeError("isolated baseline differs from production Go")
        mutations = [
            ("proxy-address-fallback", "MatchType::ProxyCidr => client.proxy_address,", "MatchType::ProxyCidr => client.proxy_address.or(client.client_address),"),
            ("normalize-raw-values", "values.contains(value)", "values.iter().any(|other| other.trim() == value.trim())"),
            ("default-ipv6-prefix-128", 'let prefix = prefix.parse::<u32>().ok()?;', 'let prefix = prefix.parse::<u32>().ok()?; let prefix = if !value.contains(\'/\') && host.contains(\':\') { 128 } else { prefix };'),
            ("cross-cluster-port-last-wins", "owner == cluster", "owner == cluster || !cluster.is_empty()"),
            ("port-conflict-self-heals", "Some(PortBinding::Conflict) => {}", "Some(binding @ PortBinding::Conflict) => { *binding = PortBinding::Bound { cluster: cluster.to_owned(), group }; }"),
            ("mapped-client-not-canonicalized", "ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)", "IpAddr::V6(ip)"),
        ]
        for name, before, after in mutations:
            if before not in original:
                raise RuntimeError(f"mutation anchor absent: {name}")
            source.write_text(original.replace(before, after))
            if observe() == baseline:
                raise RuntimeError(f"production mutation survived: {name}")
            print(f"CP-ROUTE group mutation killed: {name}", flush=True)
        source.write_text(original)
        if observe() != baseline:
            raise RuntimeError("restored baseline differs from production Go")


if __name__ == "__main__":
    main()
