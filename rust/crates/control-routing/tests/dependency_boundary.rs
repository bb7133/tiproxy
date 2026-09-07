// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Dependency-boundary inventory for the protocol-independent route domain.

use std::fs;
use std::io;
use std::path::Path;

fn assert_directory_has_no_protocol_dependency(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            assert_directory_has_no_protocol_dependency(&path)?;
        } else {
            let contents = fs::read_to_string(&path)?;
            let forbidden = concat!("control", "-proto");
            let forbidden_identifier = concat!("control", "_proto");
            assert!(
                !contents.contains(forbidden) && !contents.contains(forbidden_identifier),
                "{} leaks the legacy protocol dependency",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn public_domain_has_no_legacy_protocol_dependency() -> io::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    assert!(!manifest.contains(concat!("control", "-proto")));
    assert_directory_has_no_protocol_dependency(&root.join("src"))
}
