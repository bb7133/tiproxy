// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Drift gate for the checked external-dependency inventory.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const EXPECTED_DIRECT_PROTO_IMPORTS: &[&str] = &["github.com/pingcap/kvproto/pkg/diagnosticspb"];

#[test]
fn inventory_is_strict_and_direct_proto_surface_has_not_drifted() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| unreachable!("crate is nested under rust/crates"));
    let inventory_path = manifest_dir.join("external-inventory.v1.json");
    let inventory: Value = serde_json::from_slice(
        &fs::read(&inventory_path)
            .unwrap_or_else(|error| unreachable!("read {}: {error}", inventory_path.display())),
    )
    .unwrap_or_else(|error| unreachable!("decode inventory: {error}"));
    assert_eq!(inventory["schema_version"], 1);
    assert_eq!(inventory["implemented"].as_array().map_or(0, Vec::len), 3);
    assert_eq!(inventory["deferred"].as_array().map_or(0, Vec::len), 2);

    let mut imports = BTreeSet::new();
    for directory in ["cmd", "lib", "pkg"] {
        collect_direct_proto_imports(&root.join(directory), &mut imports);
    }
    assert_eq!(
        imports,
        EXPECTED_DIRECT_PROTO_IMPORTS
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    );
}

fn collect_direct_proto_imports(path: &Path, imports: &mut BTreeSet<String>) {
    let entries =
        fs::read_dir(path).unwrap_or_else(|error| unreachable!("read {}: {error}", path.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| unreachable!("read directory entry: {error}"));
        let path = entry.path();
        if path.is_dir() {
            collect_direct_proto_imports(&path, imports);
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("go")
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_test.go"))
        {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| unreachable!("read {}: {error}", path.display()));
        for line in source.lines() {
            for prefix in ["github.com/pingcap/kvproto/", "github.com/pingcap/tipb/"] {
                let Some(start) = line.find(prefix) else {
                    continue;
                };
                let suffix = &line[start..];
                let end = suffix.find('"').unwrap_or(suffix.len());
                imports.insert(suffix[..end].to_owned());
            }
        }
    }
}
