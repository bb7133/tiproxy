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

//! Composition root for the `TiProxy` Rust dataplane.
//!
//! No protocol behavior is implemented in the foundation workspace. Keeping
//! this crate as the only composition layer preserves the library boundaries
//! while later parity work lands independently.

#![forbid(unsafe_code)]

/// Names and stable roles of the library crates composed by the dataplane.
#[must_use]
pub const fn component_roles() -> [(&'static str, &'static str); 4] {
    [
        ("control-proto", control_proto::CRATE_ROLE),
        ("mysql-wire", mysql_wire::CRATE_ROLE),
        ("proxy-io", proxy_io::CRATE_ROLE),
        ("session-core", session_core::CRATE_ROLE),
    ]
}

#[cfg(test)]
mod tests {
    use super::component_roles;

    #[test]
    fn workspace_has_all_component_boundaries() {
        assert_eq!(component_roles().len(), 4);
    }
}
