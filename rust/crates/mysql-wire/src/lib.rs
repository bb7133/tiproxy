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

//! `MySQL` wire-format boundaries for the `TiProxy` Rust dataplane.
//!
//! This crate will own packet types and codecs. It deliberately does not own
//! sockets, routing policy, or control-plane transport.

#![forbid(unsafe_code)]

/// Stable description used by workspace-level topology checks.
pub const CRATE_ROLE: &str = "mysql wire-format types and codecs";
