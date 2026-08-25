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

//! Versioned control-plane contracts between Go and Rust.
//!
//! This boundary carries control metadata only. `MySQL` packet payloads and
//! client/backend sockets must remain inside the Rust dataplane.

#![forbid(unsafe_code)]

mod codec;
pub mod control_transport;

/// Generated protobuf v1 types.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod v1 {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/generated/tiproxy.dataplane.v1.rs"
    ));
}

pub use codec::{DEFAULT_MAX_FRAME_BYTES, FrameError, decode_frame, encode_frame, negotiate_hello};

/// The first control-protocol version reserved by the production workspace.
pub const CONTROL_PROTOCOL_V1: u16 = 1;

/// Stable description used by workspace-level topology checks.
pub const CRATE_ROLE: &str = "versioned control-plane contracts";
