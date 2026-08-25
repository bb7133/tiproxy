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

//! Bounded transport I/O for the `TiProxy` Rust dataplane.
//!
//! This crate owns client and backend byte streams and adapts the sans-I/O
//! framing rules from `mysql-wire` to asynchronous transports. Packet forwarding
//! keeps source and destination sequences independent, retains only an explicit
//! prefix, and uses fixed scratch space for arbitrarily large logical messages.
//! It does not make routing decisions.

#![forbid(unsafe_code)]

mod error;
mod packet;

pub use error::{IoSide, PacketIoError};
pub use packet::{
    DEFAULT_STREAM_BUFFER_SIZE, ForwardProgress, ForwardStatus, ForwardUntilDecision,
    ForwardUntilResult, ForwardUntilStatus, LogicalPacket, PacketPreview, PacketReader,
    PacketWriter,
};

/// Stable description used by workspace-level topology checks.
pub const CRATE_ROLE: &str = "client and backend transport ownership";
