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

use std::fmt;
use std::io;

use mysql_wire::{DecodeError, EncodeError};
use thiserror::Error;

/// Endpoint responsible for a packet transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoSide {
    /// The stream from which packet bytes are being consumed.
    Source,
    /// The stream to which packet bytes are being emitted.
    Destination,
}

impl fmt::Display for IoSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => formatter.write_str("source"),
            Self::Destination => formatter.write_str("destination"),
        }
    }
}

/// Failure while reading, writing, or forwarding `MySQL` packet frames.
#[derive(Debug, Error)]
pub enum PacketIoError {
    /// An endpoint failed during a specific I/O operation.
    #[error("{side} I/O failed while {operation}: {source}")]
    Io {
        /// Endpoint responsible for the failure.
        side: IoSide,
        /// Stable operation description.
        operation: &'static str,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// A physical header or wire field was malformed.
    #[error("invalid MySQL packet framing: {0}")]
    Decode(#[from] DecodeError),
    /// A physical header could not be represented on the wire.
    #[error("cannot encode MySQL packet framing: {0}")]
    Encode(#[from] EncodeError),
    /// A bounded materializing read observed a larger logical payload.
    #[error("logical payload has {observed} bytes, exceeding limit {limit}")]
    LogicalPayloadTooLarge {
        /// Maximum permitted materialized payload bytes.
        limit: usize,
        /// Exact payload bytes drained from the logical message.
        observed: u64,
    },
    /// An accounting counter overflowed.
    #[error("{field} counter overflow")]
    CounterOverflow {
        /// Counter that could not represent the next value.
        field: &'static str,
    },
    /// A completed forward-progress value was reused without resetting it.
    #[error("forward progress is already complete")]
    ForwardAlreadyComplete,
}

impl PacketIoError {
    pub(crate) fn io(side: IoSide, operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            side,
            operation,
            source,
        }
    }
}
