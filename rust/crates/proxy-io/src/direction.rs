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

//! Per-direction sequence coordination for a layered transport.
//!
//! The `MySQL` compressed protocol keeps a compressed sequence separate from
//! the uncompressed packet sequence and — following Go's `compressedReadWriter`
//! `BeginRW` — slaves the uncompressed sequence to the compressed one on each
//! direction change, and resets the compressed sequence once per command. A
//! `PacketIo` calls these hooks at its own read/write/forward entry points
//! (the single centralized seam), so the reset points and the real direction
//! flips are guaranteed to line up even for multi-frame requests and `forward_*`
//! streaming, which do not map one-to-one to the uncompressed reset sites.
//!
//! A plaintext or TLS transport carries no separate sequence, so every method
//! here defaults to a no-op; only a compression layer overrides them.

use std::io;

/// Direction-change coordination between a layered transport and the packet
/// sequence above it. All methods default to a no-op.
pub trait DirectionSync {
    /// Called before a read-direction operation. Returns `Some(seq)` when the
    /// packet layer must adopt `seq` as its read sequence (a layered direction
    /// change, e.g. compression); `None` leaves the packet sequence unchanged.
    /// Repeated calls in the same direction return `None`, so a `peek` followed
    /// by a `read` never shifts the sequence twice.
    ///
    /// # Errors
    ///
    /// Fails closed when the transition would strand buffered data.
    fn begin_read(&mut self) -> io::Result<Option<u8>> {
        Ok(None)
    }

    /// As [`Self::begin_read`], for a write-direction operation.
    ///
    /// # Errors
    ///
    /// Fails closed when the transition would strand buffered data.
    fn begin_write(&mut self) -> io::Result<Option<u8>> {
        Ok(None)
    }

    /// Resets the layered sequence at a clean command boundary. Called once per
    /// new command/exchange by the session owner — never bound to a per-reader
    /// or per-writer sequence reset, and never while a frame is in flight.
    ///
    /// # Errors
    ///
    /// A compression layer fails closed if a frame is still buffered (a partial
    /// header/body, unread decoded bytes, or pending output), so the reset can
    /// never silently rewind the shared sequence over live command bytes.
    fn reset_layer_sequence(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A byte cursor carries no layered sequence; the test transports built on it
/// coordinate nothing.
impl<T> DirectionSync for io::Cursor<T> {}
