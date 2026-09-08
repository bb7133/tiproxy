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

//! Temporary read-only routing observation framing. No production socket is wired.
//!
//! This adapter owns serialization; the control-router domain accepts only values.
//! The bounded inbox is a consumer-side primitive, not the Go hot-path recorder.
//! Lifecycle comparison alone never qualifies a complete routing shadow interval.

/// Optional same-process local-socket consumer with explicit cancellation/join.
pub mod consumer;
/// Strict v2 actual-capture codec, independent of the immutable v1 corpus.
pub mod live;
mod wire;
use control_router::shadow::Observation;
use std::collections::VecDeque;

/// Maximum JSON payload length, checked before decoding or allocating a frame.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Maximum simultaneously queued observation records.
pub const MAX_QUEUED_RECORDS: usize = 4096;
/// Maximum queued encoded bytes, including each four-byte prefix.
pub const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;

/// Bounded diagnostic error without copying an arbitrary input payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Missing prefix, truncated body or trailing bytes outside the frame.
    Framing,
    /// The advertised payload exceeds the hard frame limit.
    Oversized,
    /// Malformed/duplicate/unknown JSON fields or noncanonical scalar values.
    Schema,
    /// Unsupported observation schema version.
    Version,
    /// The record or queued-byte budget is exhausted; no record was inserted.
    Capacity,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shadow observation {self:?}")
    }
}
impl std::error::Error for Error {}

/// Decode exactly one frame. The caller must invalidate the interval on error;
/// continuing with the next frame would silently conceal an observation gap.
///
/// # Errors
/// Rejects oversized, truncated, malformed, unknown-version or noncanonical records.
pub fn decode(frame: &[u8]) -> Result<Observation, Error> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(Error::Framing)?
        .try_into()
        .map_err(|_| Error::Framing)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Oversized)?;
    if length > MAX_FRAME_BYTES {
        return Err(Error::Oversized);
    }
    if length == 0 || frame.len() != length + 4 {
        return Err(Error::Framing);
    }
    wire::decode(&frame[4..])
}

/// Encode a domain value outside all production router/group locks.
///
/// # Errors
/// Returns an encoding or frame-size error without creating a partial frame.
pub fn encode(observation: &Observation) -> Result<Vec<u8>, Error> {
    let body = wire::encode(observation)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(Error::Oversized);
    }
    let length = u32::try_from(body.len()).map_err(|_| Error::Oversized)?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Consumer inbox, bounded in records and encoded byte charge.
///
/// Decoded events contain only fixed-size values. Charging the larger complete
/// wire frame is conservative. Queue errors never evict or overwrite earlier
/// records; the composition must mark the associated observation epoch invalid.
#[derive(Default)]
pub struct Inbox {
    queue: VecDeque<(Observation, usize)>,
    bytes: usize,
}
impl Inbox {
    /// Check both independent budgets before appending a decoded observation.
    ///
    /// # Errors
    /// Returns capacity or decoding errors without evicting any queued record.
    pub fn push(&mut self, frame: &[u8]) -> Result<(), Error> {
        if self.queue.len() >= MAX_QUEUED_RECORDS {
            return Err(Error::Capacity);
        }
        let bytes = self.bytes.checked_add(frame.len()).ok_or(Error::Capacity)?;
        if bytes > MAX_QUEUED_BYTES {
            return Err(Error::Capacity);
        }
        let observation = decode(frame)?;
        self.queue.push_back((observation, frame.len()));
        self.bytes = bytes;
        Ok(())
    }

    /// Remove the oldest complete record and release its exact byte charge.
    pub fn pop(&mut self) -> Option<Observation> {
        let (observation, size) = self.queue.pop_front()?;
        self.bytes -= size;
        Some(observation)
    }

    /// Current conservative encoded-byte charge.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.bytes
    }

    /// Number of complete records waiting to be compared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether any records remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod live_tests;
