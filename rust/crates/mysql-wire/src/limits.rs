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

//! Central registry of external-input limits (WIRE-07).
//!
//! Every limit that bounds bytes arriving from a client, a backend, or the
//! control stream is defined here with its source of truth, so no parser
//! invents a bound and no hostile declaration is trusted before it is
//! checked. The transport-owned defaults that already live in `proxy-io`
//! (stream buffers, write high-water, dial budgets, compression bounds) are
//! cross-referenced by conformance tests there rather than moved, keeping
//! this module dependency-free.
//!
//! Usage pattern: call [`check_declared_length`] (or a specific helper)
//! **before** allocating for any length a peer declared. The helpers never
//! allocate and their errors never echo input bytes — only the field name,
//! the declared value, and the limit.
//!
//! Delegated transport-owned bounds (anchored by `proxy-io`'s conformance
//! tests so values cannot drift silently):
//! - stream/pump buffers 32 KiB; write high-water 64 KiB
//! - pump flush delay 1 ms, write/flush timeout 30 s, shutdown timeout 1 s
//! - dial budgets 1 s per attempt / 15 s total
//! - compressed frame ≤ the u24 maximum, default expansion ratio 65536
//! - control frame default/hard cap 1 MiB
//!   (`control-proto::codec::DEFAULT_MAX_FRAME_BYTES`)

use core::fmt;

/// Go `authenticator.go maxHandshakePacketSize`: largest logical packet
/// accepted before authentication completes.
pub const MAX_PRE_HANDSHAKE_PACKET_LEN: usize = 1 << 20;

/// Go `backend_conn_mgr.go ExecuteCmd` capture limit: bytes of a streamed
/// command retained for command-state decisions.
pub const COMMAND_PREFIX_CAPTURE_LEN: usize = 1024;

/// Control-protocol ADR v1 hard frame limit (body bytes, prefix excluded).
pub const MAX_CONTROL_FRAME_LEN: usize = 1 << 20;

/// Control-protocol ADR: total decoded connection-attribute bytes.
pub const MAX_CONNECTION_ATTRIBUTES_TOTAL: usize = 64 * 1024;

/// Control-protocol ADR: maximum decoded connection-attribute entries.
pub const MAX_CONNECTION_ATTRIBUTE_ENTRIES: usize = 1024;

/// Control-protocol ADR: maximum bytes for one attribute key or value.
pub const MAX_CONNECTION_ATTRIBUTE_KV: usize = 4 * 1024;

/// Control-protocol ADR: diagnostic detail text cap.
pub const MAX_DIAGNOSTIC_TEXT_LEN: usize = 4 * 1024;

/// The 24-bit physical-packet payload maximum (single source: this crate).
pub const MAX_PHYSICAL_PAYLOAD_LEN: usize = crate::MAX_PAYLOAD_LEN as usize;

/// Identity fields (username, database, auth-plugin name) carry **no
/// dedicated Go limit**: they are bounded only by the enclosing
/// pre-handshake packet cap. Registered as an explicit alias so the absence
/// of a per-field bound is a recorded decision with boundary coverage, not
/// an omission.
pub const MAX_IDENTITY_FIELD_LEN: usize = MAX_PRE_HANDSHAKE_PACKET_LEN;

/// LOCAL INFILE aggregate upload size: **unbounded in Go today** — only the
/// per-packet 24-bit framing applies, and the stream ends at the client's
/// empty packet. `None` here records the current Go-parity state, not an
/// accepted terminal posture: the session/runtime implementation (RSP-005
/// owners) must stream LOCAL INFILE with bounded per-fragment memory and
/// revisit an aggregate bound there. Do not read this constant as
/// permission to materialize an upload.
pub const LOCAL_INFILE_AGGREGATE_LIMIT: Option<usize> = None;

/// A declared length exceeded its registered limit.
///
/// The error carries only the stable field name and the two lengths: input
/// bytes, file paths, and secrets never appear in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitExceeded {
    /// Stable name of the limited field.
    pub field: &'static str,
    /// The length the peer declared or supplied.
    pub declared: usize,
    /// The registered limit.
    pub limit: usize,
}

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} length {} exceeds limit {}",
            self.field, self.declared, self.limit
        )
    }
}

impl core::error::Error for LimitExceeded {}

/// Checks a declared length against a limit before any allocation.
///
/// # Errors
///
/// Returns [`LimitExceeded`] when `declared > limit`.
pub const fn check_declared_length(
    field: &'static str,
    declared: usize,
    limit: usize,
) -> Result<(), LimitExceeded> {
    if declared > limit {
        return Err(LimitExceeded {
            field,
            declared,
            limit,
        });
    }
    Ok(())
}

/// Pre-handshake logical-packet length check (Go 1-MiB cap).
///
/// # Errors
///
/// Returns [`LimitExceeded`] above [`MAX_PRE_HANDSHAKE_PACKET_LEN`].
pub const fn check_pre_handshake_packet(declared: usize) -> Result<(), LimitExceeded> {
    check_declared_length(
        "pre-handshake packet",
        declared,
        MAX_PRE_HANDSHAKE_PACKET_LEN,
    )
}

/// Control-frame body length check (ADR 1-MiB hard limit, or a smaller
/// negotiated limit).
///
/// `negotiated_limit == 0` means "no negotiated limit" and falls back to the
/// hard cap, matching `control-proto::codec`'s `normalized_limit` semantics.
///
/// # Errors
///
/// Returns [`LimitExceeded`] above the effective limit.
pub const fn check_control_frame(
    declared: usize,
    negotiated_limit: usize,
) -> Result<(), LimitExceeded> {
    let limit = if negotiated_limit == 0 || negotiated_limit > MAX_CONTROL_FRAME_LEN {
        MAX_CONTROL_FRAME_LEN
    } else {
        negotiated_limit
    };
    check_declared_length("control frame", declared, limit)
}

/// Clamps a command-prefix capture length to the registered bound.
///
/// This is a truncation bound, not a rejection: matching Go's
/// `ForwardPacketTo(backendIO, 1024)`, at most
/// [`COMMAND_PREFIX_CAPTURE_LEN`] bytes of a streamed command are retained.
#[must_use]
pub const fn clamp_command_prefix(declared: usize) -> usize {
    if declared > COMMAND_PREFIX_CAPTURE_LEN {
        COMMAND_PREFIX_CAPTURE_LEN
    } else {
        declared
    }
}

/// Connection-attribute bounds check (ADR totals, entries, per-entry sizes).
///
/// `entries` supplies decoded `(key_len, value_len)` pairs; the helper sums
/// with saturation so a hostile declaration cannot overflow the accounting.
///
/// # Errors
///
/// Returns [`LimitExceeded`] naming the first violated bound.
pub fn check_connection_attributes<I>(entries: I) -> Result<(), LimitExceeded>
where
    I: IntoIterator<Item = (usize, usize)>,
{
    let mut total: usize = 0;
    let mut count: usize = 0;
    for (key_len, value_len) in entries {
        count += 1;
        if count > MAX_CONNECTION_ATTRIBUTE_ENTRIES {
            return Err(LimitExceeded {
                field: "connection-attribute entries",
                declared: count,
                limit: MAX_CONNECTION_ATTRIBUTE_ENTRIES,
            });
        }
        check_declared_length(
            "connection-attribute key",
            key_len,
            MAX_CONNECTION_ATTRIBUTE_KV,
        )?;
        check_declared_length(
            "connection-attribute value",
            value_len,
            MAX_CONNECTION_ATTRIBUTE_KV,
        )?;
        total = total.saturating_add(key_len).saturating_add(value_len);
        check_declared_length(
            "connection-attribute total",
            total,
            MAX_CONNECTION_ATTRIBUTES_TOTAL,
        )?;
    }
    Ok(())
}

/// Truncates diagnostic text to the ADR cap on a character boundary.
///
/// Use for outbound error detail so oversized peer-derived text can never
/// expand a control frame or a log line beyond the registered bound.
#[must_use]
pub fn clamp_diagnostic_text(text: &str) -> &str {
    if text.len() <= MAX_DIAGNOSTIC_TEXT_LEN {
        return text;
    }
    let mut end = MAX_DIAGNOSTIC_TEXT_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_limit_has_boundary_coverage() {
        // limit-1 / limit / limit+1 for the pre-handshake cap.
        assert!(check_pre_handshake_packet(MAX_PRE_HANDSHAKE_PACKET_LEN - 1).is_ok());
        assert!(check_pre_handshake_packet(MAX_PRE_HANDSHAKE_PACKET_LEN).is_ok());
        assert!(check_pre_handshake_packet(MAX_PRE_HANDSHAKE_PACKET_LEN + 1).is_err());

        assert!(check_control_frame(MAX_CONTROL_FRAME_LEN - 1, usize::MAX).is_ok());
        assert!(check_control_frame(MAX_CONTROL_FRAME_LEN, usize::MAX).is_ok());
        assert!(check_control_frame(MAX_CONTROL_FRAME_LEN + 1, usize::MAX).is_err());
        // A smaller negotiated limit wins.
        assert!(check_control_frame(511, 512).is_ok());
        assert!(check_control_frame(512, 512).is_ok());
        assert!(check_control_frame(513, 512).is_err());
        // Zero means "no negotiated limit" and falls back to the hard cap,
        // matching control-proto's normalized_limit — not a zero-size limit.
        assert!(check_control_frame(MAX_CONTROL_FRAME_LEN, 0).is_ok());
        assert!(check_control_frame(MAX_CONTROL_FRAME_LEN + 1, 0).is_err());

        // Command-prefix capture is a truncation bound with full boundary
        // coverage: below stays, at stays, above clamps.
        assert_eq!(
            clamp_command_prefix(COMMAND_PREFIX_CAPTURE_LEN - 1),
            COMMAND_PREFIX_CAPTURE_LEN - 1
        );
        assert_eq!(
            clamp_command_prefix(COMMAND_PREFIX_CAPTURE_LEN),
            COMMAND_PREFIX_CAPTURE_LEN
        );
        assert_eq!(
            clamp_command_prefix(COMMAND_PREFIX_CAPTURE_LEN + 1),
            COMMAND_PREFIX_CAPTURE_LEN
        );

        // Identity fields are bounded only by the pre-handshake cap (alias).
        assert_eq!(MAX_IDENTITY_FIELD_LEN, MAX_PRE_HANDSHAKE_PACKET_LEN);
        assert!(
            check_declared_length(
                "username",
                MAX_IDENTITY_FIELD_LEN - 1,
                MAX_IDENTITY_FIELD_LEN
            )
            .is_ok()
        );
        assert!(
            check_declared_length("username", MAX_IDENTITY_FIELD_LEN, MAX_IDENTITY_FIELD_LEN)
                .is_ok()
        );
        assert!(
            check_declared_length(
                "username",
                MAX_IDENTITY_FIELD_LEN + 1,
                MAX_IDENTITY_FIELD_LEN
            )
            .is_err()
        );

        // Attribute entry-count bound at -1 as well as = and +1 (below).
        let under_entries = (0..MAX_CONNECTION_ATTRIBUTE_ENTRIES - 1).map(|_| (1_usize, 1_usize));
        assert!(check_connection_attributes(under_entries).is_ok());

        // Attribute per-entry bound.
        let kv = MAX_CONNECTION_ATTRIBUTE_KV;
        assert!(check_connection_attributes([(kv - 1, 0)]).is_ok());
        assert!(check_connection_attributes([(kv, 0)]).is_ok());
        assert!(check_connection_attributes([(kv + 1, 0)]).is_err());

        // Attribute total bound at -1 / exact / +1: eight maximum-size
        // entries land exactly on the 64-KiB total.
        let total = MAX_CONNECTION_ATTRIBUTES_TOTAL;
        let full_entries = total / (2 * kv);
        let one_short = (0..full_entries - 1)
            .map(|_| (kv, kv))
            .chain([(kv, kv - 1)]);
        assert!(check_connection_attributes(one_short).is_ok());
        let exact = (0..full_entries).map(|_| (kv, kv));
        assert!(check_connection_attributes(exact.clone()).is_ok());
        assert!(check_connection_attributes(exact.chain([(1, 0)])).is_err());

        // Attribute entry-count bound.
        let ok_entries = (0..MAX_CONNECTION_ATTRIBUTE_ENTRIES).map(|_| (1_usize, 1_usize));
        assert!(check_connection_attributes(ok_entries).is_ok());
        let over_entries = (0..=MAX_CONNECTION_ATTRIBUTE_ENTRIES).map(|_| (1_usize, 1_usize));
        assert!(check_connection_attributes(over_entries).is_err());
    }

    #[test]
    fn hostile_declarations_are_rejected_without_allocation() {
        // The helpers are pure arithmetic: a 4-GiB declaration is rejected
        // with no buffer creation, and saturating accounting cannot wrap.
        assert!(check_pre_handshake_packet(usize::MAX).is_err());
        assert!(check_connection_attributes([(usize::MAX, usize::MAX)]).is_err());
    }

    #[test]
    fn errors_leak_no_input_bytes_or_paths() {
        let result = check_pre_handshake_packet(MAX_PRE_HANDSHAKE_PACKET_LEN + 7);
        let Err(error) = result else {
            unreachable!("a limit+7 declaration must be rejected")
        };
        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "pre-handshake packet length 1048583 exceeds limit 1048576"
        );
        assert!(!rendered.contains('/') && !rendered.contains('\\'));
    }

    #[test]
    fn diagnostic_text_clamps_on_char_boundary() {
        // -1 / exact / +1 around the cap.
        let under = "a".repeat(MAX_DIAGNOSTIC_TEXT_LEN - 1);
        assert_eq!(
            clamp_diagnostic_text(&under).len(),
            MAX_DIAGNOSTIC_TEXT_LEN - 1
        );
        let exact = "a".repeat(MAX_DIAGNOSTIC_TEXT_LEN);
        assert_eq!(clamp_diagnostic_text(&exact).len(), MAX_DIAGNOSTIC_TEXT_LEN);
        let ascii = "a".repeat(MAX_DIAGNOSTIC_TEXT_LEN + 10);
        assert_eq!(clamp_diagnostic_text(&ascii).len(), MAX_DIAGNOSTIC_TEXT_LEN);
        // A multibyte character straddling the cap is dropped, not split.
        let mut tricky = "a".repeat(MAX_DIAGNOSTIC_TEXT_LEN - 1);
        tricky.push('语');
        tricky.push_str("tail");
        let clamped = clamp_diagnostic_text(&tricky);
        assert!(clamped.len() <= MAX_DIAGNOSTIC_TEXT_LEN);
        assert!(clamped.is_char_boundary(clamped.len()));
        let short = "short";
        assert_eq!(clamp_diagnostic_text(short), short);
    }
}
