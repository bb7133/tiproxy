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

//! Byte-exact Go `sqlreplay/cmd.NativeEncoder` record framing.
//!
//! This is a codec, not a capture or replay service. The timestamp and Go
//! `strconv.Quote` literal are kept verbatim to preserve the Go writer's
//! formatting. A future capture producer must format those fields before
//! calling [`encode`]; a replay consumer must unquote the literal separately.
//! Binary `MySQL` payloads stay entirely inside the dataplane.

use chrono::DateTime;
use mysql_wire::{CommandCode, MAX_PAYLOAD_LEN};
use thiserror::Error;

/// Maximum command body accepted by the native capture codec.
pub const MAX_CAPTURE_BODY: usize = MAX_PAYLOAD_LEN as usize - 1;
const MAX_GO_LITERAL: usize = 4 * MAX_CAPTURE_BODY + 2;
const MAX_TIMESTAMP_LEN: usize = 64;
const MAX_DECIMAL_LEN: usize = 20;

/// A single native capture record. `payload` includes the `MySQL` command byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRecord {
    /// `RFC3339Nano` text from Go, preserved byte-for-byte.
    pub timestamp: String,
    /// The Go capture connection ID.
    pub conn_id: u64,
    /// The `MySQL` command code.
    pub command: CommandCode,
    /// Whether Go considered the command successful.
    pub success: bool,
    /// Original prepared statement ID, if present.
    pub captured_ps_id: u32,
    /// Complete, already quoted Go string literal including double quotes.
    pub prepared_stmt_go_literal: Option<String>,
    /// Command byte followed by the original binary body.
    pub payload: Vec<u8>,
}

/// A malformed or truncated Go native capture record.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeFormatError {
    /// The record ends before the declared payload or header is complete.
    #[error("incomplete native capture record")]
    Incomplete,
    /// A header field or payload terminator is invalid.
    #[error("invalid native capture field: {0}")]
    Invalid(&'static str),
    /// A record exceeds the one-packet capture bound.
    #[error("native capture payload exceeds one physical MySQL packet")]
    Oversize,
}

fn valid_timestamp(value: &str) -> bool {
    value.len() <= MAX_TIMESTAMP_LEN
        && !value.contains(['\r', '\n'])
        && DateTime::parse_from_rfc3339(value).is_ok()
}

fn valid_go_literal(value: &str) -> bool {
    if value.len() > MAX_GO_LITERAL
        || value.len() < 2
        || !value.starts_with('"')
        || !value.ends_with('"')
    {
        return false;
    }
    let inner = &value.as_bytes()[1..value.len() - 1];
    let mut index = 0;
    while index < inner.len() {
        match inner[index] {
            b'"' | 0..=31 | 127 => return false,
            b'\\' => {
                index += 1;
                let Some(&escaped) = inner.get(index) else {
                    return false;
                };
                let hex_len = match escaped {
                    b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' | b'\\' | b'"' => 0,
                    b'x' => 2,
                    b'u' => 4,
                    b'U' => 8,
                    _ => return false,
                };
                if hex_len > 0 {
                    let Some(digits) = inner.get(index + 1..index + 1 + hex_len) else {
                        return false;
                    };
                    if !digits.iter().all(u8::is_ascii_hexdigit) {
                        return false;
                    }
                    index += hex_len;
                }
            }
            _ => {}
        }
        index += 1;
    }
    true
}

fn validate(record: &NativeRecord) -> Result<(), NativeFormatError> {
    if !valid_timestamp(&record.timestamp) {
        return Err(NativeFormatError::Invalid("Time"));
    }
    if record.conn_id == 0 {
        return Err(NativeFormatError::Invalid("Conn_ID"));
    }
    if record.command.name().is_none()
        || record.payload.first().copied() != Some(record.command.as_byte())
    {
        return Err(NativeFormatError::Invalid("Cmd_type/payload"));
    }
    if record.payload.len() > MAX_PAYLOAD_LEN as usize {
        return Err(NativeFormatError::Oversize);
    }
    if record
        .prepared_stmt_go_literal
        .as_deref()
        .is_some_and(|literal| !valid_go_literal(literal))
    {
        return Err(NativeFormatError::Invalid("Prepared_stmt"));
    }
    Ok(())
}

/// Encode one record using Go's field order and raw payload framing.
///
/// # Errors
///
/// Rejects invalid metadata, mismatched command bytes, and payloads above
/// one physical `MySQL` packet.
pub fn encode(record: &NativeRecord) -> Result<Vec<u8>, NativeFormatError> {
    validate(record)?;
    let mut output = Vec::with_capacity(record.payload.len().saturating_add(256));
    output.extend_from_slice(
        format!(
            "# Time: {}\n# Conn_ID: {}\n",
            record.timestamp, record.conn_id
        )
        .as_bytes(),
    );
    if record.command != CommandCode::QUERY {
        output.extend_from_slice(
            format!("# Cmd_type: {}\n", record.command.name().unwrap_or("")).as_bytes(),
        );
    }
    if !record.success {
        output.extend_from_slice(b"# Success: false\n");
    }
    if record.captured_ps_id != 0 {
        output
            .extend_from_slice(format!("# Captured_ps_id: {}\n", record.captured_ps_id).as_bytes());
    }
    if let Some(literal) = &record.prepared_stmt_go_literal {
        output.extend_from_slice(format!("# Prepared_stmt: {literal}\n").as_bytes());
    }
    output.extend_from_slice(format!("# Payload_len: {}\n", record.payload.len() - 1).as_bytes());
    output.extend_from_slice(&record.payload[1..]);
    output.push(b'\n');
    Ok(output)
}

fn line<'a>(
    input: &'a [u8],
    position: &mut usize,
    max_len: usize,
) -> Result<&'a str, NativeFormatError> {
    let rest = input
        .get(*position..)
        .ok_or(NativeFormatError::Incomplete)?;
    let scan = &rest[..rest.len().min(max_len.saturating_add(1))];
    let end = scan.iter().position(|byte| *byte == b'\n');
    if end.is_none() && rest.len() > max_len {
        return Err(NativeFormatError::Invalid("header line"));
    }
    let end = end.ok_or(NativeFormatError::Incomplete)?;
    if end > max_len || rest[..end].contains(&b'\r') {
        return Err(NativeFormatError::Invalid("header line"));
    }
    let value = std::str::from_utf8(&rest[..end])
        .map_err(|_| NativeFormatError::Invalid("header UTF-8"))?;
    *position += end + 1;
    Ok(value)
}

fn field<'a>(line: &'a str, prefix: &str) -> Result<&'a str, NativeFormatError> {
    line.strip_prefix(prefix)
        .filter(|value| !value.is_empty())
        .ok_or(NativeFormatError::Invalid("header order/value"))
}

fn decimal<T: std::str::FromStr>(value: &str, key: &'static str) -> Result<T, NativeFormatError> {
    if value.len() > MAX_DECIMAL_LEN || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NativeFormatError::Invalid(key));
    }
    value.parse().map_err(|_| NativeFormatError::Invalid(key))
}

/// Decode one canonical Go native record, returning its consumed byte count.
/// The length field bounds allocation before any payload copy. A caller may
/// repeatedly pass the remaining bytes to decode a concatenated log.
///
/// # Errors
///
/// Rejects incomplete records, invalid headers or terminators, and payloads
/// above one physical `MySQL` packet.
pub fn decode_one(input: &[u8]) -> Result<(NativeRecord, usize), NativeFormatError> {
    let mut position = 0;
    let timestamp = field(
        line(input, &mut position, MAX_TIMESTAMP_LEN + 8)?,
        "# Time: ",
    )?
    .to_owned();
    let conn_id = decimal(
        field(line(input, &mut position, 32)?, "# Conn_ID: ")?,
        "Conn_ID",
    )?;
    let mut record = NativeRecord {
        timestamp,
        conn_id,
        command: CommandCode::QUERY,
        success: true,
        captured_ps_id: 0,
        prepared_stmt_go_literal: None,
        payload: Vec::new(),
    };
    let mut header = line(input, &mut position, MAX_GO_LITERAL + 20)?;
    if let Some(name) = header.strip_prefix("# Cmd_type: ") {
        record.command = (0_u8..CommandCode::END_SENTINEL.as_byte())
            .map(CommandCode::from_byte)
            .find(|command| command.name() == Some(name))
            .filter(|command| *command != CommandCode::QUERY)
            .ok_or(NativeFormatError::Invalid("Cmd_type"))?;
        header = line(input, &mut position, MAX_GO_LITERAL + 20)?;
    }
    if header == "# Success: false" {
        record.success = false;
        header = line(input, &mut position, MAX_GO_LITERAL + 20)?;
    }
    if let Some(value) = header.strip_prefix("# Captured_ps_id: ") {
        record.captured_ps_id = decimal(value, "Captured_ps_id")?;
        if record.captured_ps_id == 0 {
            return Err(NativeFormatError::Invalid("Captured_ps_id"));
        }
        header = line(input, &mut position, MAX_GO_LITERAL + 20)?;
    }
    if let Some(literal) = header.strip_prefix("# Prepared_stmt: ") {
        record.prepared_stmt_go_literal = Some(literal.to_owned());
        header = line(input, &mut position, 40)?;
    }
    let body_len: usize = decimal(field(header, "# Payload_len: ")?, "Payload_len")?;
    if body_len > MAX_CAPTURE_BODY {
        return Err(NativeFormatError::Oversize);
    }
    let end = position
        .checked_add(body_len)
        .and_then(|value| value.checked_add(1))
        .ok_or(NativeFormatError::Oversize)?;
    let body = input
        .get(position..end)
        .ok_or(NativeFormatError::Incomplete)?;
    if body[body_len] != b'\n' {
        return Err(NativeFormatError::Invalid("payload terminator"));
    }
    record.payload.reserve(body_len + 1);
    record.payload.push(record.command.as_byte());
    record.payload.extend_from_slice(&body[..body_len]);
    validate(&record)?;
    Ok((record, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_native_encoder_fixture_round_trips_byte_exactly() -> Result<(), NativeFormatError> {
        let fixture = include_bytes!("../../../../tests/dataplane/capture-format/native-v1.log");
        let mut offset = 0;
        let mut count = 0;
        let mut encoded = Vec::new();
        while offset < fixture.len() {
            let (record, consumed) = decode_one(&fixture[offset..])?;
            assert!(consumed > 0);
            encoded.extend_from_slice(&encode(&record)?);
            offset += consumed;
            count += 1;
        }
        assert_eq!(count, 5);
        assert_eq!(encoded, fixture);
        Ok(())
    }

    #[test]
    fn rejects_truncated_and_oversized_payload_before_allocating() -> Result<(), NativeFormatError>
    {
        let fixture = include_bytes!("../../../../tests/dataplane/capture-format/native-v1.log");
        let (_, consumed) = decode_one(fixture)?;
        assert_eq!(
            decode_one(&fixture[..consumed - 1]),
            Err(NativeFormatError::Incomplete)
        );
        let too_large = format!(
            "# Time: 2024-08-28T18:51:20Z\n# Conn_ID: 100\n# Payload_len: {}\n",
            MAX_CAPTURE_BODY + 1
        );
        assert_eq!(
            decode_one(too_large.as_bytes()),
            Err(NativeFormatError::Oversize)
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_header_and_command_byte_mismatch() -> Result<(), NativeFormatError> {
        let fixture = include_bytes!("../../../../tests/dataplane/capture-format/native-v1.log");
        let mut bad = fixture.to_vec();
        let marker = b"# Conn_ID: 100";
        let at = bad
            .windows(marker.len())
            .position(|part| part == marker)
            .ok_or(NativeFormatError::Invalid("missing fixture connection ID"))?;
        bad[at + marker.len() - 3..at + marker.len()].copy_from_slice(b"000");
        assert_eq!(decode_one(&bad), Err(NativeFormatError::Invalid("Conn_ID")));
        let (mut record, _) = decode_one(fixture)?;
        record.command = CommandCode::QUIT;
        assert_eq!(
            encode(&record),
            Err(NativeFormatError::Invalid("Cmd_type/payload"))
        );
        Ok(())
    }

    #[test]
    fn rejects_header_injection_and_malformed_go_literals() -> Result<(), NativeFormatError> {
        let fixture = include_bytes!("../../../../tests/dataplane/capture-format/native-v1.log");
        let (mut record, _) = decode_one(fixture)?;
        for literal in ["\"bad\nheader\"", "\"bad\\q\"", "\"bad\"quote\""] {
            record.prepared_stmt_go_literal = Some(literal.to_owned());
            assert_eq!(
                encode(&record),
                Err(NativeFormatError::Invalid("Prepared_stmt"))
            );
        }
        let mut bad = fixture.to_vec();
        let marker = b"# Payload_len: 17\n";
        let at = bad
            .windows(marker.len())
            .position(|part| part == marker)
            .ok_or(NativeFormatError::Invalid("missing fixture payload length"))?;
        bad[at + marker.len() + 17] = b'X';
        assert_eq!(
            decode_one(&bad),
            Err(NativeFormatError::Invalid("payload terminator"))
        );
        Ok(())
    }
}
