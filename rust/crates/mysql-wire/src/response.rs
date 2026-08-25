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

use crate::{
    CapabilityFlags, Cursor, DecodeError, EncodeError, LengthEncodedInt, ResponseHeader,
    StatusFlags, encode_length_encoded_int,
};

/// Structural classification of a response payload's first byte and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
    /// A regular OK packet beginning with `0x00`.
    Ok,
    /// An ERR packet beginning with `0xff`.
    Error,
    /// A LOCAL INFILE request beginning with `0xfb`.
    LocalInfile,
    /// A classic EOF packet (`0xfe`, at most five payload bytes).
    Eof,
    /// An OK-as-EOF result-set terminator (`0xfe`, 7 through 16 MiB - 2 bytes).
    ResultsetOk,
    /// An auth switch or otherwise context-dependent `0xfe` packet.
    AmbiguousFe,
    /// Any other response or result-set payload.
    Other,
}

/// Classifies a non-empty response payload using Go `TiProxy`'s EOF length rules.
///
/// # Errors
///
/// Returns [`DecodeError::UnexpectedEof`] for an empty payload.
pub fn classify_response(payload: &[u8]) -> Result<ResponseKind, DecodeError> {
    let Some(first) = payload.first().copied() else {
        return Err(DecodeError::UnexpectedEof {
            field: "response header",
            offset: 0,
            needed: 1,
            remaining: 0,
        });
    };
    Ok(match ResponseHeader::from_byte(first) {
        ResponseHeader::OK => ResponseKind::Ok,
        ResponseHeader::ERROR => ResponseKind::Error,
        ResponseHeader::LOCAL_INFILE => ResponseKind::LocalInfile,
        ResponseHeader::EOF_OR_AUTH_SWITCH if payload.len() <= 5 => ResponseKind::Eof,
        ResponseHeader::EOF_OR_AUTH_SWITCH
            if payload.len() >= 7 && payload.len() < 0x00ff_ffff_usize =>
        {
            ResponseKind::ResultsetOk
        }
        ResponseHeader::EOF_OR_AUTH_SWITCH => ResponseKind::AmbiguousFe,
        _ => ResponseKind::Other,
    })
}

/// A decoded `MySQL` ERR payload borrowing its human-readable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorPacket<'a> {
    /// Numeric `MySQL` error code.
    pub code: u16,
    /// Five-byte SQLSTATE when `CLIENT_PROTOCOL_41` is active.
    pub sql_state: Option<[u8; 5]>,
    /// Raw, untrusted message bytes after the structured header.
    pub message: &'a [u8],
    /// Exact payload bytes supplied by the caller.
    pub raw: &'a [u8],
}

/// Decodes a `MySQL` ERR payload without allocating.
///
/// # Errors
///
/// Returns a typed error for a wrong header, truncated code/SQLSTATE, or a
/// protocol-4.1 packet missing the required `#` marker.
pub fn parse_error_packet(
    payload: &[u8],
    capabilities: CapabilityFlags,
) -> Result<ErrorPacket<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let header_offset = cursor.position();
    let header = cursor.read_u8("error packet header")?;
    if header != ResponseHeader::ERROR.as_byte() {
        return Err(DecodeError::InvalidValue {
            field: "error packet header",
            offset: header_offset,
            value: header,
        });
    }
    let code = cursor.read_u16_le("error code")?;
    let sql_state = if capabilities.contains(CapabilityFlags::PROTOCOL_41) {
        let marker_offset = cursor.position();
        let marker = cursor.read_u8("SQLSTATE marker")?;
        if marker != b'#' {
            return Err(DecodeError::InvalidValue {
                field: "SQLSTATE marker",
                offset: marker_offset,
                value: marker,
            });
        }
        let bytes = cursor.take(5, "SQLSTATE")?;
        Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]])
    } else {
        None
    };
    Ok(ErrorPacket {
        code,
        sql_state,
        message: cursor.remaining_bytes(),
        raw: payload,
    })
}

/// Encodes a `MySQL` ERR payload.
///
/// # Errors
///
/// Returns [`EncodeError::MissingCapability`] if a SQLSTATE is supplied without
/// protocol 4.1, or [`EncodeError::InvalidFieldLength`] is avoided by the fixed
/// five-byte SQLSTATE type.
pub fn encode_error_packet(
    code: u16,
    sql_state: Option<[u8; 5]>,
    message: &[u8],
    capabilities: CapabilityFlags,
) -> Result<Vec<u8>, EncodeError> {
    if sql_state.is_some() && !capabilities.contains(CapabilityFlags::PROTOCOL_41) {
        return Err(EncodeError::MissingCapability {
            field: "SQLSTATE",
            capability: CapabilityFlags::PROTOCOL_41.bits(),
        });
    }
    let structured = if capabilities.contains(CapabilityFlags::PROTOCOL_41) {
        9
    } else {
        3
    };
    let mut output = Vec::with_capacity(structured + message.len());
    output.push(ResponseHeader::ERROR.as_byte());
    output.extend_from_slice(&code.to_le_bytes());
    if capabilities.contains(CapabilityFlags::PROTOCOL_41) {
        output.push(b'#');
        output.extend_from_slice(&sql_state.unwrap_or(*b"HY000"));
    }
    output.extend_from_slice(message);
    Ok(output)
}

/// A decoded OK payload borrowing its optional information tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OkPacket<'a> {
    /// Header byte (`0x00`, or `0xfe` for a result-set terminator).
    pub header: ResponseHeader,
    /// Affected row count.
    pub affected_rows: u64,
    /// Last inserted identifier.
    pub last_insert_id: u64,
    /// Server status when negotiated by protocol 4.1 or transactions.
    pub status: StatusFlags,
    /// Warning count when protocol 4.1 is active.
    pub warnings: u16,
    /// Remaining information/session-state bytes.
    pub info: &'a [u8],
    /// Exact payload bytes supplied by the caller.
    pub raw: &'a [u8],
}

/// Decodes a regular or OK-as-EOF payload without copying its tail.
///
/// # Errors
///
/// Returns a typed error for a wrong header, NULL/non-canonical length, or
/// truncated status/warning fields.
pub fn parse_ok_packet(
    payload: &[u8],
    capabilities: CapabilityFlags,
) -> Result<OkPacket<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let header_offset = cursor.position();
    let header = ResponseHeader::from_byte(cursor.read_u8("OK packet header")?);
    if header != ResponseHeader::OK && header != ResponseHeader::EOF_OR_AUTH_SWITCH {
        return Err(DecodeError::InvalidValue {
            field: "OK packet header",
            offset: header_offset,
            value: header.as_byte(),
        });
    }
    let affected_rows = read_required_lenenc(&mut cursor, "affected rows")?;
    let last_insert_id = read_required_lenenc(&mut cursor, "last insert id")?;
    let (status, warnings) = if capabilities.contains(CapabilityFlags::PROTOCOL_41) {
        (
            StatusFlags::from_bits_retain(cursor.read_u16_le("server status")?),
            cursor.read_u16_le("warning count")?,
        )
    } else if capabilities.contains(CapabilityFlags::TRANSACTIONS) {
        (
            StatusFlags::from_bits_retain(cursor.read_u16_le("server status")?),
            0,
        )
    } else {
        (StatusFlags::default(), 0)
    };
    Ok(OkPacket {
        header,
        affected_rows,
        last_insert_id,
        status,
        warnings,
        info: cursor.remaining_bytes(),
        raw: payload,
    })
}

fn read_required_lenenc(cursor: &mut Cursor<'_>, field: &'static str) -> Result<u64, DecodeError> {
    let offset = cursor.position();
    match cursor.read_length_encoded_int()? {
        LengthEncodedInt::Null => Err(DecodeError::UnexpectedNull { field, offset }),
        LengthEncodedInt::Value(value) => Ok(value),
    }
}

/// Encodes a regular or OK-as-EOF payload.
///
/// # Errors
///
/// Returns [`EncodeError::ValueOutOfRange`] when `header` is neither a regular
/// OK header nor the `0xfe` result-set terminator header.
pub fn encode_ok_packet(
    header: ResponseHeader,
    affected_rows: u64,
    last_insert_id: u64,
    status: StatusFlags,
    warnings: u16,
    info: &[u8],
    capabilities: CapabilityFlags,
) -> Result<Vec<u8>, EncodeError> {
    if header != ResponseHeader::OK && header != ResponseHeader::EOF_OR_AUTH_SWITCH {
        return Err(EncodeError::ValueOutOfRange {
            field: "OK packet header",
            value: u64::from(header.as_byte()),
            max: u64::from(ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte()),
        });
    }
    let mut output = Vec::with_capacity(7 + info.len());
    output.push(header.as_byte());
    encode_length_encoded_int(affected_rows, &mut output);
    encode_length_encoded_int(last_insert_id, &mut output);
    if capabilities.contains(CapabilityFlags::PROTOCOL_41) {
        output.extend_from_slice(&status.bits().to_le_bytes());
        output.extend_from_slice(&warnings.to_le_bytes());
    } else if capabilities.contains(CapabilityFlags::TRANSACTIONS) {
        output.extend_from_slice(&status.bits().to_le_bytes());
    }
    output.extend_from_slice(info);
    Ok(output)
}

/// A decoded legacy EOF payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EofPacket<'a> {
    /// Warning count.
    pub warnings: u16,
    /// Server status.
    pub status: StatusFlags,
    /// Exact payload bytes supplied by the caller.
    pub raw: &'a [u8],
}

/// Decodes a classic five-byte EOF payload.
///
/// # Errors
///
/// Returns a typed error for a non-EOF header or a payload that is not exactly
/// the protocol-4.1 EOF layout.
pub fn parse_eof_packet(payload: &[u8]) -> Result<EofPacket<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let header_offset = cursor.position();
    let header = cursor.read_u8("EOF packet header")?;
    if header != ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte() {
        return Err(DecodeError::InvalidValue {
            field: "EOF packet header",
            offset: header_offset,
            value: header,
        });
    }
    let warnings = cursor.read_u16_le("EOF warning count")?;
    let status = StatusFlags::from_bits_retain(cursor.read_u16_le("EOF server status")?);
    if !cursor.is_empty() {
        return Err(DecodeError::TrailingBytes {
            field: "EOF packet",
            offset: cursor.position(),
            remaining: cursor.remaining(),
        });
    }
    Ok(EofPacket {
        warnings,
        status,
        raw: payload,
    })
}

/// Encodes a classic five-byte EOF payload.
#[must_use]
pub fn encode_eof_packet(warnings: u16, status: StatusFlags) -> [u8; 5] {
    let warning_bytes = warnings.to_le_bytes();
    let status_bytes = status.bits().to_le_bytes();
    [
        ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte(),
        warning_bytes[0],
        warning_bytes[1],
        status_bytes[0],
        status_bytes[1],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTOCOL_41: CapabilityFlags = CapabilityFlags::PROTOCOL_41;

    #[test]
    fn classifies_go_eof_boundaries() {
        assert_eq!(classify_response(&[0xfe]), Ok(ResponseKind::Eof));
        assert_eq!(classify_response(&[0xfe; 5]), Ok(ResponseKind::Eof));
        assert_eq!(classify_response(&[0xfe; 6]), Ok(ResponseKind::AmbiguousFe));
        assert_eq!(classify_response(&[0xfe; 7]), Ok(ResponseKind::ResultsetOk));
    }

    #[test]
    fn error_packet_round_trip_borrows_message() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_error_packet(1064, Some(*b"42000"), b"synthetic", PROTOCOL_41)?;
        let decoded = parse_error_packet(&encoded, PROTOCOL_41)?;
        assert_eq!(decoded.code, 1064);
        assert_eq!(decoded.sql_state, Some(*b"42000"));
        assert_eq!(decoded.message, &encoded[9..]);
        Ok(())
    }

    #[test]
    fn ok_and_eof_round_trip_status() -> Result<(), Box<dyn std::error::Error>> {
        let status = StatusFlags::AUTOCOMMIT | StatusFlags::MORE_RESULTS_EXISTS;
        let encoded =
            encode_ok_packet(ResponseHeader::OK, 251, 0, status, 2, b"info", PROTOCOL_41)?;
        let decoded = parse_ok_packet(&encoded, PROTOCOL_41)?;
        assert_eq!(decoded.affected_rows, 251);
        assert_eq!(decoded.status, status);
        assert_eq!(decoded.warnings, 2);
        assert_eq!(decoded.info, b"info");

        let eof = encode_eof_packet(3, status);
        assert_eq!(
            parse_eof_packet(&eof),
            Ok(EofPacket {
                warnings: 3,
                status,
                raw: &eof,
            })
        );
        Ok(())
    }

    #[test]
    fn all_truncated_response_prefixes_return_errors() -> Result<(), EncodeError> {
        let error = encode_error_packet(1105, Some(*b"HY000"), b"x", PROTOCOL_41)?;
        for length in 0..9 {
            assert!(parse_error_packet(&error[..length], PROTOCOL_41).is_err());
        }

        let ok = encode_ok_packet(
            ResponseHeader::OK,
            0,
            0,
            StatusFlags::AUTOCOMMIT,
            0,
            &[],
            PROTOCOL_41,
        )?;
        for length in 0..7 {
            assert!(parse_ok_packet(&ok[..length], PROTOCOL_41).is_err());
        }
        Ok(())
    }
}
