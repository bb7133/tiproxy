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

//! Sans-I/O prepared-statement request and response codecs.
//!
//! Variable-width parameter values borrow the caller's packet. Decoding is
//! bounds checked even where the Go oracle indexes fixed numeric/temporal
//! fields directly. The ordinary proxy forwarding path needs only the fixed
//! statement-ID prefix; full value decoding exists for parity tests and
//! consumers that intentionally inspect a complete execute packet.

use core::fmt;

use crate::{
    CommandCode, Cursor, DecodeError, EncodeError, ResponseHeader, encode_length_encoded_bytes,
};

/// `MySQL` field types accepted by Go's prepared-execute parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColumnType {
    /// Legacy decimal.
    Decimal = 0x00,
    /// One-byte integer.
    Tiny = 0x01,
    /// Two-byte integer.
    Short = 0x02,
    /// Four-byte integer.
    Long = 0x03,
    /// IEEE-754 single precision.
    Float = 0x04,
    /// IEEE-754 double precision.
    Double = 0x05,
    /// SQL NULL.
    Null = 0x06,
    /// Timestamp temporal value.
    Timestamp = 0x07,
    /// Eight-byte integer.
    LongLong = 0x08,
    /// Three-byte SQL integer represented by four bytes on the wire.
    Int24 = 0x09,
    /// Date temporal value.
    Date = 0x0a,
    /// Time/duration temporal value.
    Time = 0x0b,
    /// Date-time temporal value.
    DateTime = 0x0c,
    /// Year value represented by two bytes.
    Year = 0x0d,
    /// Unsupported legacy new-date marker.
    NewDate = 0x0e,
    /// Variable-width character data.
    VarChar = 0x0f,
    /// Bit string.
    Bit = 0x10,
    /// `TiDB` vector extension.
    Vector = 0xf2,
    /// Invalid protocol sentinel.
    Invalid = 0xf3,
    /// Unsupported boolean extension marker.
    Bool = 0xf4,
    /// JSON bytes.
    Json = 0xf5,
    /// Modern decimal representation.
    NewDecimal = 0xf6,
    /// Enum bytes.
    Enum = 0xf7,
    /// Set bytes.
    Set = 0xf8,
    /// Tiny blob bytes.
    TinyBlob = 0xf9,
    /// Medium blob bytes.
    MediumBlob = 0xfa,
    /// Long blob bytes.
    LongBlob = 0xfb,
    /// Blob bytes.
    Blob = 0xfc,
    /// Variable string bytes.
    VarString = 0xfd,
    /// String bytes.
    String = 0xfe,
    /// Geometry bytes.
    Geometry = 0xff,
}

impl ColumnType {
    /// Decodes a raw field-type byte without losing `TiDB`'s vector extension.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => Self::Decimal,
            0x01 => Self::Tiny,
            0x02 => Self::Short,
            0x03 => Self::Long,
            0x04 => Self::Float,
            0x05 => Self::Double,
            0x06 => Self::Null,
            0x07 => Self::Timestamp,
            0x08 => Self::LongLong,
            0x09 => Self::Int24,
            0x0a => Self::Date,
            0x0b => Self::Time,
            0x0c => Self::DateTime,
            0x0d => Self::Year,
            0x0e => Self::NewDate,
            0x0f => Self::VarChar,
            0x10 => Self::Bit,
            0xf2 => Self::Vector,
            0xf3 => Self::Invalid,
            0xf4 => Self::Bool,
            0xf5 => Self::Json,
            0xf6 => Self::NewDecimal,
            0xf7 => Self::Enum,
            0xf8 => Self::Set,
            0xf9 => Self::TinyBlob,
            0xfa => Self::MediumBlob,
            0xfb => Self::LongBlob,
            0xfc => Self::Blob,
            0xfd => Self::VarString,
            0xfe => Self::String,
            0xff => Self::Geometry,
            _ => return None,
        })
    }

    /// Returns the exact protocol type byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    const fn is_length_encoded(self) -> bool {
        matches!(
            self,
            Self::Decimal
                | Self::VarChar
                | Self::Bit
                | Self::Vector
                | Self::Json
                | Self::NewDecimal
                | Self::Enum
                | Self::Set
                | Self::TinyBlob
                | Self::MediumBlob
                | Self::LongBlob
                | Self::Blob
                | Self::VarString
                | Self::String
                | Self::Geometry
        )
    }
}

/// Two-byte parameter type from `COM_STMT_EXECUTE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParameterType {
    /// MySQL/TiDB field type.
    pub column_type: ColumnType,
    /// Exact second byte. Go treats exactly `0x80` as unsigned and retains
    /// the two-byte pair for a later execute with `new-params-bound = 0`.
    pub flags: u8,
}

impl ParameterType {
    /// Whether the exact Go-compatible unsigned marker is set.
    #[must_use]
    pub const fn is_unsigned(self) -> bool {
        self.flags == 0x80
    }
}

/// One decoded execute parameter. Byte and temporal values borrow the packet.
#[derive(Clone, Copy, PartialEq)]
pub enum ParameterValue<'a> {
    /// SQL NULL.
    Null,
    /// Signed one-byte integer.
    Int8(i8),
    /// Unsigned one-byte integer.
    UInt8(u8),
    /// Signed two-byte integer.
    Int16(i16),
    /// Unsigned two-byte integer.
    UInt16(u16),
    /// Signed four-byte integer.
    Int32(i32),
    /// Unsigned four-byte integer.
    UInt32(u32),
    /// Signed eight-byte integer.
    Int64(i64),
    /// Unsigned eight-byte integer.
    UInt64(u64),
    /// IEEE-754 single precision.
    Float32(f32),
    /// IEEE-754 double precision.
    Float64(f64),
    /// Body after the one-byte temporal length. The type says date/time.
    Temporal(&'a [u8]),
    /// Length-encoded string/blob/json/vector bytes.
    Bytes(&'a [u8]),
}

impl fmt::Debug for ParameterValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("Null"),
            Self::Int8(value) => formatter.debug_tuple("Int8").field(value).finish(),
            Self::UInt8(value) => formatter.debug_tuple("UInt8").field(value).finish(),
            Self::Int16(value) => formatter.debug_tuple("Int16").field(value).finish(),
            Self::UInt16(value) => formatter.debug_tuple("UInt16").field(value).finish(),
            Self::Int32(value) => formatter.debug_tuple("Int32").field(value).finish(),
            Self::UInt32(value) => formatter.debug_tuple("UInt32").field(value).finish(),
            Self::Int64(value) => formatter.debug_tuple("Int64").field(value).finish(),
            Self::UInt64(value) => formatter.debug_tuple("UInt64").field(value).finish(),
            Self::Float32(value) => formatter.debug_tuple("Float32").field(value).finish(),
            Self::Float64(value) => formatter.debug_tuple("Float64").field(value).finish(),
            Self::Temporal(bytes) => formatter
                .debug_struct("Temporal")
                .field("bytes", &bytes.len())
                .finish(),
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("bytes", &bytes.len())
                .finish(),
        }
    }
}

/// One typed parameter from `COM_STMT_EXECUTE`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecuteParameter<'a> {
    /// Type pair carried by or retained for this execute.
    pub parameter_type: ParameterType,
    /// Decoded value.
    pub value: ParameterValue<'a>,
}

/// Decoded `COM_STMT_EXECUTE` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct StmtExecute<'a> {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Cursor flag byte.
    pub flags: u8,
    /// Protocol iteration count.
    pub iteration_count: u32,
    /// Whether this packet supplied fresh parameter types.
    pub new_params_bound: bool,
    /// Parameters decoded with the current or retained types.
    pub parameters: Vec<ExecuteParameter<'a>>,
    /// Forward-compatible bytes after all values understood from the types.
    pub trailing: &'a [u8],
}

/// Fields used to encode `COM_STMT_EXECUTE`.
#[derive(Debug, Clone, Copy)]
pub struct StmtExecuteParams<'a> {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Cursor flag byte.
    pub flags: u8,
    /// Protocol iteration count.
    pub iteration_count: u32,
    /// Whether to include the two-byte type pairs.
    pub new_params_bound: bool,
    /// Parameters to encode.
    pub parameters: &'a [ExecuteParameter<'a>],
}

/// `COM_STMT_PREPARE_OK` fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOk<'a> {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Declared result-column count.
    pub column_count: u16,
    /// Declared parameter count.
    pub parameter_count: u16,
    /// Backend warning count.
    pub warnings: u16,
    /// Forward-compatible bytes after the canonical 12-byte header.
    pub trailing: &'a [u8],
}

/// Fields encoded in the canonical prepare-OK header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOkParams {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Declared result-column count.
    pub column_count: u16,
    /// Declared parameter count.
    pub parameter_count: u16,
    /// Backend warning count.
    pub warnings: u16,
}

/// A fixed statement-ID command plus tolerated trailing bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatementCommand<'a> {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Tolerated bytes following the ID.
    pub trailing: &'a [u8],
}

/// Decoded `COM_STMT_FETCH` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StmtFetch<'a> {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Maximum number of rows requested.
    pub row_count: u32,
    /// Tolerated bytes following the fixed prefix.
    pub trailing: &'a [u8],
}

/// Decoded `COM_STMT_SEND_LONG_DATA` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StmtSendLongData<'a> {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Zero-based parameter identifier.
    pub parameter_id: u16,
    /// Opaque fragment bytes.
    pub data: &'a [u8],
}

/// Typed prepared request decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedDecodeError {
    /// Shared wire primitive failure.
    Wire(DecodeError),
    /// A reuse packet did not have the exact prior type vector available.
    MissingParameterTypes {
        /// Exact type count required by the prepare metadata.
        expected: usize,
        /// Retained type count provided by the caller.
        actual: usize,
    },
    /// The field type is not supported by Go's prepared parser.
    UnsupportedParameterType {
        /// Parameter index.
        index: usize,
        /// Raw field-type byte.
        type_code: u8,
    },
    /// A temporal value used a length outside Go's accepted set.
    InvalidTemporalLength {
        /// Parameter index.
        index: usize,
        /// Raw field-type byte.
        type_code: u8,
        /// Rejected temporal body length.
        length: u8,
    },
}

impl fmt::Display for PreparedDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::MissingParameterTypes { expected, actual } => write!(
                formatter,
                "execute needs {expected} retained parameter types, has {actual}"
            ),
            Self::UnsupportedParameterType { index, type_code } => write!(
                formatter,
                "unsupported execute parameter type 0x{type_code:02x} at index {index}"
            ),
            Self::InvalidTemporalLength {
                index,
                type_code,
                length,
            } => write!(
                formatter,
                "invalid temporal length {length} for type 0x{type_code:02x} at index {index}"
            ),
        }
    }
}

impl std::error::Error for PreparedDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DecodeError> for PreparedDecodeError {
    fn from(error: DecodeError) -> Self {
        Self::Wire(error)
    }
}

/// Typed prepared request encode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedEncodeError {
    /// Shared wire primitive failure.
    Wire(EncodeError),
    /// Protocol prepare metadata cannot declare this many parameters.
    TooManyParameters {
        /// Rejected parameter count.
        count: usize,
    },
    /// The Rust value variant does not match its declared field type.
    TypeValueMismatch {
        /// Parameter index.
        index: usize,
        /// Declared field-type byte.
        type_code: u8,
    },
    /// A temporal value used a length outside Go's accepted set.
    InvalidTemporalLength {
        /// Parameter index.
        index: usize,
        /// Declared field-type byte.
        type_code: u8,
        /// Rejected temporal body length.
        length: usize,
    },
}

impl fmt::Display for PreparedEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::TooManyParameters { count } => {
                write!(formatter, "execute parameter count {count} exceeds u16")
            }
            Self::TypeValueMismatch { index, type_code } => write!(
                formatter,
                "execute value does not match type 0x{type_code:02x} at index {index}"
            ),
            Self::InvalidTemporalLength {
                index,
                type_code,
                length,
            } => write!(
                formatter,
                "invalid temporal length {length} for type 0x{type_code:02x} at index {index}"
            ),
        }
    }
}

impl std::error::Error for PreparedEncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EncodeError> for PreparedEncodeError {
    fn from(error: EncodeError) -> Self {
        Self::Wire(error)
    }
}

fn expect_command(payload: &[u8], expected: CommandCode) -> Result<Cursor<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let actual = cursor.read_u8("prepared command").ok();
    if actual != Some(expected.as_byte()) {
        return Err(DecodeError::UnexpectedCommand {
            expected: expected.as_byte(),
            actual,
        });
    }
    Ok(cursor)
}

/// Decodes the canonical 12-byte `COM_STMT_PREPARE_OK` header.
///
/// # Errors
///
/// Returns a typed wire error for truncation, a non-OK header, or a nonzero
/// reserved byte.
pub fn decode_prepare_ok(payload: &[u8]) -> Result<PrepareOk<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let header = cursor.read_u8("prepare OK header")?;
    if header != ResponseHeader::OK.as_byte() {
        return Err(DecodeError::InvalidValue {
            field: "prepare OK header",
            offset: 0,
            value: header,
        });
    }
    let statement_id = cursor.read_u32_le("prepare statement ID")?;
    let column_count = cursor.read_u16_le("prepare column count")?;
    let parameter_count = cursor.read_u16_le("prepare parameter count")?;
    let reserved = cursor.read_u8("prepare reserved byte")?;
    if reserved != 0 {
        return Err(DecodeError::InvalidValue {
            field: "prepare reserved byte",
            offset: 9,
            value: reserved,
        });
    }
    let warnings = cursor.read_u16_le("prepare warning count")?;
    Ok(PrepareOk {
        statement_id,
        column_count,
        parameter_count,
        warnings,
        trailing: cursor.remaining_bytes(),
    })
}

/// Encodes the canonical 12-byte `COM_STMT_PREPARE_OK` header.
#[must_use]
pub fn encode_prepare_ok(params: PrepareOkParams) -> Vec<u8> {
    let mut output = Vec::with_capacity(12);
    output.push(ResponseHeader::OK.as_byte());
    output.extend_from_slice(&params.statement_id.to_le_bytes());
    output.extend_from_slice(&params.column_count.to_le_bytes());
    output.extend_from_slice(&params.parameter_count.to_le_bytes());
    output.push(0);
    output.extend_from_slice(&params.warnings.to_le_bytes());
    output
}

/// Returns the borrowed query bytes from `COM_STMT_PREPARE`.
///
/// # Errors
///
/// Returns a typed wire error when the command byte is missing or differs.
pub fn decode_stmt_prepare(payload: &[u8]) -> Result<&[u8], DecodeError> {
    let cursor = expect_command(payload, CommandCode::STMT_PREPARE)?;
    Ok(cursor.remaining_bytes())
}

/// Encodes a `COM_STMT_PREPARE` request.
#[must_use]
pub fn encode_stmt_prepare(query: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(query.len().saturating_add(1));
    output.push(CommandCode::STMT_PREPARE.as_byte());
    output.extend_from_slice(query);
    output
}

/// Decodes a command whose fixed prefix is command byte plus statement ID.
///
/// # Errors
///
/// Returns a typed wire error for the wrong command or a truncated ID.
pub fn decode_statement_command(
    payload: &[u8],
    expected: CommandCode,
) -> Result<StatementCommand<'_>, DecodeError> {
    let mut cursor = expect_command(payload, expected)?;
    let statement_id = cursor.read_u32_le("statement ID")?;
    Ok(StatementCommand {
        statement_id,
        trailing: cursor.remaining_bytes(),
    })
}

/// Encodes a command byte and statement ID.
#[must_use]
pub fn encode_statement_command(command: CommandCode, statement_id: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(5);
    output.push(command.as_byte());
    output.extend_from_slice(&statement_id.to_le_bytes());
    output
}

/// Decodes the fixed `COM_STMT_FETCH` prefix.
///
/// # Errors
///
/// Returns a typed wire error for the wrong command or truncation.
pub fn decode_stmt_fetch(payload: &[u8]) -> Result<StmtFetch<'_>, DecodeError> {
    let mut cursor = expect_command(payload, CommandCode::STMT_FETCH)?;
    let statement_id = cursor.read_u32_le("fetch statement ID")?;
    let row_count = cursor.read_u32_le("fetch row count")?;
    Ok(StmtFetch {
        statement_id,
        row_count,
        trailing: cursor.remaining_bytes(),
    })
}

/// Encodes a `COM_STMT_FETCH` request.
#[must_use]
pub fn encode_stmt_fetch(statement_id: u32, row_count: u32) -> Vec<u8> {
    let mut output = encode_statement_command(CommandCode::STMT_FETCH, statement_id);
    output.extend_from_slice(&row_count.to_le_bytes());
    output
}

/// Decodes a `COM_STMT_SEND_LONG_DATA` request without copying its data.
///
/// # Errors
///
/// Returns a typed wire error for the wrong command or truncated fixed prefix.
pub fn decode_stmt_send_long_data(payload: &[u8]) -> Result<StmtSendLongData<'_>, DecodeError> {
    let mut cursor = expect_command(payload, CommandCode::STMT_SEND_LONG_DATA)?;
    let statement_id = cursor.read_u32_le("long-data statement ID")?;
    let parameter_id = cursor.read_u16_le("long-data parameter ID")?;
    Ok(StmtSendLongData {
        statement_id,
        parameter_id,
        data: cursor.remaining_bytes(),
    })
}

/// Encodes a `COM_STMT_SEND_LONG_DATA` request.
#[must_use]
pub fn encode_stmt_send_long_data(statement_id: u32, parameter_id: u16, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len().saturating_add(7));
    output.push(CommandCode::STMT_SEND_LONG_DATA.as_byte());
    output.extend_from_slice(&statement_id.to_le_bytes());
    output.extend_from_slice(&parameter_id.to_le_bytes());
    output.extend_from_slice(data);
    output
}

fn parameter_type(raw: &[u8], index: usize) -> Result<ParameterType, PreparedDecodeError> {
    let column_type =
        ColumnType::from_byte(raw[0]).ok_or(PreparedDecodeError::UnsupportedParameterType {
            index,
            type_code: raw[0],
        })?;
    if matches!(
        column_type,
        ColumnType::NewDate | ColumnType::Invalid | ColumnType::Bool
    ) {
        return Err(PreparedDecodeError::UnsupportedParameterType {
            index,
            type_code: raw[0],
        });
    }
    Ok(ParameterType {
        column_type,
        flags: raw[1],
    })
}

fn temporal_length_valid(column_type: ColumnType, length: u8) -> bool {
    match column_type {
        ColumnType::Date | ColumnType::Timestamp | ColumnType::DateTime => {
            matches!(length, 0 | 4 | 7 | 11 | 13)
        }
        ColumnType::Time => matches!(length, 0 | 8 | 12),
        _ => false,
    }
}

fn decode_parameter<'a>(
    cursor: &mut Cursor<'a>,
    parameter_type: ParameterType,
    index: usize,
) -> Result<ParameterValue<'a>, PreparedDecodeError> {
    let ty = parameter_type.column_type;
    let value = match ty {
        ColumnType::Null => ParameterValue::Null,
        ColumnType::Tiny => {
            let value = cursor.read_u8("tiny parameter")?;
            if parameter_type.is_unsigned() {
                ParameterValue::UInt8(value)
            } else {
                ParameterValue::Int8(i8::from_le_bytes([value]))
            }
        }
        ColumnType::Short | ColumnType::Year => {
            let value = cursor.read_u16_le("short parameter")?;
            if parameter_type.is_unsigned() {
                ParameterValue::UInt16(value)
            } else {
                ParameterValue::Int16(i16::from_le_bytes(value.to_le_bytes()))
            }
        }
        ColumnType::Long | ColumnType::Int24 => {
            let value = cursor.read_u32_le("long parameter")?;
            if parameter_type.is_unsigned() {
                ParameterValue::UInt32(value)
            } else {
                ParameterValue::Int32(i32::from_le_bytes(value.to_le_bytes()))
            }
        }
        ColumnType::LongLong => {
            let value = cursor.read_u64_le("long-long parameter")?;
            if parameter_type.is_unsigned() {
                ParameterValue::UInt64(value)
            } else {
                ParameterValue::Int64(i64::from_le_bytes(value.to_le_bytes()))
            }
        }
        ColumnType::Float => {
            ParameterValue::Float32(f32::from_bits(cursor.read_u32_le("float parameter")?))
        }
        ColumnType::Double => {
            ParameterValue::Float64(f64::from_bits(cursor.read_u64_le("double parameter")?))
        }
        ColumnType::Date | ColumnType::Timestamp | ColumnType::DateTime | ColumnType::Time => {
            let length = cursor.read_u8("temporal parameter length")?;
            if !temporal_length_valid(ty, length) {
                return Err(PreparedDecodeError::InvalidTemporalLength {
                    index,
                    type_code: ty.as_byte(),
                    length,
                });
            }
            ParameterValue::Temporal(cursor.take(usize::from(length), "temporal parameter")?)
        }
        _ if ty.is_length_encoded() => {
            match cursor.read_length_encoded_bytes("execute parameter")? {
                Some(bytes) => ParameterValue::Bytes(bytes),
                None => ParameterValue::Null,
            }
        }
        _ => {
            return Err(PreparedDecodeError::UnsupportedParameterType {
                index,
                type_code: ty.as_byte(),
            });
        }
    };
    Ok(value)
}

/// Decodes a complete `COM_STMT_EXECUTE` request using its declared prepare
/// parameter count and, for reuse packets, the previously retained types.
///
/// # Errors
///
/// Returns a typed decode failure for truncation, unsupported types, invalid
/// temporal lengths, or missing retained types. Every packet prefix is safe.
pub fn decode_stmt_execute<'a>(
    payload: &'a [u8],
    parameter_count: usize,
    previous_types: &[ParameterType],
) -> Result<StmtExecute<'a>, PreparedDecodeError> {
    let mut cursor = expect_command(payload, CommandCode::STMT_EXECUTE)?;
    let statement_id = cursor.read_u32_le("execute statement ID")?;
    let flags = cursor.read_u8("execute flags")?;
    let iteration_count = cursor.read_u32_le("execute iteration count")?;
    if parameter_count == 0 {
        return Ok(StmtExecute {
            statement_id,
            flags,
            iteration_count,
            new_params_bound: false,
            parameters: Vec::new(),
            trailing: cursor.remaining_bytes(),
        });
    }

    let bitmap_length = parameter_count
        .checked_add(7)
        .ok_or(PreparedDecodeError::Wire(DecodeError::LengthOverflow {
            field: "execute null bitmap",
            offset: cursor.position(),
            value: u64::try_from(parameter_count).unwrap_or(u64::MAX),
        }))?
        / 8;
    let null_bitmap = cursor.take(bitmap_length, "execute null bitmap")?;
    let new_params_bound = cursor.read_u8("new-params-bound flag")? != 0;
    let parameter_types = if new_params_bound {
        let raw_types = cursor.take(
            parameter_count
                .checked_mul(2)
                .ok_or(PreparedDecodeError::Wire(DecodeError::LengthOverflow {
                    field: "execute parameter types",
                    offset: cursor.position(),
                    value: u64::try_from(parameter_count).unwrap_or(u64::MAX),
                }))?,
            "execute parameter types",
        )?;
        raw_types
            .chunks_exact(2)
            .enumerate()
            .map(|(index, raw)| parameter_type(raw, index))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        if previous_types.len() != parameter_count {
            return Err(PreparedDecodeError::MissingParameterTypes {
                expected: parameter_count,
                actual: previous_types.len(),
            });
        }
        previous_types.to_vec()
    };

    let mut parameters = Vec::with_capacity(parameter_count);
    for (index, parameter_type) in parameter_types.into_iter().enumerate() {
        let value = if null_bitmap[index / 8] & (1 << (index % 8)) != 0 {
            ParameterValue::Null
        } else {
            decode_parameter(&mut cursor, parameter_type, index)?
        };
        parameters.push(ExecuteParameter {
            parameter_type,
            value,
        });
    }
    Ok(StmtExecute {
        statement_id,
        flags,
        iteration_count,
        new_params_bound,
        parameters,
        trailing: cursor.remaining_bytes(),
    })
}

fn encode_parameter(
    output: &mut Vec<u8>,
    parameter: ExecuteParameter<'_>,
    index: usize,
) -> Result<(), PreparedEncodeError> {
    let ty = parameter.parameter_type.column_type;
    match (ty, parameter.value) {
        (_, ParameterValue::Null) => Ok(()),
        (ColumnType::Tiny, ParameterValue::Int8(value))
            if !parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::Tiny, ParameterValue::UInt8(value))
            if parameter.parameter_type.is_unsigned() =>
        {
            output.push(value);
            Ok(())
        }
        (ColumnType::Short | ColumnType::Year, ParameterValue::Int16(value))
            if !parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::Short | ColumnType::Year, ParameterValue::UInt16(value))
            if parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::Long | ColumnType::Int24, ParameterValue::Int32(value))
            if !parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::Long | ColumnType::Int24, ParameterValue::UInt32(value))
            if parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::LongLong, ParameterValue::Int64(value))
            if !parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::LongLong, ParameterValue::UInt64(value))
            if parameter.parameter_type.is_unsigned() =>
        {
            output.extend_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (ColumnType::Float, ParameterValue::Float32(value)) => {
            output.extend_from_slice(&value.to_bits().to_le_bytes());
            Ok(())
        }
        (ColumnType::Double, ParameterValue::Float64(value)) => {
            output.extend_from_slice(&value.to_bits().to_le_bytes());
            Ok(())
        }
        (
            ColumnType::Date | ColumnType::Timestamp | ColumnType::DateTime | ColumnType::Time,
            ParameterValue::Temporal(bytes),
        ) => {
            let length = u8::try_from(bytes.len()).map_err(|_| {
                PreparedEncodeError::InvalidTemporalLength {
                    index,
                    type_code: ty.as_byte(),
                    length: bytes.len(),
                }
            })?;
            if !temporal_length_valid(ty, length) {
                return Err(PreparedEncodeError::InvalidTemporalLength {
                    index,
                    type_code: ty.as_byte(),
                    length: bytes.len(),
                });
            }
            output.push(length);
            output.extend_from_slice(bytes);
            Ok(())
        }
        (_, ParameterValue::Bytes(bytes)) if ty.is_length_encoded() => {
            encode_length_encoded_bytes(Some(bytes), output)?;
            Ok(())
        }
        _ => Err(PreparedEncodeError::TypeValueMismatch {
            index,
            type_code: ty.as_byte(),
        }),
    }
}

/// Encodes a complete `COM_STMT_EXECUTE` request.
///
/// # Errors
///
/// Returns a typed failure for excessive parameter count, mismatched value
/// variants, invalid temporal lengths, or length-encoding overflow.
pub fn encode_stmt_execute(params: StmtExecuteParams<'_>) -> Result<Vec<u8>, PreparedEncodeError> {
    if u16::try_from(params.parameters.len()).is_err() {
        return Err(PreparedEncodeError::TooManyParameters {
            count: params.parameters.len(),
        });
    }
    let bitmap_length = params.parameters.len().saturating_add(7) / 8;
    let mut null_bitmap = vec![0_u8; bitmap_length];
    for (index, parameter) in params.parameters.iter().enumerate() {
        if matches!(parameter.value, ParameterValue::Null) {
            null_bitmap[index / 8] |= 1 << (index % 8);
        }
    }

    let mut output = Vec::new();
    output.push(CommandCode::STMT_EXECUTE.as_byte());
    output.extend_from_slice(&params.statement_id.to_le_bytes());
    output.push(params.flags);
    output.extend_from_slice(&params.iteration_count.to_le_bytes());
    if params.parameters.is_empty() {
        return Ok(output);
    }
    output.extend_from_slice(&null_bitmap);
    output.push(u8::from(params.new_params_bound));
    if params.new_params_bound {
        for parameter in params.parameters {
            output.push(parameter.parameter_type.column_type.as_byte());
            output.push(parameter.parameter_type.flags);
        }
    }
    for (index, parameter) in params.parameters.iter().copied().enumerate() {
        encode_parameter(&mut output, parameter, index)?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_LONG: ParameterType = ParameterType {
        column_type: ColumnType::Long,
        flags: 0,
    };
    const UNSIGNED_LONG_LONG: ParameterType = ParameterType {
        column_type: ColumnType::LongLong,
        flags: 0x80,
    };
    const STRING: ParameterType = ParameterType {
        column_type: ColumnType::String,
        flags: 0,
    };

    #[test]
    fn prepare_and_statement_commands_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let request = encode_stmt_prepare(b"SELECT ?");
        assert_eq!(decode_stmt_prepare(&request)?, b"SELECT ?");

        let response = encode_prepare_ok(PrepareOkParams {
            statement_id: 7,
            column_count: 2,
            parameter_count: 1,
            warnings: 3,
        });
        let decoded = decode_prepare_ok(&response)?;
        assert_eq!(decoded.statement_id, 7);
        assert_eq!(decoded.column_count, 2);
        assert_eq!(decoded.parameter_count, 1);
        assert_eq!(decoded.warnings, 3);

        for command in [CommandCode::STMT_CLOSE, CommandCode::STMT_RESET] {
            let packet = encode_statement_command(command, 9);
            assert_eq!(decode_statement_command(&packet, command)?.statement_id, 9);
        }
        let fetch = encode_stmt_fetch(11, 32);
        assert_eq!(decode_stmt_fetch(&fetch)?.row_count, 32);
        let long_data = encode_stmt_send_long_data(13, 2, b"fragment");
        assert_eq!(decode_stmt_send_long_data(&long_data)?.data, b"fragment");
        Ok(())
    }

    #[test]
    fn execute_types_values_and_reuse_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let parameters = [
            ExecuteParameter {
                parameter_type: SIGNED_LONG,
                value: ParameterValue::Int32(-200),
            },
            ExecuteParameter {
                parameter_type: UNSIGNED_LONG_LONG,
                value: ParameterValue::UInt64(300),
            },
            ExecuteParameter {
                parameter_type: STRING,
                value: ParameterValue::Bytes(b"hello"),
            },
            ExecuteParameter {
                parameter_type: STRING,
                value: ParameterValue::Null,
            },
        ];
        let first = encode_stmt_execute(StmtExecuteParams {
            statement_id: 5,
            flags: 1,
            iteration_count: 1,
            new_params_bound: true,
            parameters: &parameters,
        })?;
        let decoded = decode_stmt_execute(&first, parameters.len(), &[])?;
        assert!(decoded.new_params_bound);
        assert_eq!(decoded.parameters, parameters);

        let second = encode_stmt_execute(StmtExecuteParams {
            statement_id: 5,
            flags: 1,
            iteration_count: 1,
            new_params_bound: false,
            parameters: &parameters,
        })?;
        let types: Vec<_> = parameters
            .iter()
            .map(|parameter| parameter.parameter_type)
            .collect();
        assert_eq!(
            decode_stmt_execute(&second, parameters.len(), &types)?.parameters,
            parameters
        );
        Ok(())
    }

    #[test]
    fn temporal_blob_json_vector_and_truncation_are_safe() -> Result<(), Box<dyn std::error::Error>>
    {
        let date = [0xe8, 0x07, 8, 26];
        let time = [0, 1, 0, 0, 0, 2, 3, 4];
        let parameters = [
            ExecuteParameter {
                parameter_type: ParameterType {
                    column_type: ColumnType::DateTime,
                    flags: 0,
                },
                value: ParameterValue::Temporal(&date),
            },
            ExecuteParameter {
                parameter_type: ParameterType {
                    column_type: ColumnType::Time,
                    flags: 0,
                },
                value: ParameterValue::Temporal(&time),
            },
            ExecuteParameter {
                parameter_type: ParameterType {
                    column_type: ColumnType::Blob,
                    flags: 0,
                },
                value: ParameterValue::Bytes(b"blob"),
            },
            ExecuteParameter {
                parameter_type: ParameterType {
                    column_type: ColumnType::Json,
                    flags: 0,
                },
                value: ParameterValue::Bytes(br#"{"k":1}"#),
            },
            ExecuteParameter {
                parameter_type: ParameterType {
                    column_type: ColumnType::Vector,
                    flags: 0,
                },
                value: ParameterValue::Bytes(b"vector"),
            },
        ];
        let packet = encode_stmt_execute(StmtExecuteParams {
            statement_id: 17,
            flags: 0,
            iteration_count: 1,
            new_params_bound: true,
            parameters: &parameters,
        })?;
        assert_eq!(
            decode_stmt_execute(&packet, parameters.len(), &[])?.parameters,
            parameters
        );
        for length in 0..packet.len() {
            assert!(decode_stmt_execute(&packet[..length], parameters.len(), &[]).is_err());
        }
        Ok(())
    }

    #[test]
    fn execute_without_new_types_requires_exact_history() -> Result<(), PreparedEncodeError> {
        let parameters = [ExecuteParameter {
            parameter_type: SIGNED_LONG,
            value: ParameterValue::Int32(1),
        }];
        let packet = encode_stmt_execute(StmtExecuteParams {
            statement_id: 1,
            flags: 0,
            iteration_count: 1,
            new_params_bound: false,
            parameters: &parameters,
        })?;
        assert!(matches!(
            decode_stmt_execute(&packet, 1, &[]),
            Err(PreparedDecodeError::MissingParameterTypes {
                expected: 1,
                actual: 0
            })
        ));

        let unsigned_type_with_signed_value = [ExecuteParameter {
            parameter_type: UNSIGNED_LONG_LONG,
            value: ParameterValue::Int64(1),
        }];
        assert!(matches!(
            encode_stmt_execute(StmtExecuteParams {
                statement_id: 1,
                flags: 0,
                iteration_count: 1,
                new_params_bound: true,
                parameters: &unsigned_type_with_signed_value,
            }),
            Err(PreparedEncodeError::TypeValueMismatch { index: 0, .. })
        ));

        let noncanonical_flag_is_signed = [ExecuteParameter {
            parameter_type: ParameterType {
                column_type: ColumnType::Long,
                flags: 1,
            },
            value: ParameterValue::Int32(-1),
        }];
        assert!(
            encode_stmt_execute(StmtExecuteParams {
                statement_id: 1,
                flags: 0,
                iteration_count: 1,
                new_params_bound: true,
                parameters: &noncanonical_flag_is_signed,
            })
            .is_ok()
        );
        Ok(())
    }
}
