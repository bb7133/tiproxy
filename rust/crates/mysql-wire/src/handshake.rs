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

use crate::attributes::read_prefixed_attributes;
use crate::{
    Attribute, CapabilityFlags, CommandCode, ConnectionAttributes, Cursor, DecodeError,
    EncodeError, LengthEncodedInt, StatusFlags, encode_connection_attributes,
    encode_length_encoded_int,
};

const HANDSHAKE_PROTOCOL_VERSION: u8 = 10;
const HANDSHAKE_RESPONSE_FIXED_BYTES: usize = 32;
/// The exact size of an `SSLRequest` packet (the fixed handshake-response
/// prefix sent before a TLS handshake).
pub const SSL_REQUEST_BYTES: usize = 32;
const INITIAL_AUTH_PART_ONE_BYTES: usize = 8;
const INITIAL_AUTH_PART_TWO_WIRE_BYTES: usize = 13;

/// A decoded protocol-10 server greeting borrowing variable-width fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialHandshake<'a> {
    /// Protocol version, currently required to be 10.
    pub protocol_version: u8,
    /// NUL-terminated server-version bytes.
    pub server_version: &'a [u8],
    /// Server connection identifier.
    pub connection_id: u32,
    /// First eight authentication-plugin bytes.
    pub auth_plugin_data_part_1: &'a [u8],
    /// Remaining authentication-plugin bytes, without a trailing NUL.
    pub auth_plugin_data_part_2: &'a [u8],
    /// Advertised capabilities, retaining unknown bits.
    pub capabilities: CapabilityFlags,
    /// Server collation for a modern greeting.
    pub collation: Option<u8>,
    /// Server status for a modern greeting.
    pub status: Option<StatusFlags>,
    /// Authentication plugin name when advertised.
    pub auth_plugin_name: Option<&'a [u8]>,
    /// Exact greeting payload supplied by the caller.
    pub raw: &'a [u8],
    /// Any forward-compatible bytes after the fields this codec understands.
    pub trailing: &'a [u8],
}

/// Borrowed fields used to encode a protocol-10 server greeting.
#[derive(Debug, Clone, Copy)]
pub struct InitialHandshakeParams<'a> {
    /// Server-version bytes, without a NUL terminator.
    pub server_version: &'a [u8],
    /// Server connection identifier.
    pub connection_id: u32,
    /// Exactly 20 authentication-plugin bytes.
    pub auth_plugin_data: &'a [u8],
    /// Advertised capability mask.
    pub capabilities: CapabilityFlags,
    /// Server collation byte.
    pub collation: u8,
    /// Initial server status.
    pub status: StatusFlags,
    /// Authentication plugin name, without a NUL terminator.
    pub auth_plugin_name: &'a [u8],
}

/// Decodes a protocol-10 server greeting without allocating.
///
/// Old greetings that end after the lower capability word are accepted with
/// absent modern fields. Modern greetings require complete fixed fields,
/// authentication bytes, and a terminated plugin name when advertised.
///
/// # Errors
///
/// Returns a typed error for a wrong protocol version, missing terminator,
/// truncated field, or inconsistent authentication-data length.
pub fn parse_initial_handshake(payload: &[u8]) -> Result<InitialHandshake<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let protocol_offset = cursor.position();
    let protocol_version = cursor.read_u8("handshake protocol version")?;
    if protocol_version != HANDSHAKE_PROTOCOL_VERSION {
        return Err(DecodeError::InvalidValue {
            field: "handshake protocol version",
            offset: protocol_offset,
            value: protocol_version,
        });
    }
    let server_version = cursor.read_nul_terminated("server version")?;
    let connection_id = cursor.read_u32_le("server connection id")?;
    let auth_plugin_data_part_1 =
        cursor.take(INITIAL_AUTH_PART_ONE_BYTES, "auth plugin data part 1")?;
    let filler_offset = cursor.position();
    let filler = cursor.read_u8("handshake filler")?;
    if filler != 0 {
        return Err(DecodeError::InvalidValue {
            field: "handshake filler",
            offset: filler_offset,
            value: filler,
        });
    }
    let lower = u32::from(cursor.read_u16_le("lower capability flags")?);
    if cursor.is_empty() {
        return Ok(InitialHandshake {
            protocol_version,
            server_version,
            connection_id,
            auth_plugin_data_part_1,
            auth_plugin_data_part_2: &[],
            capabilities: CapabilityFlags::from_bits_retain(lower),
            collation: None,
            status: None,
            auth_plugin_name: None,
            raw: payload,
            trailing: &[],
        });
    }

    let collation = cursor.read_u8("server collation")?;
    let status = StatusFlags::from_bits_retain(cursor.read_u16_le("server status")?);
    let upper = u32::from(cursor.read_u16_le("upper capability flags")?);
    let capabilities = CapabilityFlags::from_bits_retain(lower | (upper << 16));
    let auth_plugin_data_length = usize::from(cursor.read_u8("auth plugin data length")?);
    cursor.take(10, "handshake reserved bytes")?;

    let has_auth_tail =
        capabilities.intersects(CapabilityFlags::SECURE_CONNECTION | CapabilityFlags::PLUGIN_AUTH);
    let auth_plugin_data_part_2 = if has_auth_tail {
        let declared_tail = auth_plugin_data_length.saturating_sub(INITIAL_AUTH_PART_ONE_BYTES);
        let wire_length = declared_tail.max(INITIAL_AUTH_PART_TWO_WIRE_BYTES);
        let tail = cursor.take(wire_length, "auth plugin data part 2")?;
        tail.strip_suffix(&[0]).unwrap_or(tail)
    } else {
        &[]
    };

    let auth_plugin_name = if capabilities.contains(CapabilityFlags::PLUGIN_AUTH) {
        Some(cursor.read_nul_terminated("auth plugin name")?)
    } else {
        None
    };
    let trailing = cursor.remaining_bytes();
    Ok(InitialHandshake {
        protocol_version,
        server_version,
        connection_id,
        auth_plugin_data_part_1,
        auth_plugin_data_part_2,
        capabilities,
        collation: Some(collation),
        status: Some(status),
        auth_plugin_name,
        raw: payload,
        trailing,
    })
}

/// Encodes a modern protocol-10 server greeting matching `TiProxy`'s Go layout.
///
/// # Errors
///
/// Returns a typed error unless the authentication data is exactly 20 bytes or
/// if a NUL-terminated source field contains an interior NUL.
pub fn encode_initial_handshake(
    params: InitialHandshakeParams<'_>,
) -> Result<Vec<u8>, EncodeError> {
    validate_nul_free(params.server_version, "server version")?;
    validate_nul_free(params.auth_plugin_name, "auth plugin name")?;
    if params.auth_plugin_data.len() != 20 {
        return Err(EncodeError::InvalidFieldLength {
            field: "auth plugin data",
            length: params.auth_plugin_data.len(),
            expected: 20,
        });
    }

    let mut output = Vec::with_capacity(
        47_usize
            .saturating_add(params.server_version.len())
            .saturating_add(params.auth_plugin_name.len()),
    );
    output.push(HANDSHAKE_PROTOCOL_VERSION);
    output.extend_from_slice(params.server_version);
    output.push(0);
    output.extend_from_slice(&params.connection_id.to_le_bytes());
    output.extend_from_slice(&params.auth_plugin_data[..INITIAL_AUTH_PART_ONE_BYTES]);
    output.push(0);
    let bits = params.capabilities.bits();
    let capability_bytes = bits.to_le_bytes();
    output.extend_from_slice(&capability_bytes[..2]);
    output.push(params.collation);
    output.extend_from_slice(&params.status.bits().to_le_bytes());
    output.extend_from_slice(&capability_bytes[2..]);
    output.push(21);
    output.extend_from_slice(&[0; 10]);
    output.extend_from_slice(&params.auth_plugin_data[INITIAL_AUTH_PART_ONE_BYTES..]);
    output.push(0);
    output.extend_from_slice(params.auth_plugin_name);
    output.push(0);
    Ok(output)
}

/// A decoded 32-byte `SSLRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SslRequest<'a> {
    /// Client capability mask including `CLIENT_SSL`.
    pub capabilities: CapabilityFlags,
    /// Maximum packet size advertised by the client.
    pub max_packet_size: u32,
    /// Client collation byte.
    pub collation: u8,
    /// Exact 32-byte request payload.
    pub raw: &'a [u8],
}

/// Decodes an exact 32-byte `SSLRequest`.
///
/// # Errors
///
/// Returns a typed error for truncation, trailing bytes, or a missing
/// `CLIENT_SSL` capability.
pub fn parse_ssl_request(payload: &[u8]) -> Result<SslRequest<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let capabilities =
        CapabilityFlags::from_bits_retain(cursor.read_u32_le("client capability flags")?);
    let max_packet_size = cursor.read_u32_le("client maximum packet size")?;
    let collation = cursor.read_u8("client collation")?;
    cursor.take(23, "SSLRequest reserved bytes")?;
    if !capabilities.contains(CapabilityFlags::SSL) {
        return Err(DecodeError::InvalidValue {
            field: "SSLRequest capability flags",
            offset: 0,
            value: capabilities.bits().to_le_bytes()[0],
        });
    }
    if !cursor.is_empty() {
        return Err(DecodeError::TrailingBytes {
            field: "SSLRequest",
            offset: cursor.position(),
            remaining: cursor.remaining(),
        });
    }
    Ok(SslRequest {
        capabilities,
        max_packet_size,
        collation,
        raw: payload,
    })
}

/// Encodes the exact 32-byte `SSLRequest` sent before a TLS handshake: the
/// capability mask (which must carry `CLIENT_SSL`), the maximum packet size,
/// the collation byte, and 23 reserved zero bytes. This is the leading prefix
/// of a full handshake response, sent alone so the peer starts TLS before the
/// credentials follow inside the encrypted channel.
#[must_use]
pub fn encode_ssl_request(
    capabilities: CapabilityFlags,
    max_packet_size: u32,
    collation: u8,
) -> [u8; SSL_REQUEST_BYTES] {
    let mut output = [0_u8; SSL_REQUEST_BYTES];
    output[0..4].copy_from_slice(&capabilities.bits().to_le_bytes());
    output[4..8].copy_from_slice(&max_packet_size.to_le_bytes());
    output[8] = collation;
    // output[9..32] stays zero: the 23 reserved bytes.
    output
}

/// A decoded full client handshake response borrowing all variable-width fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse<'a> {
    /// Client capability mask.
    pub capabilities: CapabilityFlags,
    /// Maximum packet size advertised by the client.
    pub max_packet_size: u32,
    /// Client collation byte.
    pub collation: u8,
    /// Username bytes.
    pub username: &'a [u8],
    /// Authentication response bytes.
    pub auth_response: &'a [u8],
    /// Initial database when negotiated.
    pub database: Option<&'a [u8]>,
    /// Authentication plugin name when negotiated.
    pub auth_plugin_name: Option<&'a [u8]>,
    /// Validated, ordered connection attributes when negotiated.
    pub attributes: Option<ConnectionAttributes<'a>>,
    /// Requested zstd compression level when negotiated.
    pub zstd_level: Option<u8>,
    /// Exact response payload supplied by the caller.
    pub raw: &'a [u8],
    /// Any forward-compatible bytes after fields understood by this codec.
    pub trailing: &'a [u8],
}

/// Borrowed fields used to encode a full client handshake response.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeResponseParams<'a> {
    /// Client capability mask.
    pub capabilities: CapabilityFlags,
    /// Maximum packet size advertised by the client.
    pub max_packet_size: u32,
    /// Client collation byte.
    pub collation: u8,
    /// Username bytes, without a NUL terminator.
    pub username: &'a [u8],
    /// Authentication response bytes.
    pub auth_response: &'a [u8],
    /// Initial database, without a NUL terminator.
    pub database: Option<&'a [u8]>,
    /// Authentication plugin name, without a NUL terminator.
    pub auth_plugin_name: Option<&'a [u8]>,
    /// Ordered connection attributes.
    pub attributes: Option<&'a [Attribute<'a>]>,
    /// Requested zstd compression level.
    pub zstd_level: Option<u8>,
}

/// A client connection-phase packet distinguished without losing raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHandshake<'a> {
    /// A 32-byte `SSLRequest` that must be followed by a TLS handshake.
    SslRequest(SslRequest<'a>),
    /// A full handshake response.
    Response(HandshakeResponse<'a>),
}

/// Decodes either an exact `SSLRequest` or a full handshake response.
///
/// # Errors
///
/// Returns the corresponding typed parser error.
pub fn decode_client_handshake(payload: &[u8]) -> Result<ClientHandshake<'_>, DecodeError> {
    let mut prefix = Cursor::new(payload);
    let capabilities =
        CapabilityFlags::from_bits_retain(prefix.read_u32_le("client capability flags")?);
    if payload.len() == HANDSHAKE_RESPONSE_FIXED_BYTES
        && capabilities.contains(CapabilityFlags::SSL)
    {
        return parse_ssl_request(payload).map(ClientHandshake::SslRequest);
    }
    parse_handshake_response(payload).map(ClientHandshake::Response)
}

/// Decodes a full client handshake response without allocating.
///
/// The historical Go compatibility form `0x01 0x00` under
/// `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` is treated as empty auth data.
///
/// # Errors
///
/// Returns a typed error for every truncated, overflowing, non-canonical, or
/// unterminated field.
pub fn parse_handshake_response(payload: &[u8]) -> Result<HandshakeResponse<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let capabilities =
        CapabilityFlags::from_bits_retain(cursor.read_u32_le("client capability flags")?);
    let max_packet_size = cursor.read_u32_le("client maximum packet size")?;
    let collation = cursor.read_u8("client collation")?;
    cursor.take(23, "handshake response reserved bytes")?;
    let username = cursor.read_nul_terminated("username")?;

    let auth_response = if capabilities.contains(CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA) {
        if cursor.remaining_bytes().starts_with(&[1, 0]) {
            cursor.take(2, "legacy empty auth response")?;
            &[][..]
        } else {
            let length_offset = cursor.position();
            let length = match cursor.read_length_encoded_int()? {
                LengthEncodedInt::Null => 0,
                LengthEncodedInt::Value(value) => {
                    usize::try_from(value).map_err(|_| DecodeError::LengthOverflow {
                        field: "authentication response",
                        offset: length_offset,
                        value,
                    })?
                }
            };
            take_declared(&mut cursor, length, "authentication response")?
        }
    } else if capabilities.contains(CapabilityFlags::SECURE_CONNECTION) {
        let length = usize::from(cursor.read_u8("authentication response length")?);
        take_declared(&mut cursor, length, "authentication response")?
    } else {
        cursor.read_nul_terminated("authentication response")?
    };

    let database = if capabilities.contains(CapabilityFlags::CONNECT_WITH_DB) {
        Some(cursor.read_nul_terminated("database")?)
    } else {
        None
    };
    let auth_plugin_name = if capabilities.contains(CapabilityFlags::PLUGIN_AUTH) {
        Some(cursor.read_nul_terminated("auth plugin name")?)
    } else {
        None
    };
    let attributes = if capabilities.contains(CapabilityFlags::CONNECT_ATTRS) {
        Some(
            read_prefixed_attributes(&mut cursor)?.ok_or(DecodeError::UnexpectedNull {
                field: "connection attributes",
                offset: cursor.position().saturating_sub(1),
            })?,
        )
    } else {
        None
    };
    let zstd_level = if capabilities.contains(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM) {
        Some(cursor.read_u8("zstd compression level")?)
    } else {
        None
    };
    let trailing = cursor.remaining_bytes();

    Ok(HandshakeResponse {
        capabilities,
        max_packet_size,
        collation,
        username,
        auth_response,
        database,
        auth_plugin_name,
        attributes,
        zstd_level,
        raw: payload,
        trailing,
    })
}

/// Encodes a full client handshake response.
///
/// # Errors
///
/// Returns a typed error for interior NULs, a secure-auth response above 255
/// bytes, a host length overflow, or an optional field supplied without its
/// capability bit.
pub fn encode_handshake_response(
    params: HandshakeResponseParams<'_>,
) -> Result<Vec<u8>, EncodeError> {
    validate_nul_free(params.username, "username")?;
    validate_optional_field(
        params.database,
        "database",
        params.capabilities,
        CapabilityFlags::CONNECT_WITH_DB,
    )?;
    validate_optional_field(
        params.auth_plugin_name,
        "auth plugin name",
        params.capabilities,
        CapabilityFlags::PLUGIN_AUTH,
    )?;
    if let Some(database) = params.database {
        validate_nul_free(database, "database")?;
    }
    if let Some(plugin) = params.auth_plugin_name {
        validate_nul_free(plugin, "auth plugin name")?;
    }
    if params.attributes.is_some() && !params.capabilities.contains(CapabilityFlags::CONNECT_ATTRS)
    {
        return Err(EncodeError::MissingCapability {
            field: "connection attributes",
            capability: CapabilityFlags::CONNECT_ATTRS.bits(),
        });
    }
    if params.zstd_level.is_some()
        && !params
            .capabilities
            .contains(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM)
    {
        return Err(EncodeError::MissingCapability {
            field: "zstd compression level",
            capability: CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits(),
        });
    }

    let mut output = Vec::with_capacity(
        HANDSHAKE_RESPONSE_FIXED_BYTES
            .saturating_add(params.username.len())
            .saturating_add(params.auth_response.len())
            .saturating_add(32),
    );
    output.extend_from_slice(&params.capabilities.bits().to_le_bytes());
    output.extend_from_slice(&params.max_packet_size.to_le_bytes());
    output.push(params.collation);
    output.extend_from_slice(&[0; 23]);
    output.extend_from_slice(params.username);
    output.push(0);

    if params
        .capabilities
        .contains(CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA)
    {
        let length =
            u64::try_from(params.auth_response.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "authentication response",
                length: params.auth_response.len(),
            })?;
        encode_length_encoded_int(length, &mut output);
        output.extend_from_slice(params.auth_response);
    } else if params
        .capabilities
        .contains(CapabilityFlags::SECURE_CONNECTION)
    {
        let length =
            u8::try_from(params.auth_response.len()).map_err(|_| EncodeError::ValueOutOfRange {
                field: "secure authentication response length",
                value: usize_to_u64_saturating(params.auth_response.len()),
                max: u64::from(u8::MAX),
            })?;
        output.push(length);
        output.extend_from_slice(params.auth_response);
    } else {
        validate_nul_free(params.auth_response, "authentication response")?;
        output.extend_from_slice(params.auth_response);
        output.push(0);
    }

    if params
        .capabilities
        .contains(CapabilityFlags::CONNECT_WITH_DB)
    {
        output.extend_from_slice(params.database.unwrap_or_default());
        output.push(0);
    }
    if params.capabilities.contains(CapabilityFlags::PLUGIN_AUTH) {
        output.extend_from_slice(params.auth_plugin_name.unwrap_or_default());
        output.push(0);
    }
    if params.capabilities.contains(CapabilityFlags::CONNECT_ATTRS) {
        encode_connection_attributes(params.attributes.unwrap_or_default(), &mut output)?;
    }
    if params
        .capabilities
        .contains(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM)
    {
        output.push(params.zstd_level.unwrap_or_default());
    }
    Ok(output)
}

/// A decoded `COM_CHANGE_USER` payload borrowing all variable-width fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeUser<'a> {
    /// New username bytes.
    pub username: &'a [u8],
    /// New authentication response bytes.
    pub auth_response: &'a [u8],
    /// New database bytes.
    pub database: &'a [u8],
    /// Optional two-byte character set.
    pub character_set: Option<u16>,
    /// Authentication plugin name when negotiated.
    pub auth_plugin_name: Option<&'a [u8]>,
    /// Validated ordered connection attributes when negotiated.
    pub attributes: Option<ConnectionAttributes<'a>>,
    /// Exact command payload supplied by the caller.
    pub raw: &'a [u8],
    /// Any forward-compatible bytes after fields understood by this codec.
    pub trailing: &'a [u8],
}

/// Borrowed fields used to encode `COM_CHANGE_USER`.
#[derive(Debug, Clone, Copy)]
pub struct ChangeUserParams<'a> {
    /// New username bytes, without a NUL terminator.
    pub username: &'a [u8],
    /// New authentication response bytes.
    pub auth_response: &'a [u8],
    /// New database bytes, without a NUL terminator.
    pub database: &'a [u8],
    /// Optional two-byte character set.
    pub character_set: Option<u16>,
    /// Authentication plugin name, without a NUL terminator.
    pub auth_plugin_name: Option<&'a [u8]>,
    /// Ordered connection attributes.
    pub attributes: Option<&'a [Attribute<'a>]>,
}

/// Decodes `COM_CHANGE_USER` using the negotiated capabilities.
///
/// The character-set tail is optional to preserve the legacy Go behavior, but
/// once any tail byte is present every negotiated field must be complete.
///
/// # Errors
///
/// Returns a typed error for a wrong/empty command, truncation, overflow,
/// non-canonical attribute length, or missing terminator.
pub fn parse_change_user(
    payload: &[u8],
    capabilities: CapabilityFlags,
) -> Result<ChangeUser<'_>, DecodeError> {
    let mut cursor = Cursor::new(payload);
    let actual = cursor.read_u8("COM_CHANGE_USER command").ok();
    if actual != Some(CommandCode::CHANGE_USER.as_byte()) {
        return Err(DecodeError::UnexpectedCommand {
            expected: CommandCode::CHANGE_USER.as_byte(),
            actual,
        });
    }
    let username = cursor.read_nul_terminated("change-user username")?;
    let auth_response = if capabilities.contains(CapabilityFlags::SECURE_CONNECTION) {
        let length = usize::from(cursor.read_u8("change-user auth response length")?);
        take_declared(&mut cursor, length, "change-user auth response")?
    } else {
        cursor.read_nul_terminated("change-user auth response")?
    };
    let database = cursor.read_nul_terminated("change-user database")?;
    if cursor.is_empty() {
        return Ok(ChangeUser {
            username,
            auth_response,
            database,
            character_set: None,
            auth_plugin_name: None,
            attributes: None,
            raw: payload,
            trailing: &[],
        });
    }
    let character_set = Some(cursor.read_u16_le("change-user character set")?);
    let auth_plugin_name = if capabilities.contains(CapabilityFlags::PLUGIN_AUTH) {
        Some(cursor.read_nul_terminated("change-user auth plugin name")?)
    } else {
        None
    };
    let attributes = if capabilities.contains(CapabilityFlags::CONNECT_ATTRS) {
        Some(
            read_prefixed_attributes(&mut cursor)?.ok_or(DecodeError::UnexpectedNull {
                field: "change-user connection attributes",
                offset: cursor.position().saturating_sub(1),
            })?,
        )
    } else {
        None
    };
    let trailing = cursor.remaining_bytes();
    Ok(ChangeUser {
        username,
        auth_response,
        database,
        character_set,
        auth_plugin_name,
        attributes,
        raw: payload,
        trailing,
    })
}

/// Encodes `COM_CHANGE_USER` using the negotiated capabilities.
///
/// # Errors
///
/// Returns a typed error for interior NULs, a secure-auth response above 255
/// bytes, optional tail fields without a character set, or a missing capability.
pub fn encode_change_user(
    params: ChangeUserParams<'_>,
    capabilities: CapabilityFlags,
) -> Result<Vec<u8>, EncodeError> {
    validate_nul_free(params.username, "change-user username")?;
    validate_nul_free(params.database, "change-user database")?;
    validate_optional_field(
        params.auth_plugin_name,
        "change-user auth plugin name",
        capabilities,
        CapabilityFlags::PLUGIN_AUTH,
    )?;
    if let Some(plugin) = params.auth_plugin_name {
        validate_nul_free(plugin, "change-user auth plugin name")?;
    }
    if params.attributes.is_some() && !capabilities.contains(CapabilityFlags::CONNECT_ATTRS) {
        return Err(EncodeError::MissingCapability {
            field: "change-user connection attributes",
            capability: CapabilityFlags::CONNECT_ATTRS.bits(),
        });
    }
    if params.character_set.is_none()
        && (params.auth_plugin_name.is_some() || params.attributes.is_some())
    {
        return Err(EncodeError::InvalidFieldLength {
            field: "change-user character set before optional fields",
            length: 0,
            expected: 2,
        });
    }

    let mut output = Vec::with_capacity(
        8_usize
            .saturating_add(params.username.len())
            .saturating_add(params.auth_response.len())
            .saturating_add(params.database.len()),
    );
    output.push(CommandCode::CHANGE_USER.as_byte());
    output.extend_from_slice(params.username);
    output.push(0);
    if capabilities.contains(CapabilityFlags::SECURE_CONNECTION) {
        let length =
            u8::try_from(params.auth_response.len()).map_err(|_| EncodeError::ValueOutOfRange {
                field: "change-user secure auth response length",
                value: usize_to_u64_saturating(params.auth_response.len()),
                max: u64::from(u8::MAX),
            })?;
        output.push(length);
        output.extend_from_slice(params.auth_response);
    } else {
        validate_nul_free(params.auth_response, "change-user auth response")?;
        output.extend_from_slice(params.auth_response);
        output.push(0);
    }
    output.extend_from_slice(params.database);
    output.push(0);
    if let Some(character_set) = params.character_set {
        output.extend_from_slice(&character_set.to_le_bytes());
        if capabilities.contains(CapabilityFlags::PLUGIN_AUTH) {
            output.extend_from_slice(params.auth_plugin_name.unwrap_or_default());
            output.push(0);
        }
        if capabilities.contains(CapabilityFlags::CONNECT_ATTRS) {
            encode_connection_attributes(params.attributes.unwrap_or_default(), &mut output)?;
        }
    }
    Ok(output)
}

fn take_declared<'a>(
    cursor: &mut Cursor<'a>,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], DecodeError> {
    let remaining = cursor.remaining();
    if length > remaining {
        return Err(DecodeError::LengthExceedsInput {
            field,
            offset: cursor.position(),
            declared: length,
            remaining,
        });
    }
    cursor.take(length, field)
}

fn validate_nul_free(value: &[u8], field: &'static str) -> Result<(), EncodeError> {
    if let Some(index) = value.iter().position(|byte| *byte == 0) {
        return Err(EncodeError::InteriorNul { field, index });
    }
    Ok(())
}

fn validate_optional_field(
    value: Option<&[u8]>,
    field: &'static str,
    capabilities: CapabilityFlags,
    required: CapabilityFlags,
) -> Result<(), EncodeError> {
    if value.is_some() && !capabilities.contains(required) {
        return Err(EncodeError::MissingCapability {
            field,
            capability: required.bits(),
        });
    }
    Ok(())
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_CAPS: CapabilityFlags = CapabilityFlags::PROTOCOL_41
        .union(CapabilityFlags::SECURE_CONNECTION)
        .union(CapabilityFlags::PLUGIN_AUTH)
        .union(CapabilityFlags::CONNECT_WITH_DB)
        .union(CapabilityFlags::CONNECT_ATTRS);

    #[test]
    fn initial_handshake_round_trip_and_borrowing() -> Result<(), Box<dyn std::error::Error>> {
        let salt = *b"1234567890abcdefghij";
        let params = InitialHandshakeParams {
            server_version: b"8.0.11-TiDB",
            connection_id: 42,
            auth_plugin_data: &salt,
            capabilities: CLIENT_CAPS,
            collation: 45,
            status: StatusFlags::AUTOCOMMIT,
            auth_plugin_name: b"mysql_native_password",
        };
        let encoded = encode_initial_handshake(params)?;
        let parsed = parse_initial_handshake(&encoded)?;
        assert_eq!(parsed.server_version, b"8.0.11-TiDB");
        assert_eq!(parsed.connection_id, 42);
        assert_eq!(parsed.auth_plugin_data_part_1, b"12345678");
        assert!(parsed.auth_plugin_data_part_1.as_ptr() >= encoded.as_ptr());
        assert_eq!(parsed.auth_plugin_data_part_2, b"90abcdefghij");
        assert_eq!(parsed.auth_plugin_name, Some(&b"mysql_native_password"[..]));
        assert!(parsed.trailing.is_empty());
        Ok(())
    }

    #[test]
    fn handshake_response_round_trip_borrows_fields() -> Result<(), Box<dyn std::error::Error>> {
        let attributes = [Attribute {
            key: b"_client_name",
            value: b"tiproxy-corpus",
        }];
        let params = HandshakeResponseParams {
            capabilities: CLIENT_CAPS,
            max_packet_size: 1024,
            collation: 45,
            username: b"corpus_user",
            auth_response: &[1, 2, 3, 4],
            database: Some(b"corpus_db"),
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: Some(&attributes),
            zstd_level: None,
        };
        let encoded = encode_handshake_response(params)?;
        let parsed = parse_handshake_response(&encoded)?;
        assert_eq!(parsed.username, b"corpus_user");
        assert_eq!(parsed.auth_response, &[1, 2, 3, 4]);
        assert_eq!(parsed.database, Some(&b"corpus_db"[..]));
        let attributes = parsed.attributes.ok_or(DecodeError::UnexpectedNull {
            field: "connection attributes",
            offset: 0,
        })?;
        let decoded: Result<Vec<_>, _> = attributes.iter().collect();
        assert_eq!(decoded, Ok(attributes_from(params.attributes)));
        assert!(parsed.trailing.is_empty());
        Ok(())
    }

    fn attributes_from<'a>(attributes: Option<&'a [Attribute<'a>]>) -> Vec<Attribute<'a>> {
        match attributes {
            Some(attributes) => attributes.to_vec(),
            None => Vec::new(),
        }
    }

    #[test]
    fn ssl_request_requires_exact_length_and_flag() {
        let mut request = [0_u8; HANDSHAKE_RESPONSE_FIXED_BYTES];
        request[..4].copy_from_slice(&(CLIENT_CAPS | CapabilityFlags::SSL).bits().to_le_bytes());
        request[8] = 45;
        assert!(parse_ssl_request(&request).is_ok());
        assert!(matches!(
            parse_ssl_request(&request[..31]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
        let mut extra = request.to_vec();
        extra.push(0);
        assert!(matches!(
            parse_ssl_request(&extra),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn ssl_request_encode_round_trips_through_parse() -> Result<(), Box<dyn std::error::Error>> {
        let capabilities = CLIENT_CAPS | CapabilityFlags::SSL;
        let encoded = encode_ssl_request(capabilities, 0x0100_0000, 45);
        assert_eq!(encoded.len(), SSL_REQUEST_BYTES);
        // The 23 reserved bytes are zero.
        assert_eq!(encoded[9..], [0_u8; 23]);
        let parsed = parse_ssl_request(&encoded)?;
        assert_eq!(parsed.capabilities, capabilities);
        assert_eq!(parsed.max_packet_size, 0x0100_0000);
        assert_eq!(parsed.collation, 45);
        assert!(parsed.capabilities.contains(CapabilityFlags::SSL));
        Ok(())
    }

    #[test]
    fn change_user_round_trip_and_truncation() -> Result<(), Box<dyn std::error::Error>> {
        let attributes = [Attribute {
            key: b"program_name",
            value: b"mysql",
        }];
        let params = ChangeUserParams {
            username: b"next_user",
            auth_response: &[1, 3, 3, 7],
            database: b"next_db",
            character_set: Some(45),
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: Some(&attributes),
        };
        let encoded = encode_change_user(params, CLIENT_CAPS)?;
        let parsed = parse_change_user(&encoded, CLIENT_CAPS)?;
        assert_eq!(parsed.username, b"next_user");
        assert_eq!(parsed.auth_response, &[1, 3, 3, 7]);
        assert_eq!(parsed.database, b"next_db");
        assert_eq!(parsed.character_set, Some(45));
        for length in 0..encoded.len() {
            let result = parse_change_user(&encoded[..length], CLIENT_CAPS);
            if length
                == 1 + params.username.len()
                    + 1
                    + 1
                    + params.auth_response.len()
                    + params.database.len()
                    + 1
            {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn hostile_handshake_prefixes_never_panic() -> Result<(), EncodeError> {
        let params = HandshakeResponseParams {
            capabilities: CLIENT_CAPS | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM,
            max_packet_size: u32::MAX,
            collation: 45,
            username: b"user",
            auth_response: b"auth",
            database: Some(b"db"),
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: Some(&[]),
            zstd_level: Some(3),
        };
        let encoded = encode_handshake_response(params)?;
        for length in 0..encoded.len() {
            assert!(parse_handshake_response(&encoded[..length]).is_err());
        }

        let mut state = 0x4841_4e44_5348_414b_u64;
        for length in 0..512_usize {
            let mut bytes = vec![0_u8; length];
            for byte in &mut bytes {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = state.to_le_bytes()[3];
            }
            let _ = parse_handshake_response(&bytes);
            let _ = parse_initial_handshake(&bytes);
            let state_bytes = state.to_le_bytes();
            let capability_bits = u32::from_le_bytes([
                state_bytes[0],
                state_bytes[1],
                state_bytes[2],
                state_bytes[3],
            ]);
            let _ = parse_change_user(&bytes, CapabilityFlags::from_bits_retain(capability_bits));
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_database_and_null_attributes() -> Result<(), EncodeError> {
        let database_only = HandshakeResponseParams {
            capabilities: CapabilityFlags::PROTOCOL_41
                | CapabilityFlags::SECURE_CONNECTION
                | CapabilityFlags::CONNECT_WITH_DB,
            max_packet_size: 1024,
            collation: 45,
            username: b"user",
            auth_response: b"auth",
            database: Some(b"db"),
            auth_plugin_name: None,
            attributes: None,
            zstd_level: None,
        };
        let encoded = encode_handshake_response(database_only)?;
        let missing_database =
            &encoded[..encoded.len() - database_only.database.unwrap_or_default().len() - 1];
        assert!(matches!(
            parse_handshake_response(missing_database),
            Err(DecodeError::MissingNul {
                field: "database",
                ..
            })
        ));

        let attributes_only = HandshakeResponseParams {
            capabilities: CapabilityFlags::PROTOCOL_41
                | CapabilityFlags::SECURE_CONNECTION
                | CapabilityFlags::CONNECT_ATTRS,
            database: None,
            ..database_only
        };
        let mut encoded = encode_handshake_response(attributes_only)?;
        let attribute_length = encoded.last_mut().ok_or(EncodeError::LengthOverflow {
            field: "handshake response",
            length: 0,
        })?;
        *attribute_length = 0xfb;
        assert!(matches!(
            parse_handshake_response(&encoded),
            Err(DecodeError::UnexpectedNull {
                field: "connection attributes",
                ..
            })
        ));
        Ok(())
    }
}
