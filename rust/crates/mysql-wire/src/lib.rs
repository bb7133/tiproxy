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

//! Runtime-independent `MySQL` wire-format primitives for the `TiProxy` Rust dataplane.
//!
//! Parsers in this crate are *sans I/O*: callers provide a complete byte slice and
//! retain ownership of it. Successfully decoded packet fields borrow directly from
//! that slice, so inspecting normal packets does not allocate or copy payload data.
//! Encoders allocate only their returned buffer (or append to a caller-owned buffer).
//!
//! This crate deliberately does not own sockets, buffering, TLS, compression,
//! routing, or session state. Physical/logical message streaming belongs to the
//! `proxy-io` boundary layered on top of these primitives.

#![forbid(unsafe_code)]

mod attributes;
mod constants;
mod error;
mod handshake;
mod packet;
mod prepared;
mod primitives;
mod response;

pub mod limits;

pub use attributes::{
    Attribute, AttributeIter, ConnectionAttributes, encode_connection_attributes,
};
pub use constants::{CapabilityFlags, CommandCode, ResponseHeader, StatusFlags};
pub use error::{DecodeError, EncodeError};
pub use handshake::{
    ChangeUser, ChangeUserParams, ClientHandshake, HandshakeResponse, HandshakeResponseParams,
    InitialHandshake, InitialHandshakeParams, SSL_REQUEST_BYTES, SslRequest,
    decode_client_handshake, encode_change_user, encode_handshake_response,
    encode_initial_handshake, encode_ssl_request, parse_change_user, parse_handshake_response,
    parse_initial_handshake, parse_ssl_request,
};
pub use packet::{
    CommandPacket, LogicalPacketFragments, PHYSICAL_PACKET_HEADER_LEN, PacketHeader,
    PhysicalPacket, SequenceObservation, SequenceTracker, encode_command_packet,
    encode_physical_packet, physical_packet_count,
};
pub use prepared::{
    ColumnType, ExecuteParameter, ParameterType, ParameterValue, PrepareOk, PrepareOkParams,
    PreparedDecodeError, PreparedEncodeError, StatementCommand, StmtExecute, StmtExecuteParams,
    StmtFetch, StmtSendLongData, decode_prepare_ok, decode_statement_command, decode_stmt_execute,
    decode_stmt_fetch, decode_stmt_prepare, decode_stmt_send_long_data, encode_prepare_ok,
    encode_statement_command, encode_stmt_execute, encode_stmt_fetch, encode_stmt_prepare,
    encode_stmt_send_long_data,
};
pub use primitives::{
    Cursor, LengthEncodedInt, MAX_PAYLOAD_LEN, decode_length_encoded_bytes,
    decode_length_encoded_int, encode_length_encoded_bytes, encode_length_encoded_int,
    encode_u24_le, length_encoded_int_size,
};
pub use response::{
    EofPacket, ErrorPacket, OkPacket, ResponseKind, classify_response, encode_eof_packet,
    encode_error_packet, encode_ok_packet, parse_eof_packet, parse_error_packet, parse_ok_packet,
};

/// Stable description used by workspace-level topology checks.
pub const CRATE_ROLE: &str = "mysql wire-format types and codecs";
