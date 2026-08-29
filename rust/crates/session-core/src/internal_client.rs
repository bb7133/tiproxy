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

//! Restricted internal `MySQL` query construction and result parsing (SES-08).
//!
//! This module is the only full text-result parser in `session-core`. It is
//! deliberately separate from [`crate::response`], whose ordinary user-query
//! hot path retains only a bounded 23-byte prefix and streams every row without
//! materializing it. The runtime may instantiate this parser only for an
//! [`InternalQuery`]; no raw-SQL constructor exists.
//!
//! Callers supply one complete logical response payload at a time. Physical
//! framing, compression, TLS, buffering, and sockets remain transport-owned.
//! Every retained column and cell is bounded by [`InternalLimits`].

use core::fmt;

use mysql_wire::{
    CapabilityFlags, CommandCode, Cursor, DecodeError, LengthEncodedInt, ResponseHeader,
    ResponseKind, StatusFlags, classify_response, encode_command_packet, parse_eof_packet,
    parse_error_packet, parse_ok_packet,
};
use zeroize::Zeroize;

const SHOW_SESSION_STATES: &[u8] = b"SHOW SESSION_STATES";
const SET_SESSION_STATES_PREFIX: &[u8] = b"SET SESSION_STATES '";
const COMMIT: &[u8] = b"COMMIT";
const SESSION_STATES_COLUMN: &[u8] = b"Session_states";
const SESSION_TOKEN_COLUMN: &[u8] = b"Session_token";

/// Default maximum bytes in one encoded internal `COM_QUERY`, including its
/// command byte.
pub const DEFAULT_MAX_INTERNAL_QUERY_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum aggregate logical-payload bytes in one internal response.
pub const DEFAULT_MAX_INTERNAL_RESULT_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum result-set column count.
pub const DEFAULT_MAX_INTERNAL_COLUMNS: usize = 64;
/// Default maximum result-set row count.
pub const DEFAULT_MAX_INTERNAL_ROWS: usize = 16;
/// Default maximum bytes retained for one column name.
pub const DEFAULT_MAX_INTERNAL_COLUMN_NAME_BYTES: usize = 256;
/// Default maximum bytes retained for one non-NULL text cell.
pub const DEFAULT_MAX_INTERNAL_CELL_BYTES: usize = 8 * 1024 * 1024;

/// Finite allocation and protocol-complexity limits for the internal client.
///
/// All fields must be nonzero. Custom limits remain per-parser hard bounds;
/// there is no unbounded constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalLimits {
    /// Maximum encoded request bytes, including `COM_QUERY`.
    pub max_query_bytes: usize,
    /// Maximum aggregate response logical-payload bytes.
    pub max_result_bytes: usize,
    /// Maximum declared result-set columns.
    pub max_columns: usize,
    /// Maximum parsed result-set rows.
    pub max_rows: usize,
    /// Maximum bytes in one retained column name.
    pub max_column_name_bytes: usize,
    /// Maximum bytes in one retained non-NULL cell.
    pub max_cell_bytes: usize,
}

impl Default for InternalLimits {
    fn default() -> Self {
        Self {
            max_query_bytes: DEFAULT_MAX_INTERNAL_QUERY_BYTES,
            max_result_bytes: DEFAULT_MAX_INTERNAL_RESULT_BYTES,
            max_columns: DEFAULT_MAX_INTERNAL_COLUMNS,
            max_rows: DEFAULT_MAX_INTERNAL_ROWS,
            max_column_name_bytes: DEFAULT_MAX_INTERNAL_COLUMN_NAME_BYTES,
            max_cell_bytes: DEFAULT_MAX_INTERNAL_CELL_BYTES,
        }
    }
}

impl InternalLimits {
    fn validate(self) -> Result<Self, InternalClientError> {
        for (field, value) in [
            ("max_query_bytes", self.max_query_bytes),
            ("max_result_bytes", self.max_result_bytes),
            ("max_columns", self.max_columns),
            ("max_rows", self.max_rows),
            ("max_column_name_bytes", self.max_column_name_bytes),
            ("max_cell_bytes", self.max_cell_bytes),
        ] {
            if value == 0 {
                return Err(InternalClientError::InvalidLimit { field });
            }
        }
        Ok(self)
    }
}

/// Fixed internal query kinds accepted by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalQueryKind {
    /// Read the migration JSON and signed session token.
    ShowSessionStates,
    /// Restore previously captured session state.
    SetSessionStates,
    /// Commit the old backend before replaying a held transaction opener.
    Commit,
}

/// The complete allowlist of SQL that the Rust dataplane may issue internally.
///
/// There is intentionally no arbitrary query/string variant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InternalQuery<'a> {
    /// `SHOW SESSION_STATES`.
    ShowSessionStates,
    /// `SET SESSION_STATES '<escaped-state>'`.
    SetSessionStates(&'a str),
    /// `COMMIT` used by the held-request migration path.
    Commit,
}

impl fmt::Debug for InternalQuery<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShowSessionStates => formatter.write_str("ShowSessionStates"),
            Self::SetSessionStates(state) => formatter
                .debug_struct("SetSessionStates")
                .field("state_bytes", &state.len())
                .finish(),
            Self::Commit => formatter.write_str("Commit"),
        }
    }
}

impl InternalQuery<'_> {
    /// Returns the payload-free kind used to select the response contract.
    #[must_use]
    pub const fn kind(self) -> InternalQueryKind {
        match self {
            Self::ShowSessionStates => InternalQueryKind::ShowSessionStates,
            Self::SetSessionStates(_) => InternalQueryKind::SetSessionStates,
            Self::Commit => InternalQueryKind::Commit,
        }
    }

    /// Encodes the allowlisted request as one logical `COM_QUERY` payload.
    ///
    /// Session state escaping is byte-for-byte compatible with Go `TiProxy`:
    /// backslashes are doubled first and single quotes become `\'`. The
    /// returned payload still needs physical framing by the transport.
    ///
    /// # Errors
    ///
    /// Returns a typed limit error before allocating an oversized request, or
    /// an invalid-limit error when any configured bound is zero.
    pub fn encode(self, limits: InternalLimits) -> Result<Vec<u8>, InternalClientError> {
        let limits = limits.validate()?;
        match self {
            Self::ShowSessionStates => encode_static_query(SHOW_SESSION_STATES, limits),
            Self::Commit => encode_static_query(COMMIT, limits),
            Self::SetSessionStates(state) => encode_set_session_states(state, limits),
        }
    }

    /// Builds the response parser for this exact allowlisted request.
    ///
    /// # Errors
    ///
    /// Returns an invalid-limit error when any configured bound is zero.
    pub fn parser(
        self,
        capabilities: CapabilityFlags,
        limits: InternalLimits,
    ) -> Result<InternalResultParser, InternalClientError> {
        InternalResultParser::new(self.kind(), capabilities, limits)
    }
}

fn encode_static_query(sql: &[u8], limits: InternalLimits) -> Result<Vec<u8>, InternalClientError> {
    let actual = sql
        .len()
        .checked_add(1)
        .ok_or(InternalClientError::CounterOverflow {
            field: "encoded query bytes",
        })?;
    if actual > limits.max_query_bytes {
        return Err(InternalClientError::QueryTooLarge {
            actual,
            limit: limits.max_query_bytes,
        });
    }
    Ok(encode_command_packet(CommandCode::QUERY, sql))
}

fn encode_set_session_states(
    state: &str,
    limits: InternalLimits,
) -> Result<Vec<u8>, InternalClientError> {
    let escaped_extra = state
        .as_bytes()
        .iter()
        .filter(|byte| matches!(byte, b'\\' | b'\''))
        .count();
    let sql_bytes = SET_SESSION_STATES_PREFIX
        .len()
        .checked_add(state.len())
        .and_then(|value| value.checked_add(escaped_extra))
        .and_then(|value| value.checked_add(1))
        .ok_or(InternalClientError::CounterOverflow {
            field: "escaped session-state query bytes",
        })?;
    let actual = sql_bytes
        .checked_add(1)
        .ok_or(InternalClientError::CounterOverflow {
            field: "encoded query bytes",
        })?;
    if actual > limits.max_query_bytes {
        return Err(InternalClientError::QueryTooLarge {
            actual,
            limit: limits.max_query_bytes,
        });
    }

    let mut payload = Vec::with_capacity(actual);
    payload.push(CommandCode::QUERY.as_byte());
    payload.extend_from_slice(SET_SESSION_STATES_PREFIX);
    for byte in state.bytes() {
        if matches!(byte, b'\\' | b'\'') {
            payload.push(b'\\');
        }
        payload.push(byte);
    }
    payload.push(b'\'');
    Ok(payload)
}

/// Structured OK result for `SET SESSION_STATES` or internal `COMMIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalOk {
    /// Backend affected-row count.
    pub affected_rows: u64,
    /// Backend last-insert identifier.
    pub last_insert_id: u64,
    /// Terminal server status.
    pub status: StatusFlags,
    /// Backend warning count.
    pub warnings: u16,
}

/// Captured migration state from `SHOW SESSION_STATES`.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionStateSnapshot {
    session_states: String,
    session_token: String,
    current_database: Option<String>,
    status: StatusFlags,
    warnings: u16,
}

impl SessionStateSnapshot {
    /// Sanitized session JSON returned by `TiDB`.
    #[must_use]
    pub fn session_states(&self) -> &str {
        &self.session_states
    }

    /// Nonempty signed token used by the second backend handshake.
    #[must_use]
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    /// Authoritative current database decoded from the session JSON.
    ///
    /// `TiDB` omits `current-db` when no database is selected. An empty
    /// string is normalized to the same state so callers never preserve a
    /// stale locally tracked database across migration.
    #[must_use]
    pub fn current_database(&self) -> Option<&str> {
        self.current_database.as_deref()
    }

    /// Terminal result-set status.
    #[must_use]
    pub const fn status(&self) -> StatusFlags {
        self.status
    }

    /// Terminal result-set warning count.
    #[must_use]
    pub const fn warnings(&self) -> u16 {
        self.warnings
    }
}

impl fmt::Debug for SessionStateSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionStateSnapshot")
            .field("session_states_bytes", &self.session_states.len())
            .field("session_token_bytes", &self.session_token.len())
            .field(
                "current_database_bytes",
                &self.current_database.as_ref().map_or(0, String::len),
            )
            .field("status", &self.status)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Drop for SessionStateSnapshot {
    fn drop(&mut self) {
        self.session_states.zeroize();
        self.session_token.zeroize();
        if let Some(current_database) = self.current_database.as_mut() {
            current_database.zeroize();
        }
    }
}

/// Completed result of one allowlisted internal query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalResult {
    /// `SET SESSION_STATES` or `COMMIT` completed with OK.
    Ok(InternalOk),
    /// `SHOW SESSION_STATES` produced the required state and token.
    SessionStates(SessionStateSnapshot),
}

/// Incremental result after consuming one complete logical payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalProgress {
    /// More backend logical packets are required.
    Continue,
    /// The single internal response completed successfully.
    Complete(InternalResult),
}

/// Current phase of the restricted response parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalParserState {
    /// Waiting for the first OK, ERR, or result-set header.
    Start,
    /// Reading the declared number of column definitions.
    Columns {
        /// Definitions still expected, including the next packet.
        remaining: usize,
    },
    /// Waiting for the optional metadata EOF after all definitions.
    ///
    /// Classic mode requires it. With `CLIENT_DEPRECATE_EOF`, the parser also
    /// accepts the first row directly, while tolerating the classic EOF emitted
    /// by older `TiDB` versions and frozen in the Go parity corpus.
    MetadataEnd,
    /// Reading text rows through the mode-specific final terminator.
    Rows,
    /// A successful result or backend ERR ended the response.
    Complete,
    /// Malformed input or a limit violation poisoned the parser.
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
struct TextResult {
    columns: Vec<Vec<u8>>,
    rows: Vec<Vec<Option<Vec<u8>>>>,
}

impl fmt::Debug for TextResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TextResult")
            .field("columns", &self.columns.len())
            .field("rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}

impl TextResult {
    fn value_by_name(
        &self,
        row: usize,
        name: &'static [u8],
        display_name: &'static str,
    ) -> Result<Option<&[u8]>, InternalClientError> {
        let column = self
            .columns
            .iter()
            .position(|column| column.as_slice() == name)
            .ok_or(InternalClientError::MissingColumn { name: display_name })?;
        let values = self
            .rows
            .get(row)
            .ok_or(InternalClientError::UnexpectedRowCount {
                actual: self.rows.len(),
                expected: 1,
            })?;
        Ok(values.get(column).and_then(Option::as_deref))
    }
}

/// Bounded, sans-I/O parser for one allowlisted internal query response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalResultParser {
    query: InternalQueryKind,
    capabilities: CapabilityFlags,
    limits: InternalLimits,
    state: InternalParserState,
    total_bytes: usize,
    result: TextResult,
}

impl InternalResultParser {
    /// Starts an empty parser for a fixed query kind and negotiated capability
    /// set.
    ///
    /// # Errors
    ///
    /// Returns an invalid-limit error when any bound is zero.
    pub fn new(
        query: InternalQueryKind,
        capabilities: CapabilityFlags,
        limits: InternalLimits,
    ) -> Result<Self, InternalClientError> {
        Ok(Self {
            query,
            capabilities,
            limits: limits.validate()?,
            state: InternalParserState::Start,
            total_bytes: 0,
            result: TextResult {
                columns: Vec::new(),
                rows: Vec::new(),
            },
        })
    }

    /// Current parser phase.
    #[must_use]
    pub const fn state(&self) -> InternalParserState {
        self.state
    }

    /// Aggregate logical-payload bytes accepted so far.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Consumes one complete backend logical payload.
    ///
    /// Any error poisons the parser. A backend ERR is terminal and is returned
    /// as [`InternalClientError::BackendError`] without retaining its message.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol, backend, terminal-state, or limit error.
    pub fn consume(&mut self, payload: &[u8]) -> Result<InternalProgress, InternalClientError> {
        if matches!(
            self.state,
            InternalParserState::Complete | InternalParserState::Failed
        ) {
            return Err(InternalClientError::AlreadyTerminal { state: self.state });
        }
        let total_bytes = self.total_bytes.checked_add(payload.len()).ok_or(
            InternalClientError::CounterOverflow {
                field: "internal result bytes",
            },
        )?;
        if total_bytes > self.limits.max_result_bytes {
            self.state = InternalParserState::Failed;
            return Err(InternalClientError::ResultTooLarge {
                actual: total_bytes,
                limit: self.limits.max_result_bytes,
            });
        }
        self.total_bytes = total_bytes;

        let result = self.consume_inner(payload);
        if result.is_err() && self.state != InternalParserState::Complete {
            self.state = InternalParserState::Failed;
        }
        result
    }

    fn consume_inner(&mut self, payload: &[u8]) -> Result<InternalProgress, InternalClientError> {
        if payload.first() == Some(&ResponseHeader::ERROR.as_byte()) {
            return self.backend_error(payload);
        }
        match self.state {
            InternalParserState::Start => self.consume_start(payload),
            InternalParserState::Columns { remaining } => self.consume_column(payload, remaining),
            InternalParserState::MetadataEnd => self.consume_metadata_end(payload),
            InternalParserState::Rows => self.consume_row_or_end(payload),
            InternalParserState::Complete | InternalParserState::Failed => {
                Err(InternalClientError::AlreadyTerminal { state: self.state })
            }
        }
    }

    fn consume_start(&mut self, payload: &[u8]) -> Result<InternalProgress, InternalClientError> {
        match classify_response(payload)? {
            ResponseKind::Error => self.backend_error(payload),
            ResponseKind::Ok => self.consume_ok(payload),
            ResponseKind::LocalInfile => Err(InternalClientError::LocalInfileRejected),
            ResponseKind::Other if self.query == InternalQueryKind::ShowSessionStates => {
                self.consume_column_count(payload)
            }
            kind => Err(InternalClientError::UnexpectedResponse {
                query: self.query,
                state: self.state,
                kind,
            }),
        }
    }

    fn consume_ok(&mut self, payload: &[u8]) -> Result<InternalProgress, InternalClientError> {
        if self.query == InternalQueryKind::ShowSessionStates {
            return Err(InternalClientError::UnexpectedResponse {
                query: self.query,
                state: self.state,
                kind: ResponseKind::Ok,
            });
        }
        let packet = parse_ok_packet(payload, self.capabilities)?;
        reject_more_results(packet.status)?;
        self.state = InternalParserState::Complete;
        Ok(InternalProgress::Complete(InternalResult::Ok(InternalOk {
            affected_rows: packet.affected_rows,
            last_insert_id: packet.last_insert_id,
            status: packet.status,
            warnings: packet.warnings,
        })))
    }

    fn consume_column_count(
        &mut self,
        payload: &[u8],
    ) -> Result<InternalProgress, InternalClientError> {
        let mut cursor = Cursor::new(payload);
        let count = match cursor.read_length_encoded_int()? {
            LengthEncodedInt::Null => {
                return Err(InternalClientError::MalformedStructure {
                    field: "result-set column count is NULL",
                });
            }
            LengthEncodedInt::Value(value) => {
                usize::try_from(value).map_err(|_| InternalClientError::CountOverflow {
                    field: "result-set column count",
                    value,
                })?
            }
        };
        if !cursor.is_empty() {
            return Err(InternalClientError::MalformedStructure {
                field: "result-set column count has trailing bytes",
            });
        }
        if count == 0 {
            return Err(InternalClientError::MalformedStructure {
                field: "result-set column count is zero",
            });
        }
        if count > self.limits.max_columns {
            return Err(InternalClientError::TooManyColumns {
                actual: count,
                limit: self.limits.max_columns,
            });
        }
        self.result.columns.reserve(count);
        self.state = InternalParserState::Columns { remaining: count };
        Ok(InternalProgress::Continue)
    }

    fn consume_column(
        &mut self,
        payload: &[u8],
        remaining: usize,
    ) -> Result<InternalProgress, InternalClientError> {
        let name = parse_column_name(payload)?;
        if name.len() > self.limits.max_column_name_bytes {
            return Err(InternalClientError::ColumnNameTooLarge {
                column: self.result.columns.len(),
                actual: name.len(),
                limit: self.limits.max_column_name_bytes,
            });
        }
        if let Some(first) = self
            .result
            .columns
            .iter()
            .position(|column| column.as_slice() == name)
        {
            return Err(InternalClientError::DuplicateColumn {
                first,
                duplicate: self.result.columns.len(),
            });
        }
        self.result.columns.push(name.to_vec());
        let next = remaining
            .checked_sub(1)
            .ok_or(InternalClientError::CounterOverflow {
                field: "remaining column definitions",
            })?;
        self.state = if next == 0 {
            InternalParserState::MetadataEnd
        } else {
            InternalParserState::Columns { remaining: next }
        };
        Ok(InternalProgress::Continue)
    }

    fn consume_metadata_end(
        &mut self,
        payload: &[u8],
    ) -> Result<InternalProgress, InternalClientError> {
        let kind = classify_response(payload)?;
        if kind == ResponseKind::Eof {
            let _ = parse_eof_packet(payload)?;
            self.state = InternalParserState::Rows;
            return Ok(InternalProgress::Continue);
        }
        if self.capabilities.contains(CapabilityFlags::DEPRECATE_EOF) {
            self.state = InternalParserState::Rows;
            return self.consume_row_or_end(payload);
        }
        Err(InternalClientError::UnexpectedResponse {
            query: self.query,
            state: self.state,
            kind,
        })
    }

    fn consume_row_or_end(
        &mut self,
        payload: &[u8],
    ) -> Result<InternalProgress, InternalClientError> {
        let first = payload.first().copied();
        if first == Some(ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte()) {
            match classify_response(payload)? {
                ResponseKind::Eof => {
                    let packet = parse_eof_packet(payload)?;
                    return self.finish_resultset(packet.status, packet.warnings);
                }
                ResponseKind::ResultsetOk
                    if self.capabilities.contains(CapabilityFlags::DEPRECATE_EOF) =>
                {
                    let packet = parse_ok_packet(payload, self.capabilities)?;
                    return self.finish_resultset(packet.status, packet.warnings);
                }
                _ => {}
            }
        }

        let row_index = self.result.rows.len();
        if row_index >= self.limits.max_rows {
            return Err(InternalClientError::TooManyRows {
                actual: row_index.saturating_add(1),
                limit: self.limits.max_rows,
            });
        }
        let row = parse_text_row(
            payload,
            self.result.columns.len(),
            row_index,
            self.limits.max_cell_bytes,
        )?;
        self.result.rows.push(row);
        Ok(InternalProgress::Continue)
    }

    fn finish_resultset(
        &mut self,
        status: StatusFlags,
        warnings: u16,
    ) -> Result<InternalProgress, InternalClientError> {
        reject_more_results(status)?;
        // The complete terminator is consumed and no following result exists.
        // Validation failures below therefore leave the old connection wire
        // aligned and reusable, unlike failures while rows are still unread.
        self.state = InternalParserState::Complete;
        if self.result.rows.len() != 1 {
            return Err(InternalClientError::UnexpectedRowCount {
                actual: self.result.rows.len(),
                expected: 1,
            });
        }
        let session_states = self
            .result
            .value_by_name(0, SESSION_STATES_COLUMN, "Session_states")?
            .ok_or(InternalClientError::NullValue {
                name: "Session_states",
            })?;
        let session_states = core::str::from_utf8(session_states)
            .map_err(|_| InternalClientError::InvalidUtf8 {
                name: "Session_states",
            })?
            .to_owned();
        let session_token = self
            .result
            .value_by_name(0, SESSION_TOKEN_COLUMN, "Session_token")?
            .ok_or(InternalClientError::NullValue {
                name: "Session_token",
            })?;
        let session_token = core::str::from_utf8(session_token)
            .map_err(|_| InternalClientError::InvalidUtf8 {
                name: "Session_token",
            })?
            .to_owned();
        if session_token.is_empty() {
            return Err(InternalClientError::EmptySessionToken);
        }
        let current_database = validate_session_states(&session_states)?;
        Ok(InternalProgress::Complete(InternalResult::SessionStates(
            SessionStateSnapshot {
                session_states,
                session_token,
                current_database,
                status,
                warnings,
            },
        )))
    }

    fn backend_error(&mut self, payload: &[u8]) -> Result<InternalProgress, InternalClientError> {
        let packet = parse_error_packet(payload, self.capabilities)?;
        self.state = InternalParserState::Complete;
        Err(InternalClientError::BackendError {
            code: packet.code,
            sql_state: packet.sql_state,
            message_bytes: packet.message.len(),
        })
    }
}

fn validate_session_states(session_states: &str) -> Result<Option<String>, InternalClientError> {
    let value: serde_json::Value = serde_json::from_str(session_states)
        .map_err(|_| InternalClientError::MalformedSessionStates)?;
    let Some(object) = value.as_object() else {
        return Err(InternalClientError::MalformedSessionStates);
    };
    match object.get("current-db") {
        None => Ok(None),
        Some(serde_json::Value::String(database)) if database.is_empty() => Ok(None),
        Some(serde_json::Value::String(database)) => Ok(Some(database.clone())),
        Some(_) => Err(InternalClientError::MalformedSessionStates),
    }
}

fn parse_required_bytes<'a>(
    cursor: &mut Cursor<'a>,
    field: &'static str,
) -> Result<&'a [u8], InternalClientError> {
    cursor
        .read_length_encoded_bytes(field)?
        .ok_or(InternalClientError::MalformedStructure {
            field: "column-definition field is NULL",
        })
}

fn parse_column_name(payload: &[u8]) -> Result<&[u8], InternalClientError> {
    let mut cursor = Cursor::new(payload);
    let _catalog = parse_required_bytes(&mut cursor, "column catalog")?;
    let _schema = parse_required_bytes(&mut cursor, "column schema")?;
    let _table = parse_required_bytes(&mut cursor, "column table")?;
    let _original_table = parse_required_bytes(&mut cursor, "column original table")?;
    let name = parse_required_bytes(&mut cursor, "column name")?;
    let _original_name = parse_required_bytes(&mut cursor, "column original name")?;
    let fixed_length = match cursor.read_length_encoded_int()? {
        LengthEncodedInt::Value(value) => value,
        LengthEncodedInt::Null => {
            return Err(InternalClientError::MalformedStructure {
                field: "column fixed-field length is NULL",
            });
        }
    };
    if fixed_length != 12 {
        return Err(InternalClientError::MalformedStructure {
            field: "column fixed-field length is not 12",
        });
    }
    let _fixed = cursor.take(12, "column fixed fields")?;
    if !cursor.is_empty() {
        return Err(InternalClientError::MalformedStructure {
            field: "column definition has trailing bytes",
        });
    }
    Ok(name)
}

fn parse_text_row(
    payload: &[u8],
    column_count: usize,
    row: usize,
    max_cell_bytes: usize,
) -> Result<Vec<Option<Vec<u8>>>, InternalClientError> {
    let mut cursor = Cursor::new(payload);
    let mut values = Vec::with_capacity(column_count);
    for column in 0..column_count {
        let value = cursor.read_length_encoded_bytes("text row value")?;
        if let Some(bytes) = value {
            if bytes.len() > max_cell_bytes {
                return Err(InternalClientError::CellTooLarge {
                    row,
                    column,
                    actual: bytes.len(),
                    limit: max_cell_bytes,
                });
            }
            values.push(Some(bytes.to_vec()));
        } else {
            values.push(None);
        }
    }
    if !cursor.is_empty() {
        return Err(InternalClientError::MalformedStructure {
            field: "text row has trailing bytes",
        });
    }
    Ok(values)
}

fn reject_more_results(status: StatusFlags) -> Result<(), InternalClientError> {
    if status.contains(StatusFlags::MORE_RESULTS_EXISTS) {
        Err(InternalClientError::MoreResultsRejected)
    } else {
        Ok(())
    }
}

/// Typed restricted-client failure. No variant retains SQL, session JSON,
/// tokens, row bytes, or backend error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalClientError {
    /// A configured hard limit is zero.
    InvalidLimit {
        /// Invalid configuration field.
        field: &'static str,
    },
    /// Encoded internal request exceeds its hard bound.
    QueryTooLarge {
        /// Encoded bytes required.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Aggregate logical response bytes exceed their hard bound.
    ResultTooLarge {
        /// Bytes observed including the rejected payload.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Declared column count exceeds its hard bound.
    TooManyColumns {
        /// Declared columns.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Parsed row count exceeds its hard bound.
    TooManyRows {
        /// Rows including the rejected row.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// One retained column name exceeds its hard bound.
    ColumnNameTooLarge {
        /// Zero-based column index.
        column: usize,
        /// Column-name bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// One retained cell exceeds its hard bound.
    CellTooLarge {
        /// Zero-based row index.
        row: usize,
        /// Zero-based column index.
        column: usize,
        /// Cell bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A wire primitive rejected malformed input.
    MalformedPacket(DecodeError),
    /// A result-set structure violated the restricted grammar.
    MalformedStructure {
        /// Payload-free structural description.
        field: &'static str,
    },
    /// A protocol count cannot fit the host representation.
    CountOverflow {
        /// Overflowing count field.
        field: &'static str,
        /// Wire value.
        value: u64,
    },
    /// Internal counter arithmetic overflowed.
    CounterOverflow {
        /// Overflowing counter.
        field: &'static str,
    },
    /// Packet kind is not legal for this query and parser phase.
    UnexpectedResponse {
        /// Fixed query contract.
        query: InternalQueryKind,
        /// Phase before rejection.
        state: InternalParserState,
        /// Structural packet kind.
        kind: ResponseKind,
    },
    /// The backend returned a structured `MySQL` ERR. Message text is counted
    /// but deliberately not retained.
    BackendError {
        /// `MySQL` error code.
        code: u16,
        /// Optional protocol-4.1 SQLSTATE.
        sql_state: Option<[u8; 5]>,
        /// Unretained message length.
        message_bytes: usize,
    },
    /// LOCAL INFILE is never valid for proxy-generated internal queries.
    LocalInfileRejected,
    /// The result contains ambiguous duplicate column names.
    DuplicateColumn {
        /// First zero-based index.
        first: usize,
        /// Duplicate zero-based index.
        duplicate: usize,
    },
    /// A required session-state column is absent.
    MissingColumn {
        /// Required fixed column name.
        name: &'static str,
    },
    /// `SHOW SESSION_STATES` did not return exactly one row.
    UnexpectedRowCount {
        /// Parsed rows.
        actual: usize,
        /// Required rows.
        expected: usize,
    },
    /// A required session-state value is SQL NULL.
    NullValue {
        /// Required fixed column name.
        name: &'static str,
    },
    /// A required session-state value is not UTF-8.
    InvalidUtf8 {
        /// Required fixed column name.
        name: &'static str,
    },
    /// `TiDB` returned an empty signed session token.
    EmptySessionToken,
    /// Session state is not a JSON object with the expected `current-db`
    /// shape. Parser diagnostics never retain the state text.
    MalformedSessionStates,
    /// Allowlisted internal queries must return exactly one result.
    MoreResultsRejected,
    /// A payload followed success, backend ERR, or a previous parser failure.
    AlreadyTerminal {
        /// Terminal parser state.
        state: InternalParserState,
    },
}

impl fmt::Display for InternalClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "internal limit {field} is zero"),
            Self::QueryTooLarge { actual, limit } => write!(
                formatter,
                "internal query is {actual} bytes, limit is {limit}"
            ),
            Self::ResultTooLarge { actual, limit } => write!(
                formatter,
                "internal result is at least {actual} bytes, limit is {limit}"
            ),
            Self::TooManyColumns { actual, limit } => write!(
                formatter,
                "internal result declares {actual} columns, limit is {limit}"
            ),
            Self::TooManyRows { actual, limit } => write!(
                formatter,
                "internal result has at least {actual} rows, limit is {limit}"
            ),
            Self::ColumnNameTooLarge {
                column,
                actual,
                limit,
            } => write!(
                formatter,
                "internal column {column} name is {actual} bytes, limit is {limit}"
            ),
            Self::CellTooLarge {
                row,
                column,
                actual,
                limit,
            } => write!(
                formatter,
                "internal cell {row}:{column} is {actual} bytes, limit is {limit}"
            ),
            Self::MalformedPacket(error) => error.fmt(formatter),
            Self::MalformedStructure { field } => {
                write!(formatter, "malformed internal result: {field}")
            }
            Self::CountOverflow { field, value } => {
                write!(formatter, "{field} value {value} exceeds the host size")
            }
            Self::CounterOverflow { field } => write!(formatter, "{field} overflowed"),
            Self::UnexpectedResponse { query, state, kind } => write!(
                formatter,
                "unexpected {kind:?} response for {query:?} while {state:?}"
            ),
            Self::BackendError {
                code,
                sql_state,
                message_bytes,
            } => write!(
                formatter,
                "internal backend error {code} SQLSTATE {sql_state:?} ({message_bytes} message bytes)"
            ),
            Self::LocalInfileRejected => {
                formatter.write_str("LOCAL INFILE is forbidden for internal queries")
            }
            Self::DuplicateColumn { first, duplicate } => write!(
                formatter,
                "duplicate internal result column at indexes {first} and {duplicate}"
            ),
            Self::MissingColumn { name } => {
                write!(formatter, "internal result is missing column {name}")
            }
            Self::UnexpectedRowCount { actual, expected } => write!(
                formatter,
                "internal result has {actual} rows, expected {expected}"
            ),
            Self::NullValue { name } => write!(formatter, "internal result column {name} is NULL"),
            Self::InvalidUtf8 { name } => {
                write!(formatter, "internal result column {name} is not UTF-8")
            }
            Self::EmptySessionToken => formatter.write_str("internal session token is empty"),
            Self::MalformedSessionStates => {
                formatter.write_str("internal session state JSON is malformed")
            }
            Self::MoreResultsRejected => {
                formatter.write_str("multiple internal results are forbidden")
            }
            Self::AlreadyTerminal { state } => {
                write!(formatter, "internal result parser is terminal ({state:?})")
            }
        }
    }
}

impl std::error::Error for InternalClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedPacket(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DecodeError> for InternalClientError {
    fn from(error: DecodeError) -> Self {
        Self::MalformedPacket(error)
    }
}

#[cfg(test)]
mod tests {
    use mysql_wire::{
        CapabilityFlags, ResponseHeader, StatusFlags, encode_eof_packet, encode_error_packet,
        encode_length_encoded_bytes, encode_length_encoded_int, encode_ok_packet,
    };

    use super::*;

    const LEGACY_CAPS: CapabilityFlags = CapabilityFlags::PROTOCOL_41;
    const MODERN_CAPS: CapabilityFlags =
        CapabilityFlags::PROTOCOL_41.union(CapabilityFlags::DEPRECATE_EOF);

    fn column(name: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        for field in [b"def".as_slice(), b"db", b"t", b"t", name, name] {
            assert!(
                encode_length_encoded_bytes(Some(field), &mut payload).is_ok(),
                "test column field fits in a length-encoded value"
            );
        }
        encode_length_encoded_int(12, &mut payload);
        payload.extend_from_slice(&[45, 0, 11, 0, 0, 0, 0x03, 0, 0, 0, 0, 0]);
        payload
    }

    fn row(values: &[Option<&[u8]>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for value in values {
            assert!(
                encode_length_encoded_bytes(*value, &mut payload).is_ok(),
                "test row value fits in a length-encoded value"
            );
        }
        payload
    }

    fn result_packets(modern: bool, columns: &[&[u8]], rows: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        encode_length_encoded_int(
            u64::try_from(columns.len()).unwrap_or(u64::MAX),
            &mut packets,
        );
        let mut result = vec![packets];
        result.extend(columns.iter().map(|name| column(name)));
        if !modern {
            result.push(encode_eof_packet(0, StatusFlags::AUTOCOMMIT).to_vec());
        }
        result.extend_from_slice(rows);
        if modern {
            result.push(
                encode_ok_packet(
                    ResponseHeader::EOF_OR_AUTH_SWITCH,
                    0,
                    0,
                    StatusFlags::AUTOCOMMIT,
                    0,
                    b"",
                    MODERN_CAPS,
                )
                .unwrap_or_default(),
            );
        } else {
            result.push(encode_eof_packet(0, StatusFlags::AUTOCOMMIT).to_vec());
        }
        result
    }

    fn parse_all(
        capabilities: CapabilityFlags,
        packets: &[Vec<u8>],
        limits: InternalLimits,
    ) -> Result<InternalResult, InternalClientError> {
        let mut parser =
            InternalResultParser::new(InternalQueryKind::ShowSessionStates, capabilities, limits)?;
        for packet in packets {
            match parser.consume(packet)? {
                InternalProgress::Continue => {}
                InternalProgress::Complete(result) => return Ok(result),
            }
        }
        Err(InternalClientError::MalformedStructure {
            field: "test response did not terminate",
        })
    }

    #[test]
    fn allowlist_encodes_exact_queries_and_go_escaping() -> Result<(), InternalClientError> {
        let limits = InternalLimits::default();
        assert_eq!(
            InternalQuery::ShowSessionStates.encode(limits)?,
            [b"\x03".as_slice(), SHOW_SESSION_STATES].concat()
        );
        assert_eq!(
            InternalQuery::Commit.encode(limits)?,
            b"\x03COMMIT".to_vec()
        );
        assert_eq!(
            InternalQuery::SetSessionStates(r#"{"path":"a\\b's"}"#).encode(limits)?,
            b"\x03SET SESSION_STATES '{\"path\":\"a\\\\\\\\b\\'s\"}'".to_vec()
        );
        let debug = format!(
            "{:?}",
            InternalQuery::SetSessionStates(r#"{"secret":"not-for-logs"}"#)
        );
        assert!(debug.contains("state_bytes"));
        assert!(!debug.contains("not-for-logs"));
        assert!(matches!(
            InternalQuery::Commit.encode(InternalLimits {
                max_query_bytes: 1,
                ..limits
            }),
            Err(InternalClientError::QueryTooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn parses_session_state_in_both_eof_modes() -> Result<(), InternalClientError> {
        for (modern_result, capabilities) in [
            (false, LEGACY_CAPS),
            (true, MODERN_CAPS),
            // The Go migration corpus advertises modern capabilities but
            // freezes the classic metadata and row terminators produced by
            // older TiDB versions. The restricted parser accepts that safe
            // compatibility shape without weakening its size bounds.
            (false, MODERN_CAPS),
        ] {
            let packets = result_packets(
                modern_result,
                &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
                &[row(&[Some(br#"{"current-db":"test"}"#), Some(b"token-1")])],
            );
            let InternalResult::SessionStates(snapshot) =
                parse_all(capabilities, &packets, InternalLimits::default())?
            else {
                unreachable!("SHOW must return session state");
            };
            assert_eq!(snapshot.session_states(), r#"{"current-db":"test"}"#);
            assert_eq!(snapshot.session_token(), "token-1");
            assert_eq!(snapshot.current_database(), Some("test"));
            assert_eq!(snapshot.status(), StatusFlags::AUTOCOMMIT);
            assert_eq!(snapshot.warnings(), 0);
            let debug = format!("{snapshot:?}");
            assert!(!debug.contains("current-db"));
            assert!(!debug.contains("token-1"));
        }
        Ok(())
    }

    #[test]
    fn column_lookup_rejects_duplicate_and_missing_names() {
        let duplicate = result_packets(
            false,
            &[SESSION_STATES_COLUMN, SESSION_STATES_COLUMN],
            &[row(&[Some(b"{}"), Some(b"token")])],
        );
        assert!(matches!(
            parse_all(LEGACY_CAPS, &duplicate, InternalLimits::default()),
            Err(InternalClientError::DuplicateColumn { .. })
        ));

        let missing = result_packets(
            false,
            &[SESSION_STATES_COLUMN, b"not_token"],
            &[row(&[Some(b"{}"), Some(b"token")])],
        );
        assert_eq!(
            parse_all(LEGACY_CAPS, &missing, InternalLimits::default()),
            Err(InternalClientError::MissingColumn {
                name: "Session_token"
            })
        );
    }

    #[test]
    fn required_values_reject_null_empty_and_invalid_utf8() {
        for (values, expected) in [
            (
                vec![Some(b"{}".as_slice()), None],
                InternalClientError::NullValue {
                    name: "Session_token",
                },
            ),
            (
                vec![None, Some(b"token".as_slice())],
                InternalClientError::NullValue {
                    name: "Session_states",
                },
            ),
            (
                vec![Some(b"{}".as_slice()), Some(b"".as_slice())],
                InternalClientError::EmptySessionToken,
            ),
            (
                vec![Some(b"\xff".as_slice()), Some(b"token".as_slice())],
                InternalClientError::InvalidUtf8 {
                    name: "Session_states",
                },
            ),
        ] {
            let packets = result_packets(
                true,
                &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
                &[row(&values)],
            );
            assert_eq!(
                parse_all(MODERN_CAPS, &packets, InternalLimits::default()),
                Err(expected)
            );
        }
    }

    #[test]
    fn validates_session_json_and_extracts_authoritative_database() {
        for (state, expected) in [
            (br"{}".as_slice(), None),
            (br#"{"current-db":""}"#.as_slice(), None),
            (
                br#"{"current-db":"db_after_use"}"#.as_slice(),
                Some("db_after_use"),
            ),
        ] {
            let packets = result_packets(
                true,
                &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
                &[row(&[Some(state), Some(b"signed-token")])],
            );
            let Ok(InternalResult::SessionStates(snapshot)) =
                parse_all(MODERN_CAPS, &packets, InternalLimits::default())
            else {
                unreachable!("valid state must produce a snapshot")
            };
            assert_eq!(snapshot.current_database(), expected);
        }

        for state in [
            b"{".as_slice(),
            br"[]".as_slice(),
            br#"{"current-db":7}"#.as_slice(),
            br#"{"current-db":null}"#.as_slice(),
        ] {
            let packets = result_packets(
                true,
                &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
                &[row(&[Some(state), Some(b"signed-token")])],
            );
            assert_eq!(
                parse_all(MODERN_CAPS, &packets, InternalLimits::default()),
                Err(InternalClientError::MalformedSessionStates)
            );
        }
    }

    #[test]
    fn terminal_snapshot_validation_failures_leave_the_old_wire_aligned()
    -> Result<(), InternalClientError> {
        for values in [
            vec![Some(b"{".as_slice()), Some(b"token".as_slice())],
            vec![Some(b"{}".as_slice()), None],
            vec![Some(b"{}".as_slice()), Some(b"".as_slice())],
        ] {
            let packets = result_packets(
                true,
                &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
                &[row(&values)],
            );
            let mut parser =
                InternalQuery::ShowSessionStates.parser(MODERN_CAPS, InternalLimits::default())?;
            let mut terminal_error = None;
            for packet in packets {
                match parser.consume(&packet) {
                    Ok(InternalProgress::Continue) => {}
                    Ok(InternalProgress::Complete(_)) => {
                        unreachable!("invalid snapshot cannot complete successfully")
                    }
                    Err(error) => terminal_error = Some(error),
                }
            }
            assert!(terminal_error.is_some());
            assert_eq!(parser.state(), InternalParserState::Complete);
        }
        Ok(())
    }

    #[test]
    fn malformed_counts_columns_and_rows_are_typed() -> Result<(), InternalClientError> {
        let mut parser = InternalResultParser::new(
            InternalQueryKind::ShowSessionStates,
            LEGACY_CAPS,
            InternalLimits::default(),
        )?;
        assert!(matches!(
            parser.consume(&[0xfc]),
            Err(InternalClientError::MalformedPacket(_))
        ));
        assert_eq!(parser.state(), InternalParserState::Failed);

        let malformed_column = vec![vec![1], vec![3, b'd', b'e', b'f']];
        assert!(matches!(
            parse_all(LEGACY_CAPS, &malformed_column, InternalLimits::default()),
            Err(InternalClientError::MalformedPacket(_))
        ));

        let mut trailing_row = row(&[Some(b"{}"), Some(b"token")]);
        trailing_row.push(0);
        let packets = result_packets(
            false,
            &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
            &[trailing_row],
        );
        assert_eq!(
            parse_all(LEGACY_CAPS, &packets, InternalLimits::default()),
            Err(InternalClientError::MalformedStructure {
                field: "text row has trailing bytes"
            })
        );
        Ok(())
    }

    #[test]
    fn every_allocation_dimension_is_bounded() {
        let two_columns = result_packets(
            false,
            &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
            &[row(&[Some(b"{}"), Some(b"token")])],
        );
        assert!(matches!(
            parse_all(
                LEGACY_CAPS,
                &two_columns,
                InternalLimits {
                    max_columns: 1,
                    ..InternalLimits::default()
                }
            ),
            Err(InternalClientError::TooManyColumns { .. })
        ));
        assert!(matches!(
            parse_all(
                LEGACY_CAPS,
                &two_columns,
                InternalLimits {
                    max_column_name_bytes: 4,
                    ..InternalLimits::default()
                }
            ),
            Err(InternalClientError::ColumnNameTooLarge { .. })
        ));
        assert!(matches!(
            parse_all(
                LEGACY_CAPS,
                &two_columns,
                InternalLimits {
                    max_cell_bytes: 2,
                    ..InternalLimits::default()
                }
            ),
            Err(InternalClientError::CellTooLarge { .. })
        ));
        assert!(matches!(
            parse_all(
                LEGACY_CAPS,
                &two_columns,
                InternalLimits {
                    max_result_bytes: 2,
                    ..InternalLimits::default()
                }
            ),
            Err(InternalClientError::ResultTooLarge { .. })
        ));

        let two_rows = result_packets(
            false,
            &[SESSION_STATES_COLUMN, SESSION_TOKEN_COLUMN],
            &[
                row(&[Some(b"{}"), Some(b"token")]),
                row(&[Some(b"{}"), Some(b"token")]),
            ],
        );
        assert!(matches!(
            parse_all(
                LEGACY_CAPS,
                &two_rows,
                InternalLimits {
                    max_rows: 1,
                    ..InternalLimits::default()
                }
            ),
            Err(InternalClientError::TooManyRows { .. })
        ));
    }

    #[test]
    fn ok_error_local_infile_and_more_results_follow_restricted_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let ok = encode_ok_packet(
            ResponseHeader::OK,
            0,
            0,
            StatusFlags::AUTOCOMMIT,
            0,
            b"",
            LEGACY_CAPS,
        )?;
        for query in [
            InternalQueryKind::SetSessionStates,
            InternalQueryKind::Commit,
        ] {
            let mut parser =
                InternalResultParser::new(query, LEGACY_CAPS, InternalLimits::default())?;
            assert!(matches!(
                parser.consume(&ok)?,
                InternalProgress::Complete(InternalResult::Ok(InternalOk {
                    status: StatusFlags::AUTOCOMMIT,
                    ..
                }))
            ));
            assert!(matches!(
                parser.consume(&ok),
                Err(InternalClientError::AlreadyTerminal { .. })
            ));
        }

        let error = encode_error_packet(1064, Some(*b"42000"), b"secret SQL", LEGACY_CAPS)?;
        let mut parser = InternalResultParser::new(
            InternalQueryKind::ShowSessionStates,
            LEGACY_CAPS,
            InternalLimits::default(),
        )?;
        let backend = parser.consume(&error);
        assert_eq!(
            backend,
            Err(InternalClientError::BackendError {
                code: 1064,
                sql_state: Some(*b"42000"),
                message_bytes: 10,
            })
        );
        assert_eq!(parser.state(), InternalParserState::Complete);
        assert!(!format!("{backend:?}").contains("secret SQL"));

        let mut parser = InternalResultParser::new(
            InternalQueryKind::ShowSessionStates,
            LEGACY_CAPS,
            InternalLimits::default(),
        )?;
        assert_eq!(
            parser.consume(b"\xfbfile"),
            Err(InternalClientError::LocalInfileRejected)
        );

        let more = encode_ok_packet(
            ResponseHeader::OK,
            0,
            0,
            StatusFlags::MORE_RESULTS_EXISTS,
            0,
            b"",
            LEGACY_CAPS,
        )?;
        let mut parser = InternalResultParser::new(
            InternalQueryKind::Commit,
            LEGACY_CAPS,
            InternalLimits::default(),
        )?;
        assert_eq!(
            parser.consume(&more),
            Err(InternalClientError::MoreResultsRejected)
        );
        Ok(())
    }

    #[test]
    fn row_stream_error_is_structured_and_terminal() -> Result<(), Box<dyn std::error::Error>> {
        let mut parser =
            InternalQuery::ShowSessionStates.parser(MODERN_CAPS, InternalLimits::default())?;
        assert_eq!(parser.consume(&[2])?, InternalProgress::Continue);
        assert_eq!(
            parser.consume(&column(SESSION_STATES_COLUMN))?,
            InternalProgress::Continue
        );
        assert_eq!(
            parser.consume(&column(SESSION_TOKEN_COLUMN))?,
            InternalProgress::Continue
        );
        let error = encode_error_packet(1105, Some(*b"HY000"), b"row stream failed", MODERN_CAPS)?;
        assert_eq!(
            parser.consume(&error),
            Err(InternalClientError::BackendError {
                code: 1105,
                sql_state: Some(*b"HY000"),
                message_bytes: 17,
            })
        );
        assert_eq!(parser.state(), InternalParserState::Complete);
        Ok(())
    }

    #[test]
    fn zero_limits_are_rejected_before_work() {
        assert_eq!(
            InternalQuery::Commit.encode(InternalLimits {
                max_rows: 0,
                ..InternalLimits::default()
            }),
            Err(InternalClientError::InvalidLimit { field: "max_rows" })
        );
    }
}
