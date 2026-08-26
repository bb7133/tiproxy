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

//! Prepared-statement lifecycle and prepare-response observation (SES-05).
//!
//! Go's `CmdProcessor` tracks the redirect-blocking long-data/cursor state of
//! every statement ID independently. This module preserves that contract while
//! also retaining prepare metadata and execute parameter types for the Rust
//! codec. Backend errors never mutate a pending guard: an execute error after
//! long data and a fetch error while a cursor is open must remain unsafe for
//! migration until an explicit successful reset/close/clear boundary.

use core::fmt;
use std::collections::BTreeMap;

use mysql_wire::{
    CapabilityFlags, CommandCode, DecodeError, ParameterType, ResponseHeader, StatusFlags,
    StmtExecute, decode_prepare_ok, decode_statement_command, decode_stmt_execute,
    parse_eof_packet, parse_error_packet,
};

use crate::command::{Command, PreparedMutation};
use crate::fsm::SessionEvent;
use crate::response::{FlushAction, ResponseDisposition, ResponseEffect, ResponsePacket};

/// Metadata declared by a successful `COM_STMT_PREPARE_OK` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareMetadata {
    /// Backend-assigned statement identifier.
    pub statement_id: u32,
    /// Declared parameter count.
    pub parameter_count: u16,
    /// Declared result-column count.
    pub column_count: u16,
    /// Backend warning count.
    pub warnings: u16,
}

/// Redirect-blocking lifecycle for one statement ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreparedGuard {
    /// No long data or cursor is outstanding.
    #[default]
    Idle,
    /// `COM_STMT_SEND_LONG_DATA` was forwarded and still awaits a successful
    /// execute/reset/close/clear boundary.
    LongDataPending,
    /// An execute/fetch status says a cursor still has unread rows.
    CursorOpen,
}

impl PreparedGuard {
    /// Whether this guard blocks session migration and graceful shutdown.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        !matches!(self, Self::Idle)
    }
}

/// State retained for one backend statement ID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreparedStatementState {
    metadata: Option<PrepareMetadata>,
    guard: PreparedGuard,
    parameter_types: Vec<ParameterType>,
}

impl PreparedStatementState {
    /// Successful prepare metadata, or `None` for a Go-compatible guard on an
    /// unknown ID (for example, hostile long data forwarded to the backend).
    #[must_use]
    pub const fn metadata(&self) -> Option<PrepareMetadata> {
        self.metadata
    }

    /// Current redirect-blocking guard.
    #[must_use]
    pub const fn guard(&self) -> PreparedGuard {
        self.guard
    }

    /// Parameter types retained for an execute with `new-params-bound = 0`.
    #[must_use]
    pub fn parameter_types(&self) -> &[ParameterType] {
        &self.parameter_types
    }
}

/// Per-session prepared-statement registry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreparedRegistry {
    statements: BTreeMap<u32, PreparedStatementState>,
}

impl PreparedRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            statements: BTreeMap::new(),
        }
    }

    /// Number of retained statement IDs, including unknown-ID guards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// Whether no statement IDs are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Looks up one statement ID.
    #[must_use]
    pub fn get(&self, statement_id: u32) -> Option<&PreparedStatementState> {
        self.statements.get(&statement_id)
    }

    /// Whether any independent statement guard blocks migration.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.statements
            .values()
            .any(|statement| statement.guard.is_pending())
    }

    /// Produces the payload-free SES-00 synchronization event for the current
    /// aggregate guard. The adapter applies a registry mutation/status update,
    /// sends this event, and only then sends the command-completion boundary;
    /// that ordering prevents a queued redirect or drain from crossing an
    /// unfinished long-data/cursor boundary.
    #[must_use]
    pub fn session_event(&self) -> SessionEvent {
        if self.has_pending() {
            SessionEvent::PreparedStatePending
        } else {
            SessionEvent::PreparedStateClear
        }
    }

    /// Registers a completed prepare. Reusing an ID replaces stale metadata,
    /// parameter types, and guards atomically.
    pub fn register(&mut self, metadata: PrepareMetadata) {
        self.statements.insert(
            metadata.statement_id,
            PreparedStatementState {
                metadata: Some(metadata),
                guard: PreparedGuard::Idle,
                parameter_types: Vec::new(),
            },
        );
    }

    /// Applies a dispatch-owned mutation at its declared forward/success
    /// boundary.
    pub fn apply_mutation(&mut self, mutation: PreparedMutation) {
        match mutation {
            PreparedMutation::LongData(statement_id) => {
                self.statements.entry(statement_id).or_default().guard =
                    PreparedGuard::LongDataPending;
            }
            PreparedMutation::Close(statement_id) => {
                self.statements.remove(&statement_id);
            }
            PreparedMutation::Reset(statement_id) => {
                self.clear_guard(statement_id);
            }
            PreparedMutation::ClearAll => self.statements.clear(),
        }
    }

    /// Applies Go's status-driven execute/fetch lifecycle update. Effects with
    /// no status (especially backend ERR) leave the registry unchanged.
    pub fn observe_response(
        &mut self,
        command: Command,
        statement_id: u32,
        effect: ResponseEffect,
    ) {
        let Some(status) = effect.status else {
            return;
        };
        let guard = match command {
            Command::StmtExecute => status
                .contains(StatusFlags::CURSOR_EXISTS)
                .then_some(PreparedGuard::CursorOpen),
            Command::StmtFetch => {
                (!status.contains(StatusFlags::LAST_ROW_SENT)).then_some(PreparedGuard::CursorOpen)
            }
            _ => return,
        };
        match guard {
            Some(guard) => {
                self.statements.entry(statement_id).or_default().guard = guard;
            }
            None => self.clear_guard(statement_id),
        }
    }

    /// Fully decodes one execute and retains newly supplied parameter types.
    /// This is an inspection/corpus path; transparent forwarding needs only
    /// [`statement_id`](Self::statement_id).
    ///
    /// # Errors
    ///
    /// Returns [`PreparedRegistryError::UnknownStatement`] without forwarding
    /// policy implications, or a typed packet decode error.
    pub fn decode_execute<'a>(
        &mut self,
        payload: &'a [u8],
    ) -> Result<StmtExecute<'a>, PreparedRegistryError> {
        let statement_id = Self::statement_id(payload, CommandCode::STMT_EXECUTE)?;
        let statement = self
            .statements
            .get(&statement_id)
            .ok_or(PreparedRegistryError::UnknownStatement { statement_id })?;
        let metadata = statement
            .metadata
            .ok_or(PreparedRegistryError::MissingPrepareMetadata { statement_id })?;
        let decoded = decode_stmt_execute(
            payload,
            usize::from(metadata.parameter_count),
            &statement.parameter_types,
        )?;
        if decoded.new_params_bound {
            let types = decoded
                .parameters
                .iter()
                .map(|parameter| parameter.parameter_type)
                .collect();
            if let Some(statement) = self.statements.get_mut(&statement_id) {
                statement.parameter_types = types;
            }
        }
        Ok(decoded)
    }

    /// Parses only the command byte and statement-ID prefix. It is safe for a
    /// bounded capture prefix of a multi-physical-packet execute.
    ///
    /// # Errors
    ///
    /// Returns a typed wire error for a wrong command or truncated ID.
    pub fn statement_id(payload: &[u8], command: CommandCode) -> Result<u32, DecodeError> {
        Ok(decode_statement_command(payload, command)?.statement_id)
    }

    fn clear_guard(&mut self, statement_id: u32) {
        let remove = if let Some(statement) = self.statements.get_mut(&statement_id) {
            statement.guard = PreparedGuard::Idle;
            statement.metadata.is_none()
        } else {
            false
        };
        if remove {
            self.statements.remove(&statement_id);
        }
    }
}

/// Prepared-registry inspection failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedRegistryError {
    /// The request did not contain the expected fixed command prefix.
    Wire(DecodeError),
    /// No state exists for the backend statement ID.
    UnknownStatement {
        /// Referenced statement ID.
        statement_id: u32,
    },
    /// An unknown-ID guard exists but no prepare metadata is available.
    MissingPrepareMetadata {
        /// Referenced statement ID.
        statement_id: u32,
    },
    /// Full execute decoding failed.
    Execute(mysql_wire::PreparedDecodeError),
}

impl fmt::Display for PreparedRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::UnknownStatement { statement_id } => {
                write!(formatter, "unknown prepared statement ID {statement_id}")
            }
            Self::MissingPrepareMetadata { statement_id } => write!(
                formatter,
                "prepared statement ID {statement_id} has no prepare metadata"
            ),
            Self::Execute(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PreparedRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Execute(error) => Some(error),
            Self::UnknownStatement { .. } | Self::MissingPrepareMetadata { .. } => None,
        }
    }
}

impl From<DecodeError> for PreparedRegistryError {
    fn from(error: DecodeError) -> Self {
        Self::Wire(error)
    }
}

impl From<mysql_wire::PreparedDecodeError> for PreparedRegistryError {
    fn from(error: mysql_wire::PreparedDecodeError) -> Self {
        Self::Execute(error)
    }
}

/// Prepare-response observer phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareObserverState {
    /// Waiting for the first OK or ERR packet.
    Initial,
    /// Forwarding declared parameter definitions.
    Parameters {
        /// Definitions still expected, including the next packet.
        remaining: u16,
    },
    /// Waiting for the classic EOF after parameters.
    ParameterEof,
    /// Forwarding declared column definitions.
    Columns {
        /// Definitions still expected, including the next packet.
        remaining: u16,
    },
    /// Waiting for the classic EOF after columns.
    ColumnEof,
    /// Terminal boundary reached.
    Complete,
}

/// Contextual role of one prepare-response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparePacketRole {
    /// Initial prepare-OK header.
    Ok,
    /// Initial backend error.
    Error,
    /// Parameter definition.
    ParameterDefinition,
    /// Column definition.
    ColumnDefinition,
    /// Classic EOF after one metadata group.
    MetadataEof,
}

/// Result of forwarding one prepare-response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareDisposition {
    /// More packets belong to this prepare response.
    Continue,
    /// Prepare completed and the metadata can now be registered atomically.
    CompleteSuccess(PrepareMetadata),
    /// The initial packet was a nonfatal backend error.
    CompleteError {
        /// Backend `MySQL` error code.
        code: u16,
    },
}

/// Payload-free effect from one prepare packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareEffect {
    /// Contextual packet role.
    pub role: PreparePacketRole,
    /// Whether the response continues or completed.
    pub disposition: PrepareDisposition,
    /// Flush only at the one terminal boundary.
    pub flush: FlushAction,
}

/// Constant-memory `COM_STMT_PREPARE` response observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareObserver {
    state: PrepareObserverState,
    capabilities: CapabilityFlags,
    metadata: Option<PrepareMetadata>,
}

impl PrepareObserver {
    /// Starts an observer for the negotiated EOF mode.
    #[must_use]
    pub const fn new(capabilities: CapabilityFlags) -> Self {
        Self {
            state: PrepareObserverState::Initial,
            capabilities,
            metadata: None,
        }
    }

    /// Current phase.
    #[must_use]
    pub const fn state(&self) -> PrepareObserverState {
        self.state
    }

    /// Whether a terminal boundary was reached.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, PrepareObserverState::Complete)
    }

    /// Observes one already-streamed logical backend packet. The observer
    /// retains only the prepare header and counters, never metadata payloads.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for a malformed first packet, a packet in the
    /// wrong phase, or a malformed classic metadata EOF. Rejection is inert.
    pub fn observe(
        &mut self,
        packet: ResponsePacket<'_>,
    ) -> Result<PrepareEffect, PrepareObserverError> {
        let (next, effect, metadata) = match self.state {
            PrepareObserverState::Initial => self.observe_initial(packet)?,
            PrepareObserverState::Parameters { remaining } => {
                self.observe_definition(remaining, true)?
            }
            PrepareObserverState::ParameterEof => self.observe_eof(packet, true)?,
            PrepareObserverState::Columns { remaining } => {
                self.observe_definition(remaining, false)?
            }
            PrepareObserverState::ColumnEof => self.observe_eof(packet, false)?,
            PrepareObserverState::Complete => {
                return Err(PrepareObserverError::AlreadyComplete);
            }
        };
        self.state = next;
        if let Some(metadata) = metadata {
            self.metadata = Some(metadata);
        }
        Ok(effect)
    }

    fn observe_initial(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<PrepareStep, PrepareObserverError> {
        match packet.first_byte() {
            Some(byte) if byte == ResponseHeader::OK.as_byte() => {
                let header = decode_prepare_ok(packet.prefix())?;
                let metadata = PrepareMetadata {
                    statement_id: header.statement_id,
                    parameter_count: header.parameter_count,
                    column_count: header.column_count,
                    warnings: header.warnings,
                };
                let next = Self::initial_group(metadata);
                let disposition = if matches!(next, PrepareObserverState::Complete) {
                    PrepareDisposition::CompleteSuccess(metadata)
                } else {
                    PrepareDisposition::Continue
                };
                Ok((
                    next,
                    PrepareEffect {
                        role: PreparePacketRole::Ok,
                        disposition,
                        flush: terminal_flush(disposition),
                    },
                    Some(metadata),
                ))
            }
            Some(byte) if byte == ResponseHeader::ERROR.as_byte() => {
                let error = parse_error_packet(packet.prefix(), self.capabilities)?;
                let disposition = PrepareDisposition::CompleteError { code: error.code };
                Ok((
                    PrepareObserverState::Complete,
                    PrepareEffect {
                        role: PreparePacketRole::Error,
                        disposition,
                        flush: FlushAction::ProtocolBoundary,
                    },
                    None,
                ))
            }
            other => Err(PrepareObserverError::UnexpectedPacket {
                state: self.state,
                first_byte: other,
            }),
        }
    }

    fn observe_definition(
        &self,
        remaining: u16,
        parameters: bool,
    ) -> Result<PrepareStep, PrepareObserverError> {
        let next = if remaining > 1 {
            if parameters {
                PrepareObserverState::Parameters {
                    remaining: remaining - 1,
                }
            } else {
                PrepareObserverState::Columns {
                    remaining: remaining - 1,
                }
            }
        } else if self.capabilities.contains(CapabilityFlags::DEPRECATE_EOF) {
            self.next_after_group(parameters)?
        } else if parameters {
            PrepareObserverState::ParameterEof
        } else {
            PrepareObserverState::ColumnEof
        };
        let disposition = self.disposition_for(next)?;
        Ok((
            next,
            PrepareEffect {
                role: if parameters {
                    PreparePacketRole::ParameterDefinition
                } else {
                    PreparePacketRole::ColumnDefinition
                },
                disposition,
                flush: terminal_flush(disposition),
            },
            None,
        ))
    }

    fn observe_eof(
        &self,
        packet: ResponsePacket<'_>,
        parameters: bool,
    ) -> Result<PrepareStep, PrepareObserverError> {
        if packet.first_byte() != Some(ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte())
            || packet.first_physical_payload_bytes() > 5
        {
            return Err(PrepareObserverError::UnexpectedPacket {
                state: self.state,
                first_byte: packet.first_byte(),
            });
        }
        parse_eof_packet(packet.prefix())?;
        let next = self.next_after_group(parameters)?;
        let disposition = self.disposition_for(next)?;
        Ok((
            next,
            PrepareEffect {
                role: PreparePacketRole::MetadataEof,
                disposition,
                flush: terminal_flush(disposition),
            },
            None,
        ))
    }

    fn initial_group(metadata: PrepareMetadata) -> PrepareObserverState {
        if metadata.parameter_count > 0 {
            PrepareObserverState::Parameters {
                remaining: metadata.parameter_count,
            }
        } else if metadata.column_count > 0 {
            PrepareObserverState::Columns {
                remaining: metadata.column_count,
            }
        } else {
            PrepareObserverState::Complete
        }
    }

    fn next_after_group(
        &self,
        parameters: bool,
    ) -> Result<PrepareObserverState, PrepareObserverError> {
        let metadata = self.metadata.ok_or(PrepareObserverError::MissingMetadata)?;
        Ok(if parameters && metadata.column_count > 0 {
            PrepareObserverState::Columns {
                remaining: metadata.column_count,
            }
        } else {
            PrepareObserverState::Complete
        })
    }

    fn disposition_for(
        &self,
        next: PrepareObserverState,
    ) -> Result<PrepareDisposition, PrepareObserverError> {
        if matches!(next, PrepareObserverState::Complete) {
            Ok(PrepareDisposition::CompleteSuccess(
                self.metadata.ok_or(PrepareObserverError::MissingMetadata)?,
            ))
        } else {
            Ok(PrepareDisposition::Continue)
        }
    }
}

type PrepareStep = (PrepareObserverState, PrepareEffect, Option<PrepareMetadata>);

const fn terminal_flush(disposition: PrepareDisposition) -> FlushAction {
    if matches!(disposition, PrepareDisposition::Continue) {
        FlushAction::None
    } else {
        FlushAction::ProtocolBoundary
    }
}

/// Typed prepare-observer failure. No variant carries packet data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareObserverError {
    /// Structured OK/ERR/EOF parsing failed.
    MalformedPacket(DecodeError),
    /// Packet header was not valid in the current phase.
    UnexpectedPacket {
        /// Observer phase before rejection.
        state: PrepareObserverState,
        /// First payload byte, or `None` for an empty packet.
        first_byte: Option<u8>,
    },
    /// A packet followed the terminal boundary.
    AlreadyComplete,
    /// Internal phase metadata was unavailable; rejection remains inert.
    MissingMetadata,
}

impl fmt::Display for PrepareObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedPacket(error) => error.fmt(formatter),
            Self::UnexpectedPacket { state, first_byte } => write!(
                formatter,
                "unexpected prepare packet {first_byte:?} while {state:?}"
            ),
            Self::AlreadyComplete => formatter.write_str("prepare response is already complete"),
            Self::MissingMetadata => formatter.write_str("prepare metadata is unavailable"),
        }
    }
}

impl std::error::Error for PrepareObserverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedPacket(error) => Some(error),
            Self::UnexpectedPacket { .. } | Self::AlreadyComplete | Self::MissingMetadata => None,
        }
    }
}

impl From<DecodeError> for PrepareObserverError {
    fn from(error: DecodeError) -> Self {
        Self::MalformedPacket(error)
    }
}

/// Whether this response effect is the nonfatal backend ERR path that must
/// preserve prepared state. Kept as a named predicate for adapter tests.
#[must_use]
pub const fn is_backend_error(effect: ResponseEffect) -> bool {
    matches!(
        effect.disposition,
        ResponseDisposition::CompleteError { .. }
    )
}
