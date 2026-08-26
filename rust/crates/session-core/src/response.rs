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

//! Constant-memory observation of ordinary backend responses (SES-04).
//!
//! The runtime streams every physical packet unchanged and supplies this
//! module with only a bounded logical-payload prefix plus framing counters.
//! The observer recognizes response boundaries and server status without
//! retaining column definitions or rows. It deliberately does not implement
//! `COM_STMT_PREPARE` metadata (SES-05) or the client half of `LOCAL INFILE`
//! and `COM_CHANGE_USER` (SES-06).

use core::fmt;
use core::num::NonZeroU64;

use mysql_wire::{
    CapabilityFlags, DecodeError, MAX_PAYLOAD_LEN, ResponseHeader, StatusFlags, parse_eof_packet,
    parse_error_packet, parse_ok_packet, physical_packet_count,
};

use crate::command::ExpectedResponse;
use crate::fsm::SessionEvent;

/// Maximum logical-payload prefix needed to decode an OK packet's two largest
/// length-encoded integers and protocol-4.1 status/warning fields.
pub const RESPONSE_OBSERVER_PREFIX_LIMIT: usize = 23;

/// Default wire-byte threshold between result-stream flushes.
pub const DEFAULT_RESPONSE_FLUSH_THRESHOLD: NonZeroU64 =
    NonZeroU64::new(32 * 1024).expect("the response flush threshold is nonzero");

/// A completed logical packet represented by bounded, caller-owned metadata.
///
/// `prefix` must contain exactly `min(logical_payload_bytes, 23)` bytes. This
/// invariant makes every structured parse independent of the row or message
/// tail and prevents an adapter from silently supplying too little data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponsePacket<'a> {
    prefix: &'a [u8],
    logical_payload_bytes: u64,
    first_physical_payload_bytes: u32,
    physical_packets: u64,
    forwarded_wire_bytes: u64,
}

impl<'a> ResponsePacket<'a> {
    /// Builds packet metadata from an already materialized logical payload.
    ///
    /// Tests and small-packet adapters may use this helper. The production
    /// streaming path should use [`Self::from_forwarded`].
    ///
    /// # Errors
    ///
    /// Returns a typed metadata error if the host length cannot fit `u64`.
    pub fn from_payload(payload: &'a [u8]) -> Result<Self, ResponseObserverError> {
        let logical_payload_bytes = u64::try_from(payload.len()).map_err(|_| {
            ResponseObserverError::InvalidPacketMetadata {
                reason: "logical payload length exceeds u64",
            }
        })?;
        let first_physical_payload_bytes =
            u32::try_from(logical_payload_bytes.min(u64::from(MAX_PAYLOAD_LEN))).map_err(|_| {
                ResponseObserverError::InvalidPacketMetadata {
                    reason: "first physical payload length exceeds u32",
                }
            })?;
        let prefix_length = payload.len().min(RESPONSE_OBSERVER_PREFIX_LIMIT);
        Self::from_forwarded(
            &payload[..prefix_length],
            logical_payload_bytes,
            first_physical_payload_bytes,
            physical_packet_count(logical_payload_bytes),
        )
    }

    /// Builds packet metadata from a completed streaming forward.
    ///
    /// # Errors
    ///
    /// Returns a typed error when prefix capture or physical/logical framing
    /// metadata is inconsistent, or when wire-byte accounting overflows.
    pub fn from_forwarded(
        prefix: &'a [u8],
        logical_payload_bytes: u64,
        first_physical_payload_bytes: u32,
        physical_packets: u64,
    ) -> Result<Self, ResponseObserverError> {
        let expected_prefix = if logical_payload_bytes
            >= u64::try_from(RESPONSE_OBSERVER_PREFIX_LIMIT).unwrap_or(u64::MAX)
        {
            RESPONSE_OBSERVER_PREFIX_LIMIT
        } else {
            usize::try_from(logical_payload_bytes).map_err(|_| {
                ResponseObserverError::InvalidPacketMetadata {
                    reason: "logical payload prefix length exceeds usize",
                }
            })?
        };
        if prefix.len() != expected_prefix {
            return Err(ResponseObserverError::InvalidPacketMetadata {
                reason: "captured prefix is not the required bounded length",
            });
        }

        let expected_first = logical_payload_bytes.min(u64::from(MAX_PAYLOAD_LEN));
        if u64::from(first_physical_payload_bytes) != expected_first {
            return Err(ResponseObserverError::InvalidPacketMetadata {
                reason: "first physical payload length disagrees with logical length",
            });
        }
        if physical_packets != physical_packet_count(logical_payload_bytes) {
            return Err(ResponseObserverError::InvalidPacketMetadata {
                reason: "physical packet count disagrees with logical length",
            });
        }
        let header_bytes =
            physical_packets
                .checked_mul(4)
                .ok_or(ResponseObserverError::CounterOverflow {
                    field: "physical header bytes",
                })?;
        let forwarded_wire_bytes = logical_payload_bytes.checked_add(header_bytes).ok_or(
            ResponseObserverError::CounterOverflow {
                field: "forwarded wire bytes",
            },
        )?;

        Ok(Self {
            prefix,
            logical_payload_bytes,
            first_physical_payload_bytes,
            physical_packets,
            forwarded_wire_bytes,
        })
    }

    /// Returns the retained structured prefix.
    #[must_use]
    pub const fn prefix(self) -> &'a [u8] {
        self.prefix
    }

    /// Returns the first logical-payload byte, including `None` for an empty
    /// packet that may still be valid opaque result data.
    #[must_use]
    pub fn first_byte(self) -> Option<u8> {
        self.prefix.first().copied()
    }

    /// Total bytes in the logical payload.
    #[must_use]
    pub const fn logical_payload_bytes(self) -> u64 {
        self.logical_payload_bytes
    }

    /// Payload length from the first physical header. Go uses this exact value
    /// for its short-EOF and resultset-OK tests.
    #[must_use]
    pub const fn first_physical_payload_bytes(self) -> u32 {
        self.first_physical_payload_bytes
    }

    /// Physical packets in this logical packet, including an exact-maximum
    /// zero-length terminator.
    #[must_use]
    pub const fn physical_packets(self) -> u64 {
        self.physical_packets
    }

    /// Payload plus all four-byte physical headers forwarded for this packet.
    #[must_use]
    pub const fn forwarded_wire_bytes(self) -> u64 {
        self.forwarded_wire_bytes
    }
}

/// Response state selected from the command contract and negotiated EOF mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverState {
    /// Generic command expecting exactly one OK/ERR/EOF response.
    OnePacket,
    /// Query-style first packet: OK, ERR, LOCAL INFILE, or resultset header.
    QueryStart,
    /// Classic mode column definitions through the metadata EOF.
    QueryClassicColumns,
    /// Classic mode row packets through ERR or EOF.
    QueryClassicRows,
    /// Deprecated-EOF column definitions and rows through ERR or OK-as-EOF.
    QueryDeprecateData,
    /// `COM_FIELD_LIST` metadata through ERR or mode-specific terminator.
    FieldList,
    /// `COM_STMT_FETCH` binary rows through ERR or mode-specific terminator.
    FetchRows,
    /// `COM_STATISTICS` raw one-packet response.
    Statistics,
    /// LOCAL INFILE request was forwarded; the client upload is owned by
    /// SES-06 and the next backend packet must be final OK/ERR.
    AwaitLocalInfileFinal,
    /// Terminal response boundary reached.
    Complete,
}

/// Contextual meaning assigned to one forwarded backend packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketRole {
    /// Regular or `0xfe`-encoded OK packet.
    Ok,
    /// `MySQL` ERR packet.
    Error,
    /// LOCAL INFILE request.
    LocalInfileRequest,
    /// Resultset column-count/header packet.
    ResultsetHeader,
    /// Classic metadata or `FIELD_LIST` column definition.
    ColumnDefinition,
    /// Classic text/binary row or FETCH row.
    Row,
    /// Opaque column definition or row in deprecated-EOF mode.
    ResultsetData,
    /// Classic EOF or deprecated-EOF OK terminator.
    Terminator,
    /// Raw `COM_STATISTICS` response.
    Raw,
}

/// Command-level result after one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDisposition {
    /// More packets belong to the current result.
    Continue,
    /// A result ended with `MORE_RESULTS_EXISTS`; restart at query-first-packet.
    MoreResults,
    /// Hand control to the LOCAL INFILE client-upload loop.
    LocalInfile,
    /// The command completed successfully.
    CompleteSuccess,
    /// The command completed with a nonfatal `MySQL` error.
    CompleteError {
        /// Backend `MySQL` error code.
        code: u16,
    },
    /// The raw one-packet statistics response completed.
    CompleteRaw,
}

/// Whether the runtime flushes after the just-forwarded packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushAction {
    /// Retain bytes in the bounded transport buffer.
    None,
    /// Flush because configured pending wire bytes reached the threshold.
    ConfiguredThreshold,
    /// Flush at a command/result/LOCAL-INFILE protocol boundary.
    ProtocolBoundary,
}

/// Payload-free effects produced after one backend packet is forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseEffect {
    /// Contextual packet meaning.
    pub role: PacketRole,
    /// Whether the response continues, changes duplex direction, or completes.
    pub disposition: ResponseDisposition,
    /// Parsed status only when Go's command processor applies that status.
    pub status: Option<StatusFlags>,
    /// Transaction state after applying this packet.
    pub in_transaction: bool,
    /// Flush instruction for the runtime.
    pub flush: FlushAction,
}

impl ResponseEffect {
    /// Maps this wire observation into the payload-free SES-00 FSM event.
    #[must_use]
    pub const fn session_event(self) -> SessionEvent {
        match self.disposition {
            ResponseDisposition::Continue => SessionEvent::BackendResponsePart,
            // A MORE_RESULTS terminator carries an authoritative status that
            // Go applies immediately (`handleOKPacket`/`handleEOFPacket` run
            // per result, not per command), so the FSM must see it mid-flight
            // (SES-07).
            ResponseDisposition::MoreResults => {
                if self.in_transaction {
                    SessionEvent::BackendResponsePartTxnOpen
                } else {
                    SessionEvent::BackendResponsePartTxnDone
                }
            }
            ResponseDisposition::LocalInfile => SessionEvent::BackendLocalInfileRequest,
            // An ERR carries no server status: the FSM decides the
            // boundary on its retained state and unknown-state knowledge
            // is not restored (SES-07).
            ResponseDisposition::CompleteError { .. } => SessionEvent::BackendResponseErrorComplete,
            ResponseDisposition::CompleteSuccess | ResponseDisposition::CompleteRaw => {
                if self.in_transaction {
                    SessionEvent::BackendResponseTxnOpen
                } else {
                    SessionEvent::BackendResponseTxnDone
                }
            }
        }
    }
}

/// Typed, payload-free response-observer failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseObserverError {
    /// The command completes without a backend response.
    NoResponseExpected,
    /// A sibling SES issue owns this special response flow.
    DeferredFlow {
        /// Dispatch contract deliberately not interpreted here.
        expected: ExpectedResponse,
    },
    /// Streaming adapter metadata violates the logical-packet contract.
    InvalidPacketMetadata {
        /// Static diagnostic; no payload bytes are retained.
        reason: &'static str,
    },
    /// Structured OK/ERR/EOF prefix is malformed.
    MalformedPacket(DecodeError),
    /// The header is not valid in the current contextual state.
    UnexpectedPacket {
        /// Observer state before rejection.
        state: ObserverState,
        /// First byte, or `None` for an empty logical payload.
        first_byte: Option<u8>,
        /// First physical payload length used for EOF classification.
        first_physical_payload_bytes: u32,
    },
    /// A packet arrived after the terminal boundary.
    AlreadyComplete,
    /// Constant-size accounting overflowed.
    CounterOverflow {
        /// Counter that could not represent the next value.
        field: &'static str,
    },
}

impl fmt::Display for ResponseObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoResponseExpected => formatter.write_str("command has no backend response"),
            Self::DeferredFlow { expected } => {
                write!(
                    formatter,
                    "response flow {expected:?} belongs to a sibling SES module"
                )
            }
            Self::InvalidPacketMetadata { reason } => {
                write!(formatter, "invalid forwarded packet metadata: {reason}")
            }
            Self::MalformedPacket(error) => {
                write!(formatter, "malformed backend response: {error}")
            }
            Self::UnexpectedPacket {
                state,
                first_byte,
                first_physical_payload_bytes,
            } => write!(
                formatter,
                "unexpected backend response {first_byte:?} with first physical length \
                 {first_physical_payload_bytes} in state {state:?}"
            ),
            Self::AlreadyComplete => formatter.write_str("backend response is already complete"),
            Self::CounterOverflow { field } => write!(formatter, "{field} counter overflow"),
        }
    }
}

impl std::error::Error for ResponseObserverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedPacket(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DecodeError> for ResponseObserverError {
    fn from(error: DecodeError) -> Self {
        Self::MalformedPacket(error)
    }
}

#[derive(Debug, Clone, Copy)]
struct Observation {
    state: ObserverState,
    role: PacketRole,
    disposition: ResponseDisposition,
    status: Option<StatusFlags>,
    protocol_boundary: bool,
}

/// Constant-size state for one ordinary command response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseObserver {
    state: ObserverState,
    capabilities: CapabilityFlags,
    in_transaction: bool,
    flush_threshold: NonZeroU64,
    pending_wire_bytes: u64,
    logical_packets: u64,
    physical_packets: u64,
    logical_payload_bytes: u64,
    forwarded_wire_bytes: u64,
}

impl ResponseObserver {
    /// Selects the response machine from SES-03 dispatch.
    ///
    /// # Errors
    ///
    /// Rejects no-response commands and special flows owned by SES-05/SES-06.
    pub fn new(
        expected: ExpectedResponse,
        capabilities: CapabilityFlags,
        in_transaction: bool,
        flush_threshold: NonZeroU64,
    ) -> Result<Self, ResponseObserverError> {
        let state = match expected {
            ExpectedResponse::None => return Err(ResponseObserverError::NoResponseExpected),
            ExpectedResponse::OnePacket => ObserverState::OnePacket,
            ExpectedResponse::Query => ObserverState::QueryStart,
            ExpectedResponse::FieldList => ObserverState::FieldList,
            ExpectedResponse::Statistics => ObserverState::Statistics,
            ExpectedResponse::Fetch => ObserverState::FetchRows,
            ExpectedResponse::ChangeUser | ExpectedResponse::Prepare => {
                return Err(ResponseObserverError::DeferredFlow { expected });
            }
        };
        Ok(Self {
            state,
            capabilities,
            in_transaction,
            flush_threshold,
            pending_wire_bytes: 0,
            logical_packets: 0,
            physical_packets: 0,
            logical_payload_bytes: 0,
            forwarded_wire_bytes: 0,
        })
    }

    /// Current contextual response state.
    #[must_use]
    pub const fn state(&self) -> ObserverState {
        self.state
    }

    /// Whether the last applied terminal status says a transaction is open.
    #[must_use]
    pub const fn in_transaction(&self) -> bool {
        self.in_transaction
    }

    /// Whether the command response reached its terminal boundary.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, ObserverState::Complete)
    }

    /// Wire bytes currently retained since the last instructed flush.
    #[must_use]
    pub const fn pending_wire_bytes(&self) -> u64 {
        self.pending_wire_bytes
    }

    /// Complete logical packets observed.
    #[must_use]
    pub const fn logical_packets(&self) -> u64 {
        self.logical_packets
    }

    /// Complete physical packets observed.
    #[must_use]
    pub const fn physical_packets(&self) -> u64 {
        self.physical_packets
    }

    /// Logical payload bytes observed without retaining them.
    #[must_use]
    pub const fn logical_payload_bytes(&self) -> u64 {
        self.logical_payload_bytes
    }

    /// Total payload plus physical-header bytes observed.
    #[must_use]
    pub const fn forwarded_wire_bytes(&self) -> u64 {
        self.forwarded_wire_bytes
    }

    /// The observer itself retains no response payload bytes.
    #[must_use]
    pub const fn retained_payload_bytes(&self) -> usize {
        0
    }

    /// Observes one already-forwarded logical backend packet.
    ///
    /// Classification and counter arithmetic finish before any state mutates,
    /// so a malformed packet or overflow leaves the observer unchanged.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a malformed structured packet, an impossible
    /// header in the current state, post-completion traffic, or overflow.
    pub fn observe_backend(
        &mut self,
        packet: ResponsePacket<'_>,
    ) -> Result<ResponseEffect, ResponseObserverError> {
        if self.is_complete() {
            return Err(ResponseObserverError::AlreadyComplete);
        }
        let observation = self.classify(packet)?;

        let logical_packets =
            self.logical_packets
                .checked_add(1)
                .ok_or(ResponseObserverError::CounterOverflow {
                    field: "logical packets",
                })?;
        let physical_packets = self
            .physical_packets
            .checked_add(packet.physical_packets())
            .ok_or(ResponseObserverError::CounterOverflow {
                field: "physical packets",
            })?;
        let logical_payload_bytes = self
            .logical_payload_bytes
            .checked_add(packet.logical_payload_bytes())
            .ok_or(ResponseObserverError::CounterOverflow {
                field: "logical payload bytes",
            })?;
        let forwarded_wire_bytes = self
            .forwarded_wire_bytes
            .checked_add(packet.forwarded_wire_bytes())
            .ok_or(ResponseObserverError::CounterOverflow {
                field: "forwarded wire bytes",
            })?;
        let pending_wire_bytes = self
            .pending_wire_bytes
            .checked_add(packet.forwarded_wire_bytes())
            .ok_or(ResponseObserverError::CounterOverflow {
                field: "pending wire bytes",
            })?;

        let (flush, pending_wire_bytes) = if observation.protocol_boundary {
            (FlushAction::ProtocolBoundary, 0)
        } else if pending_wire_bytes >= self.flush_threshold.get() {
            (FlushAction::ConfiguredThreshold, 0)
        } else {
            (FlushAction::None, pending_wire_bytes)
        };

        self.state = observation.state;
        if let Some(status) = observation.status {
            self.in_transaction = status.contains(StatusFlags::IN_TRANS);
        }
        self.logical_packets = logical_packets;
        self.physical_packets = physical_packets;
        self.logical_payload_bytes = logical_payload_bytes;
        self.forwarded_wire_bytes = forwarded_wire_bytes;
        self.pending_wire_bytes = pending_wire_bytes;

        Ok(ResponseEffect {
            role: observation.role,
            disposition: observation.disposition,
            status: observation.status,
            in_transaction: self.in_transaction,
            flush,
        })
    }

    fn classify(&self, packet: ResponsePacket<'_>) -> Result<Observation, ResponseObserverError> {
        match self.state {
            ObserverState::OnePacket => self.classify_one_packet(packet),
            ObserverState::QueryStart => self.classify_query_start(packet),
            ObserverState::QueryClassicColumns => Self::classify_classic_columns(packet),
            ObserverState::QueryClassicRows => self.classify_classic_rows(packet),
            ObserverState::QueryDeprecateData => self.classify_deprecate_data(packet),
            ObserverState::FieldList => {
                self.classify_result_end(packet, PacketRole::ColumnDefinition)
            }
            ObserverState::FetchRows => self.classify_result_end(packet, PacketRole::Row),
            ObserverState::Statistics => Ok(Observation {
                state: ObserverState::Complete,
                role: PacketRole::Raw,
                disposition: ResponseDisposition::CompleteRaw,
                status: None,
                protocol_boundary: true,
            }),
            ObserverState::AwaitLocalInfileFinal => self.classify_local_infile_final(packet),
            ObserverState::Complete => Err(ResponseObserverError::AlreadyComplete),
        }
    }

    fn classify_one_packet(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        match packet.first_byte() {
            Some(byte) if byte == ResponseHeader::OK.as_byte() => {
                let status = self.parse_ok_status(packet)?;
                Ok(Self::complete_success(PacketRole::Ok, status))
            }
            Some(byte) if byte == ResponseHeader::ERROR.as_byte() => self.complete_error(packet),
            Some(byte) if byte == ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte() => {
                let status = if self.capabilities.contains(CapabilityFlags::DEPRECATE_EOF) {
                    self.parse_ok_status(packet)?
                } else {
                    parse_legacy_eof_status(packet.prefix())?
                };
                Ok(Self::complete_success(PacketRole::Terminator, status))
            }
            _ => Err(self.unexpected(packet)),
        }
    }

    fn classify_query_start(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        match packet.first_byte() {
            Some(byte) if byte == ResponseHeader::OK.as_byte() => {
                let status = self.parse_ok_status(packet)?;
                Ok(Self::finish_query_result(PacketRole::Ok, status))
            }
            Some(byte) if byte == ResponseHeader::ERROR.as_byte() => self.complete_error(packet),
            Some(byte) if byte == ResponseHeader::LOCAL_INFILE.as_byte() => Ok(Observation {
                state: ObserverState::AwaitLocalInfileFinal,
                role: PacketRole::LocalInfileRequest,
                disposition: ResponseDisposition::LocalInfile,
                status: None,
                protocol_boundary: true,
            }),
            Some(_) => Ok(Observation {
                state: if self.capabilities.contains(CapabilityFlags::DEPRECATE_EOF) {
                    ObserverState::QueryDeprecateData
                } else {
                    ObserverState::QueryClassicColumns
                },
                role: PacketRole::ResultsetHeader,
                disposition: ResponseDisposition::Continue,
                status: None,
                protocol_boundary: false,
            }),
            None => Err(self.unexpected(packet)),
        }
    }

    fn classify_classic_columns(
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        if is_classic_eof(packet) {
            let status = parse_eof_packet(packet.prefix())?.status;
            if status.contains(StatusFlags::CURSOR_EXISTS) {
                return Ok(Self::finish_query_result(PacketRole::Terminator, status));
            }
            // Go reads this status only to decide whether a cursor exists. A
            // metadata EOF without a cursor neither updates session status nor
            // flushes; the row terminator remains authoritative.
            return Ok(Observation {
                state: ObserverState::QueryClassicRows,
                role: PacketRole::Terminator,
                disposition: ResponseDisposition::Continue,
                status: None,
                protocol_boundary: false,
            });
        }
        Ok(Observation {
            state: ObserverState::QueryClassicColumns,
            role: PacketRole::ColumnDefinition,
            disposition: ResponseDisposition::Continue,
            status: None,
            protocol_boundary: false,
        })
    }

    fn classify_classic_rows(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        if packet.first_byte() == Some(ResponseHeader::ERROR.as_byte()) {
            return self.complete_error(packet);
        }
        if is_classic_eof(packet) {
            let status = parse_eof_packet(packet.prefix())?.status;
            return Ok(Self::finish_query_result(PacketRole::Terminator, status));
        }
        Ok(Observation {
            state: ObserverState::QueryClassicRows,
            role: PacketRole::Row,
            disposition: ResponseDisposition::Continue,
            status: None,
            protocol_boundary: false,
        })
    }

    fn classify_deprecate_data(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        if packet.first_byte() == Some(ResponseHeader::ERROR.as_byte()) {
            return self.complete_error(packet);
        }
        if is_resultset_ok(packet) {
            let status = self.parse_ok_status(packet)?;
            return Ok(Self::finish_query_result(PacketRole::Terminator, status));
        }
        Ok(Observation {
            state: ObserverState::QueryDeprecateData,
            role: PacketRole::ResultsetData,
            disposition: ResponseDisposition::Continue,
            status: None,
            protocol_boundary: false,
        })
    }

    fn classify_result_end(
        &self,
        packet: ResponsePacket<'_>,
        data_role: PacketRole,
    ) -> Result<Observation, ResponseObserverError> {
        if packet.first_byte() == Some(ResponseHeader::ERROR.as_byte()) {
            return self.complete_error(packet);
        }
        let status = if self.capabilities.contains(CapabilityFlags::DEPRECATE_EOF) {
            is_resultset_ok(packet)
                .then(|| self.parse_ok_status(packet))
                .transpose()?
        } else {
            is_classic_eof(packet)
                .then(|| parse_eof_packet(packet.prefix()).map(|eof| eof.status))
                .transpose()?
        };
        if let Some(status) = status {
            return Ok(Self::complete_success(PacketRole::Terminator, status));
        }
        Ok(Observation {
            state: self.state,
            role: data_role,
            disposition: ResponseDisposition::Continue,
            status: None,
            protocol_boundary: false,
        })
    }

    fn classify_local_infile_final(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        match packet.first_byte() {
            Some(byte) if byte == ResponseHeader::OK.as_byte() => {
                let status = self.parse_ok_status(packet)?;
                Ok(Self::finish_query_result(PacketRole::Ok, status))
            }
            Some(byte) if byte == ResponseHeader::ERROR.as_byte() => self.complete_error(packet),
            _ => Err(self.unexpected(packet)),
        }
    }

    fn parse_ok_status(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<StatusFlags, ResponseObserverError> {
        Ok(parse_ok_packet(packet.prefix(), self.capabilities)?.status)
    }

    fn complete_error(
        &self,
        packet: ResponsePacket<'_>,
    ) -> Result<Observation, ResponseObserverError> {
        let error = parse_error_packet(packet.prefix(), self.capabilities)?;
        Ok(Observation {
            state: ObserverState::Complete,
            role: PacketRole::Error,
            disposition: ResponseDisposition::CompleteError { code: error.code },
            status: None,
            protocol_boundary: true,
        })
    }

    const fn complete_success(role: PacketRole, status: StatusFlags) -> Observation {
        Observation {
            state: ObserverState::Complete,
            role,
            disposition: ResponseDisposition::CompleteSuccess,
            status: Some(status),
            protocol_boundary: true,
        }
    }

    const fn finish_query_result(role: PacketRole, status: StatusFlags) -> Observation {
        if status.contains(StatusFlags::MORE_RESULTS_EXISTS) {
            Observation {
                state: ObserverState::QueryStart,
                role,
                disposition: ResponseDisposition::MoreResults,
                status: Some(status),
                protocol_boundary: true,
            }
        } else {
            Self::complete_success(role, status)
        }
    }

    fn unexpected(&self, packet: ResponsePacket<'_>) -> ResponseObserverError {
        ResponseObserverError::UnexpectedPacket {
            state: self.state,
            first_byte: packet.first_byte(),
            first_physical_payload_bytes: packet.first_physical_payload_bytes(),
        }
    }
}

fn is_classic_eof(packet: ResponsePacket<'_>) -> bool {
    packet.first_byte() == Some(ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte())
        && packet.first_physical_payload_bytes() <= 5
}

fn is_resultset_ok(packet: ResponsePacket<'_>) -> bool {
    packet.first_byte() == Some(ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte())
        && packet.first_physical_payload_bytes() >= 7
        && packet.first_physical_payload_bytes() < MAX_PAYLOAD_LEN
}

fn parse_legacy_eof_status(prefix: &[u8]) -> Result<StatusFlags, DecodeError> {
    if prefix.first().copied() != Some(ResponseHeader::EOF_OR_AUTH_SWITCH.as_byte()) {
        return Err(DecodeError::InvalidValue {
            field: "EOF packet header",
            offset: 0,
            value: prefix.first().copied().unwrap_or_default(),
        });
    }
    let status = prefix.get(3..5).ok_or(DecodeError::UnexpectedEof {
        field: "EOF server status",
        offset: 3,
        needed: 2,
        remaining: prefix.len().saturating_sub(3),
    })?;
    Ok(StatusFlags::from_bits_retain(u16::from_le_bytes([
        status[0], status[1],
    ])))
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use mysql_wire::encode_eof_packet;

    use super::*;

    const LEGACY_CAPS: CapabilityFlags = CapabilityFlags::PROTOCOL_41;
    const MODERN_CAPS: CapabilityFlags =
        CapabilityFlags::PROTOCOL_41.union(CapabilityFlags::DEPRECATE_EOF);

    fn observer(
        expected: ExpectedResponse,
        capabilities: CapabilityFlags,
        in_transaction: bool,
        threshold: u64,
    ) -> ResponseObserver {
        let state = match expected {
            ExpectedResponse::OnePacket => ObserverState::OnePacket,
            ExpectedResponse::Query => ObserverState::QueryStart,
            ExpectedResponse::FieldList => ObserverState::FieldList,
            ExpectedResponse::Statistics => ObserverState::Statistics,
            ExpectedResponse::Fetch => ObserverState::FetchRows,
            ExpectedResponse::None | ExpectedResponse::ChangeUser | ExpectedResponse::Prepare => {
                ObserverState::Complete
            }
        };
        ResponseObserver {
            state,
            capabilities,
            in_transaction,
            flush_threshold: NonZeroU64::new(threshold).unwrap_or(NonZeroU64::MIN),
            pending_wire_bytes: 0,
            logical_packets: 0,
            physical_packets: 0,
            logical_payload_bytes: 0,
            forwarded_wire_bytes: 0,
        }
    }

    fn packet(payload: &[u8]) -> ResponsePacket<'_> {
        let logical_payload_bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let physical_packets = physical_packet_count(logical_payload_bytes);
        ResponsePacket {
            prefix: &payload[..payload.len().min(RESPONSE_OBSERVER_PREFIX_LIMIT)],
            logical_payload_bytes,
            first_physical_payload_bytes: u32::try_from(
                logical_payload_bytes.min(u64::from(MAX_PAYLOAD_LEN)),
            )
            .unwrap_or(MAX_PAYLOAD_LEN),
            physical_packets,
            forwarded_wire_bytes: logical_payload_bytes
                .saturating_add(physical_packets.saturating_mul(4)),
        }
    }

    fn ok(header: ResponseHeader, status: StatusFlags) -> Vec<u8> {
        let status = status.bits().to_le_bytes();
        vec![header.as_byte(), 0, 0, status[0], status[1], 0, 0]
    }

    fn error(code: u16) -> Vec<u8> {
        let code = code.to_le_bytes();
        let mut packet = vec![ResponseHeader::ERROR.as_byte(), code[0], code[1], b'#'];
        packet.extend_from_slice(b"HY000failure");
        packet
    }

    #[test]
    fn marker_meanings_are_contextual() -> Result<(), ResponseObserverError> {
        for (payload, role) in [
            (vec![0x00], PacketRole::ColumnDefinition),
            (vec![0x01], PacketRole::ColumnDefinition),
            (vec![0xfb], PacketRole::ColumnDefinition),
            (vec![0xfe, 0, 0, 0, 0, 0], PacketRole::ColumnDefinition),
        ] {
            let mut current = observer(ExpectedResponse::Query, LEGACY_CAPS, false, 1024);
            current.observe_backend(packet(&[1]))?;
            assert_eq!(current.observe_backend(packet(&payload))?.role, role);
        }

        for (payload, role) in [
            (vec![0x00], PacketRole::Row),
            (vec![0x01], PacketRole::Row),
            (vec![0xfb], PacketRole::Row),
            (vec![0xfe, 0, 0, 0, 0, 0], PacketRole::Row),
        ] {
            let mut current = observer(ExpectedResponse::Query, LEGACY_CAPS, false, 1024);
            current.observe_backend(packet(&[1]))?;
            current.observe_backend(packet(&encode_eof_packet(0, StatusFlags::AUTOCOMMIT)))?;
            assert_eq!(current.observe_backend(packet(&payload))?.role, role);
        }

        for (payload, role) in [
            (vec![0x00], PacketRole::ResultsetData),
            (vec![0x01], PacketRole::ResultsetData),
            (vec![0xfb], PacketRole::ResultsetData),
            (vec![0xfe, 0, 0, 0, 0, 0], PacketRole::ResultsetData),
        ] {
            let mut current = observer(ExpectedResponse::Query, MODERN_CAPS, false, 1024);
            current.observe_backend(packet(&[1]))?;
            assert_eq!(current.observe_backend(packet(&payload))?.role, role);
        }

        let mut query = observer(ExpectedResponse::Query, LEGACY_CAPS, false, 1024);
        assert_eq!(
            query.observe_backend(packet(b"\xfbfile"))?.disposition,
            ResponseDisposition::LocalInfile
        );
        let mut query = observer(ExpectedResponse::Query, LEGACY_CAPS, false, 1024);
        assert_eq!(
            query.observe_backend(packet(&[0x01]))?.role,
            PacketRole::ResultsetHeader
        );
        let mut query = observer(ExpectedResponse::Query, LEGACY_CAPS, false, 1024);
        assert_eq!(
            query.observe_backend(packet(&[0xfe, 0, 0, 0, 0]))?.role,
            PacketRole::ResultsetHeader
        );

        for expected in [ExpectedResponse::FieldList, ExpectedResponse::Fetch] {
            for marker in [0x00, 0x01, 0xfb] {
                let mut current = observer(expected, LEGACY_CAPS, false, 1024);
                assert_eq!(
                    current.observe_backend(packet(&[marker]))?.disposition,
                    ResponseDisposition::Continue
                );
            }
            let mut classic = observer(expected, LEGACY_CAPS, false, 1024);
            assert_eq!(
                classic
                    .observe_backend(packet(&[0xfe, 0, 0, 0, 0, 0]))?
                    .disposition,
                ResponseDisposition::Continue
            );
            for payload in [
                vec![0x00],
                vec![0x01],
                vec![0xfb],
                vec![0xfe, 0, 0, 0, 0, 0],
            ] {
                let mut modern = observer(expected, MODERN_CAPS, false, 1024);
                assert_eq!(
                    modern.observe_backend(packet(&payload))?.disposition,
                    ResponseDisposition::Continue
                );
            }
        }
        Ok(())
    }

    #[test]
    fn classic_resultset_tracks_cursor_rows_and_multi_results() -> Result<(), ResponseObserverError>
    {
        let more = StatusFlags::AUTOCOMMIT | StatusFlags::MORE_RESULTS_EXISTS;
        let mut current = observer(ExpectedResponse::Query, LEGACY_CAPS, true, 4096);
        assert_eq!(
            current.observe_backend(packet(&[1]))?.role,
            PacketRole::ResultsetHeader
        );
        current.observe_backend(packet(b"column"))?;
        let metadata = current.observe_backend(packet(&encode_eof_packet(0, more)))?;
        assert_eq!(metadata.status, None);
        assert_eq!(metadata.flush, FlushAction::None);
        assert!(metadata.in_transaction);

        current.observe_backend(packet(b"\x011"))?;
        let first_end = current.observe_backend(packet(&encode_eof_packet(0, more)))?;
        assert_eq!(first_end.disposition, ResponseDisposition::MoreResults);
        assert_eq!(first_end.flush, FlushAction::ProtocolBoundary);
        assert!(!first_end.in_transaction);
        assert_eq!(current.state(), ObserverState::QueryStart);

        let final_ok = ok(ResponseHeader::OK, StatusFlags::AUTOCOMMIT);
        assert_eq!(
            current.observe_backend(packet(&final_ok))?.disposition,
            ResponseDisposition::CompleteSuccess
        );

        let cursor_status = StatusFlags::AUTOCOMMIT | StatusFlags::CURSOR_EXISTS;
        let mut cursor = observer(ExpectedResponse::Query, LEGACY_CAPS, false, 4096);
        cursor.observe_backend(packet(&[1]))?;
        cursor.observe_backend(packet(b"column"))?;
        let end = cursor.observe_backend(packet(&encode_eof_packet(0, cursor_status)))?;
        assert_eq!(end.status, Some(cursor_status));
        assert!(cursor.is_complete());
        Ok(())
    }

    #[test]
    fn deprecated_eof_resultset_recognizes_only_protocol_length_terminator()
    -> Result<(), ResponseObserverError> {
        let more = StatusFlags::AUTOCOMMIT | StatusFlags::MORE_RESULTS_EXISTS;
        let mut current = observer(ExpectedResponse::Query, MODERN_CAPS, false, 4096);
        current.observe_backend(packet(&[1]))?;
        assert_eq!(
            current
                .observe_backend(packet(&[0xfe, 0, 0, 0, 0, 0]))?
                .role,
            PacketRole::ResultsetData
        );
        let maximum_prefix = [0xfe; RESPONSE_OBSERVER_PREFIX_LIMIT];
        let maximum_packet = ResponsePacket::from_forwarded(
            &maximum_prefix,
            u64::from(MAX_PAYLOAD_LEN),
            MAX_PAYLOAD_LEN,
            2,
        )?;
        assert_eq!(
            current.observe_backend(maximum_packet)?.role,
            PacketRole::ResultsetData
        );
        let first = ok(ResponseHeader::EOF_OR_AUTH_SWITCH, more);
        assert_eq!(
            current.observe_backend(packet(&first))?.disposition,
            ResponseDisposition::MoreResults
        );
        current.observe_backend(packet(&[1]))?;
        current.observe_backend(packet(b"column"))?;
        let final_packet = ok(ResponseHeader::EOF_OR_AUTH_SWITCH, StatusFlags::AUTOCOMMIT);
        assert_eq!(
            current.observe_backend(packet(&final_packet))?.disposition,
            ResponseDisposition::CompleteSuccess
        );
        Ok(())
    }

    #[test]
    fn errors_are_nonfatal_command_results_and_preserve_transaction()
    -> Result<(), ResponseObserverError> {
        for expected in [
            ExpectedResponse::OnePacket,
            ExpectedResponse::Query,
            ExpectedResponse::FieldList,
            ExpectedResponse::Fetch,
        ] {
            let mut current = observer(expected, LEGACY_CAPS, true, 1024);
            let effect = current.observe_backend(packet(&error(1064)))?;
            assert_eq!(
                effect.disposition,
                ResponseDisposition::CompleteError { code: 1064 }
            );
            assert!(effect.in_transaction);
            assert_eq!(effect.status, None);
            // SES-07: statusless ERR maps to its own completion event so
            // the FSM decides the boundary on retained state and never
            // restores unknown-state knowledge from an ERR.
            assert_eq!(
                effect.session_event(),
                SessionEvent::BackendResponseErrorComplete
            );
        }
        Ok(())
    }

    #[test]
    fn generic_one_packet_accepts_shared_ok_error_and_eof_contract()
    -> Result<(), ResponseObserverError> {
        for payload in [
            ok(ResponseHeader::OK, StatusFlags::IN_TRANS),
            encode_eof_packet(0, StatusFlags::AUTOCOMMIT).to_vec(),
        ] {
            let mut current = observer(ExpectedResponse::OnePacket, LEGACY_CAPS, false, 1024);
            let effect = current.observe_backend(packet(&payload))?;
            assert_eq!(effect.disposition, ResponseDisposition::CompleteSuccess);
            assert_eq!(effect.flush, FlushAction::ProtocolBoundary);
        }
        let mut modern = observer(ExpectedResponse::OnePacket, MODERN_CAPS, false, 1024);
        let eof_ok = ok(ResponseHeader::EOF_OR_AUTH_SWITCH, StatusFlags::AUTOCOMMIT);
        assert_eq!(
            modern.observe_backend(packet(&eof_ok))?.role,
            PacketRole::Terminator
        );
        Ok(())
    }

    #[test]
    fn field_list_and_fetch_apply_their_terminal_status() -> Result<(), ResponseObserverError> {
        let final_status = StatusFlags::AUTOCOMMIT | StatusFlags::LAST_ROW_SENT;
        for (expected, role) in [
            (ExpectedResponse::FieldList, PacketRole::ColumnDefinition),
            (ExpectedResponse::Fetch, PacketRole::Row),
        ] {
            let mut current = observer(expected, LEGACY_CAPS, true, 1024);
            assert_eq!(current.observe_backend(packet(b"data"))?.role, role);
            let effect = current.observe_backend(packet(&encode_eof_packet(0, final_status)))?;
            assert_eq!(effect.status, Some(final_status));
            assert!(!effect.in_transaction);
            assert!(current.is_complete());
        }
        Ok(())
    }

    #[test]
    fn local_infile_handoff_accepts_only_final_ok_or_error() -> Result<(), ResponseObserverError> {
        let mut current = observer(ExpectedResponse::Query, LEGACY_CAPS, true, 1024);
        let request = current.observe_backend(packet(b"\xfbsynthetic.csv"))?;
        assert_eq!(request.disposition, ResponseDisposition::LocalInfile);
        assert_eq!(request.flush, FlushAction::ProtocolBoundary);
        assert_eq!(
            request.session_event(),
            SessionEvent::BackendLocalInfileRequest
        );
        assert!(matches!(
            current.observe_backend(packet(b"unexpected")),
            Err(ResponseObserverError::UnexpectedPacket {
                state: ObserverState::AwaitLocalInfileFinal,
                ..
            })
        ));
        assert_eq!(current.state(), ObserverState::AwaitLocalInfileFinal);
        let final_ok = ok(ResponseHeader::OK, StatusFlags::AUTOCOMMIT);
        assert_eq!(
            current.observe_backend(packet(&final_ok))?.disposition,
            ResponseDisposition::CompleteSuccess
        );
        Ok(())
    }

    #[test]
    fn malformed_terminal_prefixes_are_typed_and_do_not_mutate_state() {
        for payload in [vec![0x00], vec![0xff, 1], vec![0xfe, 0, 0, 0]] {
            let mut current = observer(ExpectedResponse::OnePacket, LEGACY_CAPS, true, 1024);
            let before = current.clone();
            assert!(matches!(
                current.observe_backend(packet(&payload)),
                Err(ResponseObserverError::MalformedPacket(_))
            ));
            assert_eq!(current, before);
        }
        assert!(matches!(
            ResponsePacket::from_forwarded(&[0], 100, 100, 1),
            Err(ResponseObserverError::InvalidPacketMetadata { .. })
        ));
    }

    #[test]
    fn flushes_only_at_threshold_or_protocol_boundary() -> Result<(), ResponseObserverError> {
        let mut current = observer(ExpectedResponse::Fetch, LEGACY_CAPS, false, 12);
        assert_eq!(
            current.observe_backend(packet(b"a"))?.flush,
            FlushAction::None
        );
        assert_eq!(current.pending_wire_bytes(), 5);
        assert_eq!(
            current.observe_backend(packet(b"b"))?.flush,
            FlushAction::None
        );
        assert_eq!(
            current.observe_backend(packet(b"c"))?.flush,
            FlushAction::ConfiguredThreshold
        );
        assert_eq!(current.pending_wire_bytes(), 0);
        let end =
            current.observe_backend(packet(&encode_eof_packet(0, StatusFlags::AUTOCOMMIT)))?;
        assert_eq!(end.flush, FlushAction::ProtocolBoundary);
        assert_eq!(current.pending_wire_bytes(), 0);
        Ok(())
    }

    #[test]
    fn million_rows_use_constant_observer_memory() -> Result<(), ResponseObserverError> {
        let mut current = observer(ExpectedResponse::Fetch, LEGACY_CAPS, false, u64::MAX);
        let observer_bytes = size_of::<ResponseObserver>();
        for _ in 0..1_000_000 {
            let effect = current.observe_backend(packet(&[0x01]))?;
            assert_eq!(effect.role, PacketRole::Row);
        }
        let end =
            current.observe_backend(packet(&encode_eof_packet(0, StatusFlags::AUTOCOMMIT)))?;
        assert_eq!(end.disposition, ResponseDisposition::CompleteSuccess);
        assert_eq!(size_of::<ResponseObserver>(), observer_bytes);
        assert_eq!(current.retained_payload_bytes(), 0);
        assert_eq!(current.logical_packets(), 1_000_001);
        assert_eq!(current.physical_packets(), 1_000_001);
        assert_eq!(current.logical_payload_bytes(), 1_000_005);
        assert_eq!(current.forwarded_wire_bytes(), 5_000_009);
        Ok(())
    }

    #[test]
    fn unsupported_sibling_flows_are_explicit() {
        assert_eq!(
            ResponseObserver::new(
                ExpectedResponse::None,
                LEGACY_CAPS,
                false,
                DEFAULT_RESPONSE_FLUSH_THRESHOLD,
            ),
            Err(ResponseObserverError::NoResponseExpected)
        );
        for expected in [ExpectedResponse::Prepare, ExpectedResponse::ChangeUser] {
            assert!(matches!(
                ResponseObserver::new(
                    expected,
                    LEGACY_CAPS,
                    false,
                    DEFAULT_RESPONSE_FLUSH_THRESHOLD,
                ),
                Err(ResponseObserverError::DeferredFlow { expected: got }) if got == expected
            ));
        }
    }
}
