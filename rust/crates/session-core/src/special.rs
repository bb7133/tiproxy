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

//! Special duplex flows (SES-06): the LOCAL INFILE client upload and the
//! `COM_CHANGE_USER` reauthentication relay, frozen from Go
//! `cmd_processor_exec.go::forwardLoadInFile`/`forwardChangeUserCmd`.
//!
//! Both flows reverse the ordinary request→response direction:
//!
//! - **LOCAL INFILE**: after the backend's `0xfb` request (observed by the
//!   SES-04 observer, which then parks in its final-response state), the
//!   *client* streams file packets until a terminating empty packet; only
//!   then does the backend answer with the final OK/ERR. [`LocalInfileUpload`]
//!   owns the upload turns; the final packet goes back through the SES-04
//!   observer (`AwaitLocalInfileFinal`), which also handles `MORE_RESULTS`.
//! - **`COM_CHANGE_USER`**: the request is *rewritten* before forwarding —
//!   Go replaces the plugin with [`UNKNOWN_AUTH_PLUGIN`] and **drops the
//!   client's auth data** (`req.AuthData = nil`, tiproxy#127) so the backend
//!   issues a fresh auth-switch carrying its own salt. The subsequent
//!   backend↔client exchange is relayed untouched. Only a final OK commits
//!   the pending identity (user/database/attributes); ERR keeps the previous
//!   identity, exactly like Go applying `changeUser` only when `err == nil`.
//!
//! Secret hygiene mirrors SES-02: no event, effect, error, or retained state
//! carries authentication bytes. The rewritten change-user packet contains
//! **no auth data by construction**, and the pending identity redacts its
//! attribute bytes from `Debug` output.
//!
//! Go-parity notes:
//! - Go forwards the LOCAL INFILE flow regardless of the negotiated
//!   `LOCAL_FILES` capability (`TiDB` enforces the feature); the relay does
//!   the same and only exposes [`local_infile_negotiated`] so the runtime
//!   can log the mismatch. Bounded termination is unconditional.
//! - Go reads nothing from the backend during the upload (it deliberately
//!   avoids `ForwardUntil`'s five-byte peek because an empty packet has only
//!   four header bytes); backend events during the upload are illegal here.
//! - `COM_STATISTICS` needs no sub-machine: Go forwards one raw packet, and
//!   the SES-04 observer's `Statistics` state already models it. A pin test
//!   documents that decision.

use core::fmt;

use mysql_wire::{
    Attribute, CapabilityFlags, ChangeUser, ChangeUserParams, DecodeError, encode_change_user,
    parse_change_user, parse_ok_packet,
};

use crate::auth::UNKNOWN_AUTH_PLUGIN;
use crate::command::CurrentDatabaseState;
use crate::fsm::SessionEvent;
use crate::response::RESPONSE_OBSERVER_PREFIX_LIMIT;

/// Whether the session negotiated `LOCAL_FILES`. Go forwards the flow
/// regardless (`TiDB` enforces the capability); this exists for runtime
/// logging and tests only.
#[must_use]
pub const fn local_infile_negotiated(capabilities: CapabilityFlags) -> bool {
    capabilities.contains(CapabilityFlags::LOCAL_FILES)
}

/// Turn state of one LOCAL INFILE client upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadTurn {
    /// The client owns the direction and streams file packets.
    ClientStreaming,
    /// The terminating empty packet was forwarded; the backend owns the
    /// final OK/ERR, which the SES-04 observer consumes.
    AwaitingFinal,
    /// The upload ended without reaching the backend-final phase.
    Aborted,
}

/// Classified upload events. No variant carries file bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadEvent {
    /// A non-empty client file packet arrived; `payload_bytes` is its
    /// logical payload length and `physical_packets` the frame count.
    ClientFileChunk {
        /// Logical payload bytes of this chunk.
        payload_bytes: u64,
        /// Physical frames carrying this chunk.
        physical_packets: u64,
    },
    /// The terminating empty client packet arrived.
    ClientUploadEnd,
    /// The client connection ended (EOF or error) mid-upload.
    ClientAborted,
}

/// Upload effects; forwarding refers to the runtime's buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadEffect {
    /// Forward the client file packet to the backend without flushing
    /// (Go batches the upload and flushes once at the end).
    ForwardChunkToBackend,
    /// Forward the empty terminator and flush the backend side
    /// (Go `backendIO.Flush` after the empty packet).
    ForwardTerminatorAndFlush,
    /// Close-path classification: the client vanished mid-upload.
    AbortUpload,
}

/// Typed upload failure. Carries counters only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadError {
    /// An event arrived on the wrong turn (including any backend packet
    /// during the client-owned phase, which Go never reads).
    IllegalTurn {
        /// The turn the upload was in.
        turn: UploadTurn,
    },
    /// A counter would overflow.
    CounterOverflow,
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTurn { turn } => write!(f, "illegal LOCAL INFILE event while {turn:?}"),
            Self::CounterOverflow => f.write_str("LOCAL INFILE counter overflow"),
        }
    }
}

impl std::error::Error for UploadError {}

/// The pure LOCAL INFILE upload machine (Go `forwardLoadInFile`'s client
/// loop). Holds counters only — file bytes never enter this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInfileUpload {
    turn: UploadTurn,
    chunks: u64,
    payload_bytes: u64,
    physical_packets: u64,
}

impl Default for LocalInfileUpload {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalInfileUpload {
    /// Starts an upload after the observer reported the `0xfb` request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            turn: UploadTurn::ClientStreaming,
            chunks: 0,
            payload_bytes: 0,
            physical_packets: 0,
        }
    }

    /// The current turn.
    #[must_use]
    pub const fn turn(&self) -> UploadTurn {
        self.turn
    }

    /// Non-empty chunks forwarded so far.
    #[must_use]
    pub const fn chunks(&self) -> u64 {
        self.chunks
    }

    /// Logical file payload bytes forwarded so far.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Physical frames forwarded so far.
    #[must_use]
    pub const fn physical_packets(&self) -> u64 {
        self.physical_packets
    }

    /// Applies one classified upload event.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError`] for wrong-turn events or counter overflow;
    /// the machine is unchanged.
    pub fn on_event(&mut self, event: UploadEvent) -> Result<UploadEffect, UploadError> {
        if self.turn != UploadTurn::ClientStreaming {
            return Err(UploadError::IllegalTurn { turn: self.turn });
        }
        match event {
            UploadEvent::ClientFileChunk {
                payload_bytes,
                physical_packets,
            } => {
                let chunks = self
                    .chunks
                    .checked_add(1)
                    .ok_or(UploadError::CounterOverflow)?;
                let payload_bytes = self
                    .payload_bytes
                    .checked_add(payload_bytes)
                    .ok_or(UploadError::CounterOverflow)?;
                let physical_packets = self
                    .physical_packets
                    .checked_add(physical_packets)
                    .ok_or(UploadError::CounterOverflow)?;
                self.chunks = chunks;
                self.payload_bytes = payload_bytes;
                self.physical_packets = physical_packets;
                Ok(UploadEffect::ForwardChunkToBackend)
            }
            UploadEvent::ClientUploadEnd => {
                self.turn = UploadTurn::AwaitingFinal;
                Ok(UploadEffect::ForwardTerminatorAndFlush)
            }
            UploadEvent::ClientAborted => {
                self.turn = UploadTurn::Aborted;
                Ok(UploadEffect::AbortUpload)
            }
        }
    }
}

/// Pending identity parsed from a `COM_CHANGE_USER` request. Committed only
/// on the backend's final OK; discarded on ERR. Attribute bytes are
/// redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingIdentity {
    username: Vec<u8>,
    database: Vec<u8>,
    attributes: Option<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl PendingIdentity {
    /// The pending username bytes.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// The pending database bytes (may be empty).
    #[must_use]
    pub fn database(&self) -> &[u8] {
        &self.database
    }

    /// The pending attribute pairs, when the client sent any.
    #[must_use]
    pub fn attributes(&self) -> Option<&[(Vec<u8>, Vec<u8>)]> {
        self.attributes.as_deref()
    }
}

impl fmt::Debug for PendingIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingIdentity")
            .field("username_bytes", &self.username.len())
            .field("database_bytes", &self.database.len())
            .field(
                "attribute_pairs",
                &self.attributes.as_ref().map_or(0, Vec::len),
            )
            .finish()
    }
}

/// The session identity SES-06 owns across reauthentication.
/// Attribute bytes are redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    username: Vec<u8>,
    database: CurrentDatabaseState,
    attributes: Option<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionIdentity")
            .field("username_bytes", &self.username.len())
            .field("database", &self.database)
            .field(
                "attribute_pairs",
                &self.attributes.as_ref().map_or(0, Vec::len),
            )
            .finish()
    }
}

impl SessionIdentity {
    /// Creates the identity from the initial handshake outcome. Go keeps
    /// the first `HandshakeResponse`'s attributes on the authenticator
    /// (`auth.attrs = clientResp.Attrs`), so they belong here from the
    /// start — a later change-user replaces them entirely (including
    /// clearing them when the new request carries none).
    #[must_use]
    pub fn new(
        username: &[u8],
        database: Option<&[u8]>,
        attributes: Option<&[(Vec<u8>, Vec<u8>)]>,
    ) -> Self {
        Self {
            username: username.to_vec(),
            database: database.map_or(CurrentDatabaseState::None, |database| {
                CurrentDatabaseState::Selected(database.to_vec())
            }),
            attributes: attributes.map(<[(Vec<u8>, Vec<u8>)]>::to_vec),
        }
    }

    /// Current connection-attribute pairs, when any were committed.
    #[must_use]
    pub fn attributes(&self) -> Option<&[(Vec<u8>, Vec<u8>)]> {
        self.attributes.as_deref()
    }

    /// Current username bytes.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// Current tracked database state (SES-03 semantics: migration must use
    /// `SHOW SESSION_STATES`, never this value).
    #[must_use]
    pub const fn database(&self) -> &CurrentDatabaseState {
        &self.database
    }

    /// Commits a successful change-user: Go `authenticator.changeUser`
    /// replaces user, dbname, **and attrs** (`authenticator.go:483-487`).
    pub fn apply_change_user(&mut self, pending: &PendingIdentity) {
        self.username.clone_from(&pending.username);
        self.database = if pending.database.is_empty() {
            CurrentDatabaseState::None
        } else {
            CurrentDatabaseState::Selected(pending.database.clone())
        };
        self.attributes.clone_from(&pending.attributes);
    }
}

/// The rewritten change-user plan.
pub struct ChangeUserPlan {
    /// The packet to forward to the backend: the client's request with the
    /// plugin replaced by [`UNKNOWN_AUTH_PLUGIN`] and **no auth data**.
    pub rewritten: Vec<u8>,
    /// Identity to commit if the backend finally answers OK.
    pub pending: PendingIdentity,
}

impl fmt::Debug for ChangeUserPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeUserPlan")
            .field("rewritten_bytes", &self.rewritten.len())
            .field("pending", &self.pending)
            .finish()
    }
}

/// Typed change-user failure. Never carries request bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeUserError {
    /// The request payload does not parse as `COM_CHANGE_USER`
    /// (Go returns `ErrMalformPacket`).
    Malformed,
    /// Re-encoding the rewritten request failed.
    RewriteFailed,
    /// An event arrived on the wrong relay turn.
    IllegalTurn {
        /// The turn the relay was in.
        turn: ChangeUserTurn,
    },
}

impl fmt::Display for ChangeUserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed COM_CHANGE_USER request"),
            Self::RewriteFailed => f.write_str("COM_CHANGE_USER rewrite failed"),
            Self::IllegalTurn { turn } => {
                write!(f, "illegal change-user event while {turn:?}")
            }
        }
    }
}

impl std::error::Error for ChangeUserError {}

/// Plans a change-user: parse with the session capability, then rewrite
/// with [`UNKNOWN_AUTH_PLUGIN`] and empty auth data (Go tiproxy#127 —
/// the backend must re-issue an auth switch with its own salt).
///
/// # Errors
///
/// Returns [`ChangeUserError`] for an oversized, unparsable, or
/// unrewritable request.
pub fn plan_change_user(
    payload: &[u8],
    capabilities: CapabilityFlags,
) -> Result<ChangeUserPlan, ChangeUserError> {
    // No size gate here: COM_CHANGE_USER is an ordinary command packet in
    // Go (the 1-MiB `maxHandshakePacketSize` cap applies only to the
    // pre-authentication handshake reads), so adding one would be an
    // undocumented divergence.
    let parsed: ChangeUser<'_> =
        parse_change_user(payload, capabilities).map_err(|_| ChangeUserError::Malformed)?;
    let attributes_entries: Option<Vec<Attribute<'_>>> = match parsed.attributes {
        Some(view) => Some(
            view.iter()
                .collect::<Result<Vec<_>, DecodeError>>()
                .map_err(|_| ChangeUserError::Malformed)?,
        ),
        None => None,
    };
    let rewritten = encode_change_user(
        ChangeUserParams {
            username: parsed.username,
            auth_response: &[],
            database: parsed.database,
            character_set: parsed.character_set,
            auth_plugin_name: Some(UNKNOWN_AUTH_PLUGIN),
            attributes: attributes_entries.as_deref(),
        },
        capabilities,
    )
    .map_err(|_| ChangeUserError::RewriteFailed)?;
    Ok(ChangeUserPlan {
        rewritten,
        pending: PendingIdentity {
            username: parsed.username.to_vec(),
            database: parsed.database.to_vec(),
            attributes: attributes_entries.as_ref().map(|entries| {
                entries
                    .iter()
                    .map(|attribute| (attribute.key.to_vec(), attribute.value.to_vec()))
                    .collect()
            }),
        },
    })
}

/// Whose packet the change-user relay expects next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeUserTurn {
    /// Waiting for a backend packet.
    AwaitingBackend,
    /// Waiting for the client's answer to relayed auth data.
    AwaitingClient,
    /// The relay finished.
    Finished,
}

/// Classified relay events (produced by
/// [`crate::auth::classify_backend_auth_packet`] for backend packets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeUserEvent {
    /// The backend accepted the reauthentication; carries the parsed OK
    /// status bits used for the transaction boundary.
    BackendOk {
        /// Whether the OK status still marks an open transaction.
        in_transaction: bool,
    },
    /// The backend rejected the reauthentication.
    BackendError {
        /// Backend `MySQL` error code.
        code: u16,
    },
    /// Any other backend packet (auth switch or extra data): relay it.
    BackendAuthData,
    /// The client's next auth packet arrived: relay it back.
    ClientAuthResponse,
}

/// Relay effects, in Go `forwardChangeUserCmd` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeUserEffect {
    /// Forward the backend packet to the client and flush.
    ForwardBackendToClient,
    /// Forward the client packet to the backend and flush.
    ForwardClientToBackend,
    /// Commit the pending identity and clear prepared state
    /// (SES-03 `PreparedMutation::ClearAll` fires on the same success).
    CommitPendingIdentity,
    /// Keep the previous identity (backend rejected the change).
    DiscardPendingIdentity,
}

/// One relay step: effects plus the session event at a terminal boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeUserStep {
    /// Effects in order.
    pub effects: Vec<ChangeUserEffect>,
    /// The SES-00 boundary event when this step finished the command.
    pub session_event: Option<SessionEvent>,
}

/// The pure change-user relay (Go `forwardChangeUserCmd`'s loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeUserRelay {
    turn: ChangeUserTurn,
    in_transaction_before: bool,
}

impl ChangeUserRelay {
    /// Starts after the rewritten request was forwarded to the backend.
    /// `in_transaction_before` is the transaction state retained from
    /// before the command: Go's `handleErrorPacket` never touches
    /// `serverStatus`, so a rejected change-user reaches its boundary
    /// with exactly that retained state.
    #[must_use]
    pub const fn new(in_transaction_before: bool) -> Self {
        Self {
            turn: ChangeUserTurn::AwaitingBackend,
            in_transaction_before,
        }
    }

    /// The current turn.
    #[must_use]
    pub const fn turn(&self) -> ChangeUserTurn {
        self.turn
    }

    /// Applies one classified event.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeUserError::IllegalTurn`] for wrong-turn events; the
    /// relay is unchanged.
    pub fn on_event(&mut self, event: ChangeUserEvent) -> Result<ChangeUserStep, ChangeUserError> {
        match (self.turn, event) {
            (ChangeUserTurn::AwaitingBackend, ChangeUserEvent::BackendOk { in_transaction }) => {
                self.turn = ChangeUserTurn::Finished;
                Ok(ChangeUserStep {
                    effects: vec![
                        ChangeUserEffect::ForwardBackendToClient,
                        ChangeUserEffect::CommitPendingIdentity,
                    ],
                    session_event: Some(if in_transaction {
                        SessionEvent::BackendResponseTxnOpen
                    } else {
                        SessionEvent::BackendResponseTxnDone
                    }),
                })
            }
            (ChangeUserTurn::AwaitingBackend, ChangeUserEvent::BackendError { .. }) => {
                self.turn = ChangeUserTurn::Finished;
                Ok(ChangeUserStep {
                    effects: vec![
                        ChangeUserEffect::ForwardBackendToClient,
                        ChangeUserEffect::DiscardPendingIdentity,
                    ],
                    // Go's handleErrorPacket leaves the transaction flag
                    // untouched, so the failure boundary is reached with
                    // the retained pre-command state — the session must
                    // still cross it (queued redirect/drain proceed).
                    session_event: Some(if self.in_transaction_before {
                        SessionEvent::BackendResponseTxnOpen
                    } else {
                        SessionEvent::BackendResponseTxnDone
                    }),
                })
            }
            (ChangeUserTurn::AwaitingBackend, ChangeUserEvent::BackendAuthData) => {
                self.turn = ChangeUserTurn::AwaitingClient;
                Ok(ChangeUserStep {
                    effects: vec![ChangeUserEffect::ForwardBackendToClient],
                    session_event: None,
                })
            }
            (ChangeUserTurn::AwaitingClient, ChangeUserEvent::ClientAuthResponse) => {
                self.turn = ChangeUserTurn::AwaitingBackend;
                Ok(ChangeUserStep {
                    effects: vec![ChangeUserEffect::ForwardClientToBackend],
                    session_event: None,
                })
            }
            (turn, _) => Err(ChangeUserError::IllegalTurn { turn }),
        }
    }
}

/// Parses the final change-user OK's transaction bit from a bounded prefix
/// (at most [`RESPONSE_OBSERVER_PREFIX_LIMIT`] bytes), for building
/// [`ChangeUserEvent::BackendOk`].
///
/// # Errors
///
/// Returns the wire decode error for a malformed OK prefix.
pub fn change_user_ok_in_transaction(
    prefix: &[u8],
    capabilities: CapabilityFlags,
) -> Result<bool, DecodeError> {
    let bounded = &prefix[..prefix.len().min(RESPONSE_OBSERVER_PREFIX_LIMIT)];
    Ok(parse_ok_packet(bounded, capabilities)?
        .status
        .contains(mysql_wire::StatusFlags::IN_TRANS))
}
