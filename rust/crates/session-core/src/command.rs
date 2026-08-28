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

//! Exhaustive `MySQL` command dispatch and response contracts (SES-03).
//!
//! The Go dataplane dispatches in `cmd_processor_exec.go::forwardCommand`.
//! This module freezes that switch as a pure, payload-borrowing plan:
//! no socket I/O is performed, command bytes never cross control IPC, and
//! the only retained command data is the `COM_INIT_DB` database slice until
//! the response succeeds.
//!
//! Every real Go command byte (`0x00..=0x1f`) is represented by [`Command`].
//! Go's `COM_END` constant (`0x20`) is an array-length sentinel, not a wire
//! command. It and future unknown bytes are rejected before forwarding; this
//! avoids Go's out-of-range command-metrics access while making the extension
//! policy explicit.

use core::fmt;

use mysql_wire::{CapabilityFlags, CommandCode, CommandPacket};

/// The fixed policy for command bytes outside `0x00..=0x1f`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownCommandPolicy {
    /// Reject the packet before forwarding it to a backend.
    Reject,
}

/// Unknown commands are rejected deterministically.
pub const UNKNOWN_COMMAND_POLICY: UnknownCommandPolicy = UnknownCommandPolicy::Reject;

/// Every real command declared by Go's `pkg/proxy/net/command.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Command {
    /// `COM_SLEEP` (`0x00`).
    Sleep = 0x00,
    /// `COM_QUIT` (`0x01`).
    Quit = 0x01,
    /// `COM_INIT_DB` (`0x02`).
    InitDb = 0x02,
    /// `COM_QUERY` (`0x03`).
    Query = 0x03,
    /// `COM_FIELD_LIST` (`0x04`).
    FieldList = 0x04,
    /// `COM_CREATE_DB` (`0x05`).
    CreateDb = 0x05,
    /// `COM_DROP_DB` (`0x06`).
    DropDb = 0x06,
    /// `COM_REFRESH` (`0x07`).
    Refresh = 0x07,
    /// Deprecated `COM_SHUTDOWN` slot (`0x08`).
    DeprecatedShutdown = 0x08,
    /// `COM_STATISTICS` (`0x09`).
    Statistics = 0x09,
    /// `COM_PROCESS_INFO` (`0x0a`).
    ProcessInfo = 0x0a,
    /// `COM_CONNECT` (`0x0b`).
    Connect = 0x0b,
    /// `COM_PROCESS_KILL` (`0x0c`).
    ProcessKill = 0x0c,
    /// `COM_DEBUG` (`0x0d`).
    Debug = 0x0d,
    /// `COM_PING` (`0x0e`).
    Ping = 0x0e,
    /// `COM_TIME` (`0x0f`).
    Time = 0x0f,
    /// `COM_DELAYED_INSERT` (`0x10`).
    DelayedInsert = 0x10,
    /// `COM_CHANGE_USER` (`0x11`).
    ChangeUser = 0x11,
    /// `COM_BINLOG_DUMP` (`0x12`).
    BinlogDump = 0x12,
    /// `COM_TABLE_DUMP` (`0x13`).
    TableDump = 0x13,
    /// `COM_CONNECT_OUT` (`0x14`).
    ConnectOut = 0x14,
    /// `COM_REGISTER_SLAVE` (`0x15`).
    RegisterSlave = 0x15,
    /// `COM_STMT_PREPARE` (`0x16`).
    StmtPrepare = 0x16,
    /// `COM_STMT_EXECUTE` (`0x17`).
    StmtExecute = 0x17,
    /// `COM_STMT_SEND_LONG_DATA` (`0x18`).
    StmtSendLongData = 0x18,
    /// `COM_STMT_CLOSE` (`0x19`).
    StmtClose = 0x19,
    /// `COM_STMT_RESET` (`0x1a`).
    StmtReset = 0x1a,
    /// `COM_SET_OPTION` (`0x1b`).
    SetOption = 0x1b,
    /// `COM_STMT_FETCH` (`0x1c`).
    StmtFetch = 0x1c,
    /// `COM_DAEMON` (`0x1d`).
    Daemon = 0x1d,
    /// `COM_BINLOG_DUMP_GTID` (`0x1e`).
    BinlogDumpGtid = 0x1e,
    /// `COM_RESET_CONNECTION` (`0x1f`).
    ResetConnection = 0x1f,
}

impl Command {
    /// All commands in wire-byte order.
    pub const ALL: [Self; 32] = [
        Self::Sleep,
        Self::Quit,
        Self::InitDb,
        Self::Query,
        Self::FieldList,
        Self::CreateDb,
        Self::DropDb,
        Self::Refresh,
        Self::DeprecatedShutdown,
        Self::Statistics,
        Self::ProcessInfo,
        Self::Connect,
        Self::ProcessKill,
        Self::Debug,
        Self::Ping,
        Self::Time,
        Self::DelayedInsert,
        Self::ChangeUser,
        Self::BinlogDump,
        Self::TableDump,
        Self::ConnectOut,
        Self::RegisterSlave,
        Self::StmtPrepare,
        Self::StmtExecute,
        Self::StmtSendLongData,
        Self::StmtClose,
        Self::StmtReset,
        Self::SetOption,
        Self::StmtFetch,
        Self::Daemon,
        Self::BinlogDumpGtid,
        Self::ResetConnection,
    ];

    /// Returns the command's wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Returns the stable Go metrics/log label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sleep => "Sleep",
            Self::Quit => "Quit",
            Self::InitDb => "InitDB",
            Self::Query => "Query",
            Self::FieldList => "FieldList",
            Self::CreateDb => "CreateDB",
            Self::DropDb => "DropDB",
            Self::Refresh => "Refresh",
            Self::DeprecatedShutdown => "(DEPRECATED)Shutdown",
            Self::Statistics => "Statistics",
            Self::ProcessInfo => "ProcessInfo",
            Self::Connect => "Connect",
            Self::ProcessKill => "ProcessKill",
            Self::Debug => "Debug",
            Self::Ping => "Ping",
            Self::Time => "Time",
            Self::DelayedInsert => "DelayedInsert",
            Self::ChangeUser => "ChangeUser",
            Self::BinlogDump => "BinlogDump",
            Self::TableDump => "TableDump",
            Self::ConnectOut => "ConnectOut",
            Self::RegisterSlave => "RegisterSlave",
            Self::StmtPrepare => "StmtPrepare",
            Self::StmtExecute => "StmtExecute",
            Self::StmtSendLongData => "StmtSendLongData",
            Self::StmtClose => "StmtClose",
            Self::StmtReset => "StmtReset",
            Self::SetOption => "SetOption",
            Self::StmtFetch => "StmtFetch",
            Self::Daemon => "Daemon",
            Self::BinlogDumpGtid => "BinlogDumpGtid",
            Self::ResetConnection => "ResetConnect",
        }
    }
}

impl TryFrom<CommandCode> for Command {
    type Error = CommandDispatchError;

    fn try_from(code: CommandCode) -> Result<Self, Self::Error> {
        let byte = code.as_byte();
        Self::ALL
            .get(usize::from(byte))
            .copied()
            .ok_or(CommandDispatchError::UnknownCommand { byte })
    }
}

/// Response state machine selected before the request is forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedResponse {
    /// No backend packet is read. The runtime completes immediately after
    /// forwarding (and closes normally for `COM_QUIT`).
    None,
    /// Exactly one terminal OK/ERR/EOF packet. Go accepts all three headers
    /// for every command routed through its generic one-packet branch;
    /// command dispatch must not narrow that shared compatibility policy.
    OnePacket,
    /// Query-style OK/ERR/resultset/LOCAL-INFILE/multi-result processing.
    Query,
    /// Column definitions through EOF/ERR.
    FieldList,
    /// One raw human-readable packet, without OK/ERR interpretation.
    Statistics,
    /// Backend authentication-switch loop for `COM_CHANGE_USER`.
    ChangeUser,
    /// Prepare OK/ERR plus declared parameter/column metadata.
    Prepare,
    /// Cursor rows through EOF/OK/ERR.
    Fetch,
}

impl ExpectedResponse {
    /// Whether dispatch completes without reading any backend packet.
    #[must_use]
    pub const fn waits_for_backend(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// How the request itself reaches the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestForwarding {
    /// Forward the request bytes unchanged (streaming is allowed).
    Transparent,
    /// Parse and rewrite `COM_CHANGE_USER` before forwarding (SES-06).
    RewriteChangeUser,
}

/// Session-level state updates produced by command dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMutation<'a> {
    /// Mark the session as normally quitting.
    MarkQuit,
    /// Replace the current database after a successful `COM_INIT_DB`.
    SetCurrentDatabase(&'a [u8]),
    /// Enable or disable `CLIENT_MULTI_STATEMENTS` after `COM_SET_OPTION`
    /// succeeds.
    SetMultiStatements(bool),
    /// Reset session-scoped state after `COM_RESET_CONNECTION` succeeds and
    /// invalidate the locally tracked database. The backend's post-reset
    /// current database is not inferred from the command alone.
    ResetConnection,
}

/// Prepared-statement update exposed to SES-05 without owning its state map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedMutation {
    /// The statement received a long-data fragment.
    LongData(u32),
    /// Remove one statement after no-response `COM_STMT_CLOSE` forwarding.
    Close(u32),
    /// Clear one statement's cursor/long-data state after reset succeeds.
    Reset(u32),
    /// Clear every statement after reset-connection or change-user succeeds.
    ClearAll,
}

/// State effects at one command boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommandStateEffects<'a> {
    /// Session state change, when present.
    pub session: Option<SessionMutation<'a>>,
    /// Prepared-statement state change, when present.
    pub prepared: Option<PreparedMutation>,
}

/// Complete pure dispatch plan for one client command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPlan<'a> {
    /// The exhaustive known command.
    pub command: Command,
    /// Whether the request is transparent or rewritten.
    pub forwarding: RequestForwarding,
    /// Backend response state machine.
    pub response: ExpectedResponse,
    /// Effects applied once request forwarding succeeds. These are the only
    /// effects used by no-response commands.
    pub after_forward: CommandStateEffects<'a>,
    /// Effects applied only after a successful terminal backend response.
    pub after_success: CommandStateEffects<'a>,
}

/// Mutable session fields directly owned by SES-03.
///
/// Prepared-statement state deliberately remains outside this type for
/// SES-05. [`CommandPlan::after_forward`] and
/// [`CommandPlan::after_success`] expose those updates explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSessionState {
    capabilities: CapabilityFlags,
    current_database: CurrentDatabaseState,
    quit: bool,
}

/// Confidence attached to the locally tracked current database.
///
/// This is command-boundary bookkeeping only. Migration must obtain the
/// authoritative current database from `TiDB`'s `SHOW SESSION_STATES`; it must
/// never substitute this value for backend session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentDatabaseState {
    /// The frontend selected no initial database.
    None,
    /// A successful `COM_INIT_DB` (or the frontend handshake) selected these
    /// opaque database bytes.
    Selected(Vec<u8>),
    /// A command changed/reset backend session state in a way that this layer
    /// cannot determine authoritatively.
    Unknown,
}

impl CommandSessionState {
    /// Creates command state from the negotiated handshake fields.
    #[must_use]
    pub fn new(capabilities: CapabilityFlags, current_database: Option<&[u8]>) -> Self {
        Self {
            capabilities,
            current_database: current_database.map_or(CurrentDatabaseState::None, |database| {
                CurrentDatabaseState::Selected(database.to_vec())
            }),
            quit: false,
        }
    }

    /// Current negotiated capability mask, including dynamic
    /// `MULTI_STATEMENTS` changes.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilityFlags {
        self.capabilities
    }

    /// Locally tracked current-database state.
    ///
    /// [`CurrentDatabaseState::Unknown`] must remain unknown until an
    /// authoritative backend observation refreshes it; it is not equivalent
    /// to no database being selected.
    #[must_use]
    pub const fn current_database(&self) -> &CurrentDatabaseState {
        &self.current_database
    }

    /// Replaces local command-derived database tracking with the
    /// authoritative value decoded from `SHOW SESSION_STATES`.
    ///
    /// Absence means no database is selected, not unknown: `TiDB` omits the
    /// `current-db` field for that state.
    pub fn replace_current_database_from_snapshot(&mut self, database: Option<&str>) {
        self.current_database = database.map_or(CurrentDatabaseState::None, |database| {
            CurrentDatabaseState::Selected(database.as_bytes().to_vec())
        });
    }

    /// Whether `COM_QUIT` was forwarded.
    #[must_use]
    pub const fn quit(&self) -> bool {
        self.quit
    }

    /// Applies a session mutation emitted by a plan.
    pub fn apply(&mut self, mutation: SessionMutation<'_>) {
        match mutation {
            SessionMutation::MarkQuit => self.quit = true,
            SessionMutation::SetCurrentDatabase(database) => {
                self.current_database = CurrentDatabaseState::Selected(database.to_vec());
            }
            SessionMutation::SetMultiStatements(enabled) => {
                if enabled {
                    self.capabilities |= CapabilityFlags::MULTI_STATEMENTS;
                } else {
                    self.capabilities =
                        self.capabilities.without(CapabilityFlags::MULTI_STATEMENTS);
                }
            }
            SessionMutation::ResetConnection => {
                // COM_RESET_CONNECTION preserves negotiated capabilities.
                // The exact post-reset database belongs to backend session
                // state, so invalidate rather than inventing Known(None).
                // Prepared state is carried as PreparedMutation::ClearAll.
                self.current_database = CurrentDatabaseState::Unknown;
            }
        }
    }
}

/// Safe, payload-free command-dispatch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandDispatchError {
    /// `COM_END` or an extension byte outside the frozen command table.
    UnknownCommand {
        /// Rejected raw command byte.
        byte: u8,
    },
    /// A fixed-width command prefix is truncated.
    MalformedCommand {
        /// Command being decoded.
        command: Command,
        /// Required command-data bytes after byte zero.
        required: usize,
        /// Available command-data bytes after byte zero.
        actual: usize,
    },
    /// `COM_SET_OPTION` accepts only 0 (enable) and 1 (disable).
    InvalidSetOption {
        /// Rejected little-endian option value.
        value: u16,
    },
}

impl fmt::Display for CommandDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand { byte } => {
                write!(f, "unknown MySQL command byte 0x{byte:02x}")
            }
            Self::MalformedCommand {
                command,
                required,
                actual,
            } => write!(
                f,
                "{} command data is truncated: need at least {required} bytes, have {actual}",
                command.name()
            ),
            Self::InvalidSetOption { value } => {
                write!(f, "invalid COM_SET_OPTION value {value}")
            }
        }
    }
}

impl std::error::Error for CommandDispatchError {}

const fn effects(
    session: Option<SessionMutation<'_>>,
    prepared: Option<PreparedMutation>,
) -> CommandStateEffects<'_> {
    CommandStateEffects { session, prepared }
}

fn statement_id(command: Command, data: &[u8]) -> Result<u32, CommandDispatchError> {
    let bytes: [u8; 4] = data
        .get(..4)
        .ok_or(CommandDispatchError::MalformedCommand {
            command,
            required: 4,
            actual: data.len(),
        })?
        .try_into()
        .map_err(|_| CommandDispatchError::MalformedCommand {
            command,
            required: 4,
            actual: data.len(),
        })?;
    Ok(u32::from_le_bytes(bytes))
}

fn set_option(data: &[u8]) -> Result<bool, CommandDispatchError> {
    let bytes: [u8; 2] = data
        .get(..2)
        .ok_or(CommandDispatchError::MalformedCommand {
            command: Command::SetOption,
            required: 2,
            actual: data.len(),
        })?
        .try_into()
        .map_err(|_| CommandDispatchError::MalformedCommand {
            command: Command::SetOption,
            required: 2,
            actual: data.len(),
        })?;
    match u16::from_le_bytes(bytes) {
        0 => Ok(true),
        1 => Ok(false),
        value => Err(CommandDispatchError::InvalidSetOption { value }),
    }
}

/// Dispatches one decoded command into forwarding, response, and state plans.
///
/// # Errors
///
/// Returns [`CommandDispatchError`] before forwarding for `COM_END`, unknown
/// bytes, truncated statement identifiers/options, or an invalid
/// `COM_SET_OPTION` value. Trailing bytes are retained for Go compatibility.
pub fn dispatch(packet: CommandPacket<'_>) -> Result<CommandPlan<'_>, CommandDispatchError> {
    let command = Command::try_from(packet.command)?;
    let mut plan = CommandPlan {
        command,
        forwarding: RequestForwarding::Transparent,
        response: ExpectedResponse::OnePacket,
        after_forward: CommandStateEffects::default(),
        after_success: CommandStateEffects::default(),
    };

    match command {
        Command::Sleep
        | Command::Connect
        | Command::Time
        | Command::DelayedInsert
        | Command::BinlogDump
        | Command::TableDump
        | Command::ConnectOut
        | Command::RegisterSlave
        | Command::Daemon
        | Command::BinlogDumpGtid
        | Command::CreateDb
        | Command::DropDb
        | Command::Refresh
        | Command::DeprecatedShutdown
        | Command::ProcessKill
        | Command::Debug
        | Command::Ping => {}
        Command::Quit => {
            plan.response = ExpectedResponse::None;
            plan.after_forward = effects(Some(SessionMutation::MarkQuit), None);
        }
        Command::InitDb => {
            plan.after_success =
                effects(Some(SessionMutation::SetCurrentDatabase(packet.data)), None);
        }
        Command::Query | Command::ProcessInfo => {
            plan.response = ExpectedResponse::Query;
        }
        Command::FieldList => {
            plan.response = ExpectedResponse::FieldList;
        }
        Command::Statistics => {
            plan.response = ExpectedResponse::Statistics;
        }
        Command::ChangeUser => {
            plan.forwarding = RequestForwarding::RewriteChangeUser;
            plan.response = ExpectedResponse::ChangeUser;
            plan.after_success = effects(None, Some(PreparedMutation::ClearAll));
        }
        Command::StmtPrepare => {
            plan.response = ExpectedResponse::Prepare;
        }
        Command::StmtExecute => {
            let _ = statement_id(command, packet.data)?;
            plan.response = ExpectedResponse::Query;
        }
        Command::StmtSendLongData => {
            let statement_id = statement_id(command, packet.data)?;
            plan.response = ExpectedResponse::None;
            plan.after_forward = effects(None, Some(PreparedMutation::LongData(statement_id)));
        }
        Command::StmtClose => {
            let statement_id = statement_id(command, packet.data)?;
            plan.response = ExpectedResponse::None;
            plan.after_forward = effects(None, Some(PreparedMutation::Close(statement_id)));
        }
        Command::StmtReset => {
            let statement_id = statement_id(command, packet.data)?;
            plan.after_success = effects(None, Some(PreparedMutation::Reset(statement_id)));
        }
        Command::SetOption => {
            let enabled = set_option(packet.data)?;
            plan.after_success = effects(Some(SessionMutation::SetMultiStatements(enabled)), None);
        }
        Command::StmtFetch => {
            let _ = statement_id(command, packet.data)?;
            plan.response = ExpectedResponse::Fetch;
        }
        Command::ResetConnection => {
            plan.after_success = effects(
                Some(SessionMutation::ResetConnection),
                Some(PreparedMutation::ClearAll),
            );
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload: &[u8]) -> Result<CommandPacket<'_>, mysql_wire::DecodeError> {
        CommandPacket::decode(payload)
    }

    #[test]
    fn command_table_is_dense_and_label_identical_to_wire_crate() {
        for (byte, command) in (0_u8..=0x1f).zip(Command::ALL) {
            assert_eq!(command.as_byte(), byte);
            assert_eq!(
                command.name(),
                CommandCode::from_byte(byte).name().unwrap_or("")
            );
        }
    }

    #[test]
    fn every_command_has_an_explicit_response_strategy() -> Result<(), Box<dyn std::error::Error>> {
        for command in Command::ALL {
            let mut payload = vec![command.as_byte()];
            match command {
                Command::StmtExecute
                | Command::StmtSendLongData
                | Command::StmtClose
                | Command::StmtReset
                | Command::StmtFetch => payload.extend_from_slice(&7_u32.to_le_bytes()),
                Command::SetOption => payload.extend_from_slice(&0_u16.to_le_bytes()),
                _ => {}
            }
            let plan = dispatch(packet(&payload)?)?;
            assert_eq!(plan.command, command);
        }
        Ok(())
    }

    #[test]
    fn no_response_commands_never_wait_and_apply_after_forward()
    -> Result<(), Box<dyn std::error::Error>> {
        let quit_payload = [Command::Quit.as_byte()];
        let quit = dispatch(packet(&quit_payload)?)?;
        assert!(!quit.response.waits_for_backend());
        assert_eq!(quit.after_forward.session, Some(SessionMutation::MarkQuit));

        for (command, expected) in [
            (Command::StmtSendLongData, PreparedMutation::LongData(7)),
            (Command::StmtClose, PreparedMutation::Close(7)),
        ] {
            let mut payload = vec![command.as_byte()];
            payload.extend_from_slice(&7_u32.to_le_bytes());
            let plan = dispatch(packet(&payload)?)?;
            assert!(!plan.response.waits_for_backend());
            assert_eq!(plan.after_forward.prepared, Some(expected));
            assert_eq!(plan.after_success, CommandStateEffects::default());
        }
        Ok(())
    }

    #[test]
    fn state_changes_apply_only_at_declared_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let capabilities = CapabilityFlags::PROTOCOL_41 | CapabilityFlags::MULTI_STATEMENTS;
        let mut state = CommandSessionState::new(capabilities, Some(b"before"));

        let disable_payload = [Command::SetOption.as_byte(), 1, 0];
        let disable = dispatch(packet(&disable_payload)?)?;
        assert_eq!(
            disable.after_success.session,
            Some(SessionMutation::SetMultiStatements(false))
        );
        state.apply(
            disable
                .after_success
                .session
                .ok_or("missing SET_OPTION effect")?,
        );
        assert!(
            !state
                .capabilities()
                .contains(CapabilityFlags::MULTI_STATEMENTS)
        );

        let enable_payload = [Command::SetOption.as_byte(), 0, 0, 0xff];
        let enable = dispatch(packet(&enable_payload)?)?;
        state.apply(
            enable
                .after_success
                .session
                .ok_or("missing SET_OPTION effect")?,
        );
        assert!(
            state
                .capabilities()
                .contains(CapabilityFlags::MULTI_STATEMENTS)
        );

        let init = dispatch(packet(b"\x02after")?)?;
        assert_eq!(
            state.current_database(),
            &CurrentDatabaseState::Selected(b"before".to_vec())
        );
        state.apply(init.after_success.session.ok_or("missing INIT_DB effect")?);
        assert_eq!(
            state.current_database(),
            &CurrentDatabaseState::Selected(b"after".to_vec())
        );

        let reset_payload = [Command::ResetConnection.as_byte()];
        let reset = dispatch(packet(&reset_payload)?)?;
        assert_eq!(
            reset.after_success.prepared,
            Some(PreparedMutation::ClearAll)
        );
        state.apply(reset.after_success.session.ok_or("missing RESET effect")?);
        assert_eq!(state.current_database(), &CurrentDatabaseState::Unknown);
        state.replace_current_database_from_snapshot(Some("authoritative_db"));
        assert_eq!(
            state.current_database(),
            &CurrentDatabaseState::Selected(b"authoritative_db".to_vec())
        );
        state.replace_current_database_from_snapshot(None);
        assert_eq!(state.current_database(), &CurrentDatabaseState::None);
        assert!(
            state
                .capabilities()
                .contains(CapabilityFlags::MULTI_STATEMENTS)
        );

        let quit_payload = [Command::Quit.as_byte()];
        let quit = dispatch(packet(&quit_payload)?)?;
        state.apply(quit.after_forward.session.ok_or("missing QUIT effect")?);
        assert!(state.quit());
        Ok(())
    }

    #[test]
    fn set_option_and_statement_prefixes_are_checked_before_forwarding()
    -> Result<(), Box<dyn std::error::Error>> {
        for data_len in 0..2 {
            let mut payload = vec![Command::SetOption.as_byte()];
            payload.resize(1 + data_len, 0);
            assert!(matches!(
                dispatch(packet(&payload)?),
                Err(CommandDispatchError::MalformedCommand {
                    command: Command::SetOption,
                    required: 2,
                    actual,
                }) if actual == data_len
            ));
        }
        assert_eq!(
            dispatch(packet(&[Command::SetOption.as_byte(), 2, 0])?),
            Err(CommandDispatchError::InvalidSetOption { value: 2 })
        );

        for command in [
            Command::StmtExecute,
            Command::StmtSendLongData,
            Command::StmtClose,
            Command::StmtReset,
            Command::StmtFetch,
        ] {
            for data_len in 0..4 {
                let mut payload = vec![command.as_byte()];
                payload.resize(1 + data_len, 0);
                assert!(matches!(
                    dispatch(packet(&payload)?),
                    Err(CommandDispatchError::MalformedCommand {
                        command: got,
                        required: 4,
                        actual,
                    }) if got == command && actual == data_len
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn sentinel_and_unknown_commands_are_rejected_before_forwarding()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(UNKNOWN_COMMAND_POLICY, UnknownCommandPolicy::Reject);
        for byte in [CommandCode::END_SENTINEL.as_byte(), 0x21, 0xff] {
            assert_eq!(
                dispatch(packet(&[byte])?),
                Err(CommandDispatchError::UnknownCommand { byte })
            );
        }
        Ok(())
    }
}
