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

use std::fmt;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

/// `MySQL` client capability flags, retaining unknown bits for forward compatibility.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct CapabilityFlags(u32);

impl CapabilityFlags {
    /// Use the legacy password protocol.
    pub const LONG_PASSWORD: Self = Self(1 << 0);
    /// Return found rows instead of affected rows.
    pub const FOUND_ROWS: Self = Self(1 << 1);
    /// Send all column flags.
    pub const LONG_FLAG: Self = Self(1 << 2);
    /// Include an initial database in the handshake response.
    pub const CONNECT_WITH_DB: Self = Self(1 << 3);
    /// Do not permit database-qualified table names.
    pub const NO_SCHEMA: Self = Self(1 << 4);
    /// Support classic zlib compression.
    pub const COMPRESS: Self = Self(1 << 5);
    /// Identify as an ODBC client.
    pub const ODBC: Self = Self(1 << 6);
    /// Permit `LOCAL INFILE`.
    pub const LOCAL_FILES: Self = Self(1 << 7);
    /// Ignore spaces before function parentheses.
    pub const IGNORE_SPACE: Self = Self(1 << 8);
    /// Use the protocol-4.1 handshake and packet layouts.
    pub const PROTOCOL_41: Self = Self(1 << 9);
    /// Mark the connection as interactive.
    pub const INTERACTIVE: Self = Self(1 << 10);
    /// Request TLS after the `SSLRequest` packet.
    pub const SSL: Self = Self(1 << 11);
    /// Ignore `SIGPIPE` in the client library.
    pub const IGNORE_SIGPIPE: Self = Self(1 << 12);
    /// Include protocol-4.1 transaction status.
    pub const TRANSACTIONS: Self = Self(1 << 13);
    /// Historical reserved capability bit.
    pub const RESERVED: Self = Self(1 << 14);
    /// Prefix authentication data with a one-byte length.
    pub const SECURE_CONNECTION: Self = Self(1 << 15);
    /// Permit multiple statements per command.
    pub const MULTI_STATEMENTS: Self = Self(1 << 16);
    /// Permit multiple result sets.
    pub const MULTI_RESULTS: Self = Self(1 << 17);
    /// Permit prepared statements to return multiple result sets.
    pub const PS_MULTI_RESULTS: Self = Self(1 << 18);
    /// Include the authentication plugin name.
    pub const PLUGIN_AUTH: Self = Self(1 << 19);
    /// Include length-prefixed connection attributes.
    pub const CONNECT_ATTRS: Self = Self(1 << 20);
    /// Prefix authentication data with a length-encoded integer.
    pub const PLUGIN_AUTH_LENENC_CLIENT_DATA: Self = Self(1 << 21);
    /// Allow expired-password handling.
    pub const CAN_HANDLE_EXPIRED_PASSWORDS: Self = Self(1 << 22);
    /// Include session-state tracking data.
    pub const SESSION_TRACK: Self = Self(1 << 23);
    /// Use OK packets instead of legacy EOF packets.
    pub const DEPRECATE_EOF: Self = Self(1 << 24);
    /// Negotiate optional result-set metadata.
    pub const OPTIONAL_RESULTSET_METADATA: Self = Self(1 << 25);
    /// Support zstd compression.
    pub const ZSTD_COMPRESSION_ALGORITHM: Self = Self(1 << 26);
    /// Support query attributes.
    pub const QUERY_ATTRIBUTES: Self = Self(1 << 27);
    /// Support multi-factor authentication.
    pub const MULTI_FACTOR_AUTHENTICATION: Self = Self(1 << 28);
    /// Signal a capability-extension word.
    pub const CAPABILITY_EXTENSION: Self = Self(1 << 29);
    /// Historical server-certificate verification bit.
    pub const SSL_VERIFY_SERVER_CERT: Self = Self(1 << 30);
    /// Retain client options after a reset.
    pub const REMEMBER_OPTIONS: Self = Self(1 << 31);

    /// Creates a flag set while retaining every known or unknown bit.
    #[must_use]
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw 32-bit capability mask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether all bits in `other` are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether any bit in `other` is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Returns the union of this set and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns this set with `other` removed.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl fmt::Debug for CapabilityFlags {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CapabilityFlags(0x{:08x})", self.0)
    }
}

impl BitOr for CapabilityFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CapabilityFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for CapabilityFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for CapabilityFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for CapabilityFlags {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

/// `MySQL` server-status flags, retaining unknown bits for forward compatibility.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct StatusFlags(u16);

impl StatusFlags {
    /// A transaction is active.
    pub const IN_TRANS: Self = Self(0x0001);
    /// Autocommit is enabled.
    pub const AUTOCOMMIT: Self = Self(0x0002);
    /// Additional result sets follow.
    pub const MORE_RESULTS_EXISTS: Self = Self(0x0008);
    /// The query used a non-optimal index.
    pub const NO_GOOD_INDEX_USED: Self = Self(0x0010);
    /// The query used no index.
    pub const NO_INDEX_USED: Self = Self(0x0020);
    /// A prepared-statement cursor exists.
    pub const CURSOR_EXISTS: Self = Self(0x0040);
    /// The last cursor row was sent.
    pub const LAST_ROW_SENT: Self = Self(0x0080);
    /// The current database was dropped.
    pub const DB_DROPPED: Self = Self(0x0100);
    /// Backslash escaping is disabled.
    pub const NO_BACKSLASH_ESCAPES: Self = Self(0x0200);
    /// Result metadata changed.
    pub const METADATA_CHANGED: Self = Self(0x0400);
    /// The query was classified as slow.
    pub const QUERY_WAS_SLOW: Self = Self(0x0800);
    /// Prepared-statement output parameters exist.
    pub const PS_OUT_PARAMS: Self = Self(0x1000);
    /// The transaction is read-only.
    pub const IN_TRANS_READONLY: Self = Self(0x2000);
    /// Session-state tracking data changed.
    pub const SESSION_STATE_CHANGED: Self = Self(0x4000);

    /// Creates a status set while retaining every known or unknown bit.
    #[must_use]
    pub const fn from_bits_retain(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw 16-bit status mask.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether all bits in `other` are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether any bit in `other` is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Returns the union of this set and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Debug for StatusFlags {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StatusFlags(0x{:04x})", self.0)
    }
}

impl BitOr for StatusFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for StatusFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for StatusFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// A `MySQL` command byte, retaining unknown values for future protocol extensions.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandCode(u8);

impl CommandCode {
    /// `COM_SLEEP` (`0x00`).
    pub const SLEEP: Self = Self(0x00);
    /// `COM_QUIT` (`0x01`).
    pub const QUIT: Self = Self(0x01);
    /// `COM_INIT_DB` (`0x02`).
    pub const INIT_DB: Self = Self(0x02);
    /// `COM_QUERY` (`0x03`).
    pub const QUERY: Self = Self(0x03);
    /// `COM_FIELD_LIST` (`0x04`).
    pub const FIELD_LIST: Self = Self(0x04);
    /// `COM_CREATE_DB` (`0x05`).
    pub const CREATE_DB: Self = Self(0x05);
    /// `COM_DROP_DB` (`0x06`).
    pub const DROP_DB: Self = Self(0x06);
    /// `COM_REFRESH` (`0x07`).
    pub const REFRESH: Self = Self(0x07);
    /// Deprecated `COM_SHUTDOWN` slot (`0x08`).
    pub const DEPRECATED_SHUTDOWN: Self = Self(0x08);
    /// `COM_STATISTICS` (`0x09`).
    pub const STATISTICS: Self = Self(0x09);
    /// `COM_PROCESS_INFO` (`0x0a`).
    pub const PROCESS_INFO: Self = Self(0x0a);
    /// `COM_CONNECT` (`0x0b`).
    pub const CONNECT: Self = Self(0x0b);
    /// `COM_PROCESS_KILL` (`0x0c`).
    pub const PROCESS_KILL: Self = Self(0x0c);
    /// `COM_DEBUG` (`0x0d`).
    pub const DEBUG: Self = Self(0x0d);
    /// `COM_PING` (`0x0e`).
    pub const PING: Self = Self(0x0e);
    /// `COM_TIME` (`0x0f`).
    pub const TIME: Self = Self(0x0f);
    /// `COM_DELAYED_INSERT` (`0x10`).
    pub const DELAYED_INSERT: Self = Self(0x10);
    /// `COM_CHANGE_USER` (`0x11`).
    pub const CHANGE_USER: Self = Self(0x11);
    /// `COM_BINLOG_DUMP` (`0x12`).
    pub const BINLOG_DUMP: Self = Self(0x12);
    /// `COM_TABLE_DUMP` (`0x13`).
    pub const TABLE_DUMP: Self = Self(0x13);
    /// `COM_CONNECT_OUT` (`0x14`).
    pub const CONNECT_OUT: Self = Self(0x14);
    /// `COM_REGISTER_SLAVE` (`0x15`).
    pub const REGISTER_SLAVE: Self = Self(0x15);
    /// `COM_STMT_PREPARE` (`0x16`).
    pub const STMT_PREPARE: Self = Self(0x16);
    /// `COM_STMT_EXECUTE` (`0x17`).
    pub const STMT_EXECUTE: Self = Self(0x17);
    /// `COM_STMT_SEND_LONG_DATA` (`0x18`).
    pub const STMT_SEND_LONG_DATA: Self = Self(0x18);
    /// `COM_STMT_CLOSE` (`0x19`).
    pub const STMT_CLOSE: Self = Self(0x19);
    /// `COM_STMT_RESET` (`0x1a`).
    pub const STMT_RESET: Self = Self(0x1a);
    /// `COM_SET_OPTION` (`0x1b`).
    pub const SET_OPTION: Self = Self(0x1b);
    /// `COM_STMT_FETCH` (`0x1c`).
    pub const STMT_FETCH: Self = Self(0x1c);
    /// `COM_DAEMON` (`0x1d`).
    pub const DAEMON: Self = Self(0x1d);
    /// `COM_BINLOG_DUMP_GTID` (`0x1e`).
    pub const BINLOG_DUMP_GTID: Self = Self(0x1e);
    /// `COM_RESET_CONNECTION` (`0x1f`).
    pub const RESET_CONNECTION: Self = Self(0x1f);
    /// Go's `ComEnd` sentinel (`0x20`), which is not a wire command.
    pub const END_SENTINEL: Self = Self(0x20);

    /// Creates a command from its raw wire byte.
    #[must_use]
    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Returns whether this is a real command declared by the current Go dataplane.
    #[must_use]
    pub const fn is_known_command(self) -> bool {
        self.0 < Self::END_SENTINEL.0
    }

    /// Returns Go's stable metrics/log label for a known command.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            0x00 => Some("Sleep"),
            0x01 => Some("Quit"),
            0x02 => Some("InitDB"),
            0x03 => Some("Query"),
            0x04 => Some("FieldList"),
            0x05 => Some("CreateDB"),
            0x06 => Some("DropDB"),
            0x07 => Some("Refresh"),
            0x08 => Some("(DEPRECATED)Shutdown"),
            0x09 => Some("Statistics"),
            0x0a => Some("ProcessInfo"),
            0x0b => Some("Connect"),
            0x0c => Some("ProcessKill"),
            0x0d => Some("Debug"),
            0x0e => Some("Ping"),
            0x0f => Some("Time"),
            0x10 => Some("DelayedInsert"),
            0x11 => Some("ChangeUser"),
            0x12 => Some("BinlogDump"),
            0x13 => Some("TableDump"),
            0x14 => Some("ConnectOut"),
            0x15 => Some("RegisterSlave"),
            0x16 => Some("StmtPrepare"),
            0x17 => Some("StmtExecute"),
            0x18 => Some("StmtSendLongData"),
            0x19 => Some("StmtClose"),
            0x1a => Some("StmtReset"),
            0x1b => Some("SetOption"),
            0x1c => Some("StmtFetch"),
            0x1d => Some("Daemon"),
            0x1e => Some("BinlogDumpGtid"),
            0x1f => Some("ResetConnect"),
            _ => None,
        }
    }
}

impl fmt::Debug for CommandCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(formatter, "CommandCode({name}, 0x{:02x})", self.0),
            None => write!(formatter, "CommandCode(unknown, 0x{:02x})", self.0),
        }
    }
}

impl fmt::Display for CommandCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => formatter.write_str(name),
            None => write!(formatter, "Not a command: {:x}", self.0),
        }
    }
}

/// A one-byte `MySQL` response header.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseHeader(u8);

impl ResponseHeader {
    /// OK packet (`0x00`).
    pub const OK: Self = Self(0x00);
    /// LOCAL INFILE request (`0xfb`).
    pub const LOCAL_INFILE: Self = Self(0xfb);
    /// EOF, result-set OK, or authentication switch packet (`0xfe`).
    pub const EOF_OR_AUTH_SWITCH: Self = Self(0xfe);
    /// ERR packet (`0xff`).
    pub const ERROR: Self = Self(0xff);

    /// Creates a response header from a raw byte.
    #[must_use]
    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for ResponseHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OK => formatter.write_str("ResponseHeader(OK)"),
            Self::LOCAL_INFILE => formatter.write_str("ResponseHeader(LOCAL_INFILE)"),
            Self::EOF_OR_AUTH_SWITCH => formatter.write_str("ResponseHeader(EOF_OR_AUTH_SWITCH)"),
            Self::ERROR => formatter.write_str("ResponseHeader(ERROR)"),
            Self(value) => write!(formatter, "ResponseHeader(0x{value:02x})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_and_status_retain_unknown_bits() {
        let capabilities = CapabilityFlags::from_bits_retain(0x853b_eeef);
        assert_eq!(capabilities.bits(), 0x853b_eeef);
        assert!(capabilities.contains(CapabilityFlags::PROTOCOL_41));
        assert_eq!(
            capabilities.without(CapabilityFlags::SSL).bits(),
            capabilities.bits() & !CapabilityFlags::SSL.bits()
        );

        let status = StatusFlags::from_bits_retain(0x8002);
        assert_eq!(status.bits(), 0x8002);
        assert!(status.contains(StatusFlags::AUTOCOMMIT));
    }

    #[test]
    fn command_labels_match_go_metrics_contract() {
        assert_eq!(
            CommandCode::DEPRECATED_SHUTDOWN.name(),
            Some("(DEPRECATED)Shutdown")
        );
        assert_eq!(CommandCode::RESET_CONNECTION.name(), Some("ResetConnect"));
        assert!(!CommandCode::END_SENTINEL.is_known_command());
        assert_eq!(CommandCode::from_byte(0xff).name(), None);
    }
}
