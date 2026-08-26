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

//! First-handshake negotiation policy (SES-01), frozen from Go
//! `pkg/proxy/backend/authenticator.go`.
//!
//! The wire layouts live in `mysql-wire` (`handshake` module); this module
//! owns the *decisions*: which capabilities the proxy advertises, how the
//! frontend response is validated and intersected, the trust-first rule for
//! the `SSLRequest`/response capability pair, backend capability and TLS
//! verification, the handshake size gates, and the routing gate that ties
//! [`crate::fsm::SessionEffect::DialBackend`] to parsed client metadata
//! ("route only after username, listener, and client metadata are
//! available").
//!
//! Everything here is pure: no I/O and no logging. Where Go logs, the
//! functions return the exact sets (unsupported, ignored, mismatched,
//! forced) so the runtime can log them; no decision is hidden.

use core::fmt;

use mysql_wire::limits::{LimitExceeded, check_pre_handshake_packet};
use mysql_wire::{CapabilityFlags, HandshakeResponse, InitialHandshakeParams, StatusFlags};

/// Go `SupportedServerCapabilities`: the default capability set the proxy
/// advertises. Byte-pinned by test against Go's literal union.
pub const SUPPORTED_SERVER_CAPABILITIES: CapabilityFlags = CapabilityFlags::from_bits_retain(
    CapabilityFlags::LONG_PASSWORD.bits()
        | CapabilityFlags::FOUND_ROWS.bits()
        | CapabilityFlags::CONNECT_WITH_DB.bits()
        | CapabilityFlags::ODBC.bits()
        | CapabilityFlags::LOCAL_FILES.bits()
        | CapabilityFlags::INTERACTIVE.bits()
        | CapabilityFlags::LONG_FLAG.bits()
        | CapabilityFlags::SSL.bits()
        | CapabilityFlags::TRANSACTIONS.bits()
        | CapabilityFlags::RESERVED.bits()
        | CapabilityFlags::SECURE_CONNECTION.bits()
        | CapabilityFlags::MULTI_STATEMENTS.bits()
        | CapabilityFlags::MULTI_RESULTS.bits()
        | CapabilityFlags::PLUGIN_AUTH.bits()
        | CapabilityFlags::CONNECT_ATTRS.bits()
        | CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA.bits()
        | CapabilityFlags::COMPRESS.bits()
        | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits()
        | REQUIRED_FRONTEND_CAPABILITIES.bits()
        | DEFAULT_REQUIRED_BACKEND_CAPABILITIES.bits(),
);

/// Go `requiredFrontendCaps`: the client must speak protocol 4.1.
pub const REQUIRED_FRONTEND_CAPABILITIES: CapabilityFlags = CapabilityFlags::PROTOCOL_41;

/// Go `defRequiredBackendCaps`: the backend must support `DEPRECATE_EOF`
/// when the negotiated session uses it.
pub const DEFAULT_REQUIRED_BACKEND_CAPABILITIES: CapabilityFlags = CapabilityFlags::DEPRECATE_EOF;

/// Go: both `SSLRequest` and `HandshakeResponse` are at least 32 bytes; a
/// shorter first client packet is malformed.
pub const MIN_CLIENT_HANDSHAKE_LEN: usize = 32;

/// The greeting always advertises `mysql_native_password`
/// (Go `handshakeFirstTime` passes `pnet.AuthNativePassword`).
pub const GREETING_AUTH_PLUGIN: &[u8] = b"mysql_native_password";

/// `MySQL` `ER_NOT_SUPPORTED_AUTH_MODE`, sent when the client lacks a
/// required capability (Go `mysql.NewDefaultError`).
pub const ER_NOT_SUPPORTED_AUTH_MODE: u16 = 1251;
/// The SQLSTATE go-mysql associates with [`ER_NOT_SUPPORTED_AUTH_MODE`].
/// go-mysql v1.12.0 is not vendored, so this literal (like the default
/// message below) is pinned here and must gain a corpus vector when the
/// live driver matrix runs against a real backend.
pub const SQL_STATE_NOT_SUPPORTED_AUTH_MODE: [u8; 5] = *b"08004";
/// The default message go-mysql associates with the code.
pub const MSG_NOT_SUPPORTED_AUTH_MODE: &str = "Client does not support authentication \
     protocol requested by server; consider upgrading MySQL client";

const fn intersect(a: CapabilityFlags, b: CapabilityFlags) -> CapabilityFlags {
    CapabilityFlags::from_bits_retain(a.bits() & b.bits())
}

/// The capability set the greeting advertises: the configured proxy
/// capability, with `SSL` cleared when no frontend TLS configuration
/// exists.
///
/// Go XORs `ClientSSL` under the invariant that `GetCapability` always
/// includes it; clearing is the drift-proof equivalent and identical
/// whenever that invariant holds.
#[must_use]
pub const fn greeting_capability(
    proxy: CapabilityFlags,
    frontend_tls_available: bool,
) -> CapabilityFlags {
    if frontend_tls_available {
        proxy
    } else {
        proxy.without(CapabilityFlags::SSL)
    }
}

/// Builds the greeting parameters exactly as Go `handshakeFirstTime` does:
/// the caller's capability (see [`greeting_capability`]), a 20-byte salt,
/// and the pinned `mysql_native_password` plugin. The connection identifier
/// is the registry's `u64`; the greeting carries its **low 32 bits**, the
/// exact bytes Go `MakeInitialHandshake` writes.
#[must_use]
pub fn build_greeting<'a>(
    capabilities: CapabilityFlags,
    salt: &'a [u8; 20],
    server_version: &'a [u8],
    connection_id: u64,
    collation: u8,
    status: StatusFlags,
) -> InitialHandshakeParams<'a> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go MakeInitialHandshake writes exactly the low 32 bits \
                  of the u64 connection id; the truncation is the contract"
    )]
    let wire_connection_id = connection_id as u32;
    InitialHandshakeParams {
        server_version,
        connection_id: wire_connection_id,
        auth_plugin_data: salt,
        capabilities,
        collation,
        status,
        auth_plugin_name: GREETING_AUTH_PLUGIN,
    }
}

/// The successful outcome of frontend capability negotiation.
///
/// Opaque and unforgeable outside this module: the only constructor is
/// [`negotiate_frontend`]'s success path, so holding one proves the
/// required-capability check passed. It is also the only source of a
/// [`RoutingHandshake`] (see [`FrontendNegotiation::routing_handshake`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontendNegotiation {
    negotiated: CapabilityFlags,
    unsupported_by_proxy: CapabilityFlags,
    plugin_auth_forced: bool,
}

impl FrontendNegotiation {
    /// The session capability: the frontend/proxy intersection, with
    /// `PLUGIN_AUTH` force-set when missing.
    #[must_use]
    pub const fn negotiated(&self) -> CapabilityFlags {
        self.negotiated
    }

    /// Frontend capabilities the proxy does not support (Go debug-logs
    /// this set and ignores it).
    #[must_use]
    pub const fn unsupported_by_proxy(&self) -> CapabilityFlags {
        self.unsupported_by_proxy
    }

    /// `PLUGIN_AUTH` was missing and force-set (Go warns: some clients,
    /// e.g. node/mysql, support it without setting the bit).
    #[must_use]
    pub const fn plugin_auth_forced(&self) -> bool {
        self.plugin_auth_forced
    }

    /// Builds the routing gate from this successful negotiation, the
    /// parsed handshake response, and the connection endpoints. This is
    /// the **only** constructor of [`RoutingHandshake`]: routing cannot
    /// run before capability negotiation succeeded and listener/client
    /// metadata exist.
    #[must_use]
    pub fn routing_handshake<'a>(
        &self,
        response: &HandshakeResponse<'a>,
        endpoints: ConnectionEndpoints,
    ) -> RoutingHandshake<'a> {
        RoutingHandshake {
            username: response.username,
            database: response.database,
            collation: response.collation,
            zstd_level: response.zstd_level,
            has_attributes: response.attributes.is_some(),
            negotiated: self.negotiated,
            endpoints,
        }
    }
}

/// The endpoints routing may depend on: the proxy listener the client
/// connected to and the real client address (post-PROXY-protocol when
/// enabled), mirroring Go `ConnContext`'s `ServerAddr`/`ClientAddr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEndpoints {
    /// The proxy listener address that accepted the connection.
    pub listener_addr: core::net::SocketAddr,
    /// The real client address.
    pub client_addr: core::net::SocketAddr,
}

/// The frontend lacks a required capability. Carries the missing set only;
/// the client-visible response is the fixed [`ER_NOT_SUPPORTED_AUTH_MODE`]
/// triple, never derived from input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingFrontendCapabilities {
    /// The required capabilities the client did not advertise.
    pub missing: CapabilityFlags,
}

impl MissingFrontendCapabilities {
    /// The fixed client-visible error triple Go sends
    /// (`ER_NOT_SUPPORTED_AUTH_MODE` default error).
    #[must_use]
    pub const fn client_response(&self) -> (u16, [u8; 5], &'static str) {
        (
            ER_NOT_SUPPORTED_AUTH_MODE,
            SQL_STATE_NOT_SUPPORTED_AUTH_MODE,
            MSG_NOT_SUPPORTED_AUTH_MODE,
        )
    }
}

impl fmt::Display for MissingFrontendCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frontend lacks required capabilities {:?}", self.missing)
    }
}

impl std::error::Error for MissingFrontendCapabilities {}

/// Validates and intersects the frontend capability mask, mirroring Go
/// `handshakeFirstTime` exactly: required-capability check first (fixed
/// error response), then the proxy intersection, then the forced
/// `PLUGIN_AUTH` tolerance.
///
/// # Errors
///
/// Returns [`MissingFrontendCapabilities`] when the client does not
/// advertise [`REQUIRED_FRONTEND_CAPABILITIES`].
pub fn negotiate_frontend(
    frontend: CapabilityFlags,
    proxy: CapabilityFlags,
) -> Result<FrontendNegotiation, MissingFrontendCapabilities> {
    let common_required = intersect(frontend, REQUIRED_FRONTEND_CAPABILITIES);
    if common_required != REQUIRED_FRONTEND_CAPABILITIES {
        return Err(MissingFrontendCapabilities {
            missing: REQUIRED_FRONTEND_CAPABILITIES.without(common_required),
        });
    }
    let common = intersect(frontend, proxy);
    let unsupported_by_proxy = frontend.without(common);
    let plugin_auth_forced = !common.contains(CapabilityFlags::PLUGIN_AUTH);
    let negotiated = if plugin_auth_forced {
        common.union(CapabilityFlags::PLUGIN_AUTH)
    } else {
        common
    };
    Ok(FrontendNegotiation {
        negotiated,
        unsupported_by_proxy,
        plugin_auth_forced,
    })
}

/// The trust-first reconciliation of the `SSLRequest` and
/// `HandshakeResponse` capability masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsCapabilityReconciliation {
    /// The mask to use: always the `SSLRequest`'s (Go overwrites the
    /// response bytes with it — some drivers drop `SSL` in the second
    /// packet).
    pub trusted: CapabilityFlags,
    /// The differing bits, empty when consistent (Go warn-logs this set).
    pub mismatched: CapabilityFlags,
}

/// Reconciles the two capability masks a TLS client sends, mirroring Go:
/// the first (`SSLRequest`) mask wins; a mismatch is reported for logging.
#[must_use]
pub const fn reconcile_tls_capabilities(
    ssl_request: CapabilityFlags,
    handshake_response: CapabilityFlags,
) -> TlsCapabilityReconciliation {
    let mismatched =
        CapabilityFlags::from_bits_retain(ssl_request.bits() ^ handshake_response.bits());
    TlsCapabilityReconciliation {
        trusted: ssl_request,
        mismatched,
    }
}

/// The successful outcome of backend verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendVerification {
    /// Proxy capabilities the backend did not advertise, excluding `SSL`
    /// (Go debug-logs and ignores them because `TiDB` under-advertises).
    pub ignored_by_backend: CapabilityFlags,
}

/// Backend verification failure, mirroring Go `verifyBackendCaps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendVerificationError {
    /// The backend lacks required capabilities (Go `ErrBackendCap`;
    /// classifies via [`crate::error_source::FailureKind::BackendCapability`]).
    MissingCapabilities(CapabilityFlags),
    /// `require-backend-tls` is set but the backend does not offer `SSL`
    /// (Go `ErrBackendNoTLS`;
    /// [`crate::error_source::FailureKind::BackendNoTls`]).
    TlsRequired,
}

impl fmt::Display for BackendVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCapabilities(missing) => {
                write!(f, "backend lacks required capabilities {missing:?}")
            }
            Self::TlsRequired => {
                f.write_str("require-backend-tls is set but the backend offers no TLS")
            }
        }
    }
}

impl std::error::Error for BackendVerificationError {}

/// Verifies the backend greeting capability, mirroring Go
/// `verifyBackendCaps` plus the ignored-capability report from
/// `handshakeFirstTime`: the required set is
/// [`DEFAULT_REQUIRED_BACKEND_CAPABILITIES`] **intersected with the
/// negotiated session capability** (a session that never negotiated
/// `DEPRECATE_EOF` does not require it from the backend), TLS enforcement
/// follows `require-backend-tls`, and the ignored set is the proxy
/// capability the backend under-advertises, excluding `SSL`.
///
/// # Errors
///
/// Returns [`BackendVerificationError`] for a missing required capability
/// or a missing TLS offer under `require-backend-tls`.
pub fn verify_backend(
    backend: CapabilityFlags,
    negotiated: CapabilityFlags,
    proxy: CapabilityFlags,
    require_backend_tls: bool,
) -> Result<BackendVerification, BackendVerificationError> {
    let required = intersect(DEFAULT_REQUIRED_BACKEND_CAPABILITIES, negotiated);
    let common_required = intersect(backend, required);
    if common_required != required {
        return Err(BackendVerificationError::MissingCapabilities(
            required.without(common_required),
        ));
    }
    if require_backend_tls && !backend.contains(CapabilityFlags::SSL) {
        return Err(BackendVerificationError::TlsRequired);
    }
    let common = intersect(proxy, backend);
    Ok(BackendVerification {
        ignored_by_backend: proxy.without(common).without(CapabilityFlags::SSL),
    })
}

/// The first client packet is too short to be an `SSLRequest` or a
/// `HandshakeResponse` (Go wraps `ErrClientHandshake` around
/// `ErrMalformPacket`; classification treats malformed packets as proxy
/// bugs per WIRE-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeTooShort {
    /// The observed payload length.
    pub length: usize,
}

impl fmt::Display for HandshakeTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client handshake packet of {} bytes is shorter than the {}-byte minimum",
            self.length, MIN_CLIENT_HANDSHAKE_LEN
        )
    }
}

impl std::error::Error for HandshakeTooShort {}

/// Gates a client handshake packet's declared length before it is read:
/// at most the 1-MiB pre-handshake cap (Go `maxHandshakePacketSize`,
/// checked against the peeked length before reading).
///
/// # Errors
///
/// Returns the registry's [`LimitExceeded`] above the cap.
pub fn check_handshake_packet_size(declared: usize) -> Result<(), LimitExceeded> {
    check_pre_handshake_packet(declared)
}

/// Gates a read first client packet's minimum size (32 bytes).
///
/// # Errors
///
/// Returns [`HandshakeTooShort`] below [`MIN_CLIENT_HANDSHAKE_LEN`].
pub const fn check_min_client_handshake(length: usize) -> Result<(), HandshakeTooShort> {
    if length < MIN_CLIENT_HANDSHAKE_LEN {
        Err(HandshakeTooShort { length })
    } else {
        Ok(())
    }
}

/// The routing gate: everything routing may depend on. Opaque and
/// unforgeable — the only constructor is
/// [`FrontendNegotiation::routing_handshake`], so holding one proves
/// capability negotiation succeeded **and** listener/client metadata
/// exist. The FSM's `DialBackend` effect must be given one of these,
/// which encodes "route only after username, listener, and client
/// metadata are available" in the types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingHandshake<'a> {
    username: &'a [u8],
    database: Option<&'a [u8]>,
    collation: u8,
    zstd_level: Option<u8>,
    has_attributes: bool,
    negotiated: CapabilityFlags,
    endpoints: ConnectionEndpoints,
}

impl<'a> RoutingHandshake<'a> {
    /// The username the client sent.
    #[must_use]
    pub const fn username(&self) -> &'a [u8] {
        self.username
    }

    /// The initial database, when negotiated.
    #[must_use]
    pub const fn database(&self) -> Option<&'a [u8]> {
        self.database
    }

    /// The client collation byte.
    #[must_use]
    pub const fn collation(&self) -> u8 {
        self.collation
    }

    /// The requested zstd level, when negotiated.
    #[must_use]
    pub const fn zstd_level(&self) -> Option<u8> {
        self.zstd_level
    }

    /// Whether the response carried connection attributes.
    #[must_use]
    pub const fn has_attributes(&self) -> bool {
        self.has_attributes
    }

    /// The negotiated session capability this gate was built under.
    #[must_use]
    pub const fn negotiated(&self) -> CapabilityFlags {
        self.negotiated
    }

    /// The listener and real client addresses.
    #[must_use]
    pub const fn endpoints(&self) -> ConnectionEndpoints {
        self.endpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's `SupportedServerCapabilities` literal union, bit-for-bit.
    #[test]
    fn supported_capabilities_match_go_literal() {
        assert_eq!(SUPPORTED_SERVER_CAPABILITIES.bits(), 0x053B_EEEF);
        assert!(SUPPORTED_SERVER_CAPABILITIES.contains(CapabilityFlags::PROTOCOL_41));
        assert!(SUPPORTED_SERVER_CAPABILITIES.contains(CapabilityFlags::DEPRECATE_EOF));
        // Not supported by the proxy: a drift here is deliberate.
        for absent in [
            CapabilityFlags::NO_SCHEMA,
            CapabilityFlags::IGNORE_SPACE,
            CapabilityFlags::IGNORE_SIGPIPE,
            CapabilityFlags::PS_MULTI_RESULTS,
            CapabilityFlags::CAN_HANDLE_EXPIRED_PASSWORDS,
            CapabilityFlags::SESSION_TRACK,
            CapabilityFlags::OPTIONAL_RESULTSET_METADATA,
            CapabilityFlags::QUERY_ATTRIBUTES,
        ] {
            assert!(
                !SUPPORTED_SERVER_CAPABILITIES.contains(absent),
                "{absent:?} must not be advertised"
            );
        }
    }

    /// The greeting clears `SSL` exactly when no frontend TLS exists.
    #[test]
    fn greeting_capability_follows_tls_availability() {
        let with_tls = greeting_capability(SUPPORTED_SERVER_CAPABILITIES, true);
        assert!(with_tls.contains(CapabilityFlags::SSL));
        let without_tls = greeting_capability(SUPPORTED_SERVER_CAPABILITIES, false);
        assert!(!without_tls.contains(CapabilityFlags::SSL));
        assert_eq!(
            without_tls.union(CapabilityFlags::SSL),
            SUPPORTED_SERVER_CAPABILITIES
        );
    }

    /// The greeting builder pins `mysql_native_password` and round-trips
    /// through the wire codec.
    #[test]
    fn greeting_roundtrips_through_wire_codec() {
        let salt = [7_u8; 20];
        let params = build_greeting(
            greeting_capability(SUPPORTED_SERVER_CAPABILITIES, true),
            &salt,
            b"8.0.11-TiDB-v8.5.0",
            42,
            0x21,
            StatusFlags::from_bits_retain(0x0002),
        );
        assert_eq!(params.auth_plugin_name, b"mysql_native_password");
        let encoded = match mysql_wire::encode_initial_handshake(params) {
            Ok(encoded) => encoded,
            Err(error) => unreachable!("encode failed: {error}"),
        };
        let parsed = match mysql_wire::parse_initial_handshake(&encoded) {
            Ok(parsed) => parsed,
            Err(error) => unreachable!("parse failed: {error}"),
        };
        assert_eq!(parsed.connection_id, 42);
        assert_eq!(parsed.auth_plugin_data_part_1, &salt[..8]);
        assert_eq!(parsed.auth_plugin_data_part_2, &salt[8..]);
        assert_eq!(parsed.auth_plugin_name, Some(&b"mysql_native_password"[..]));
        assert_eq!(
            parsed.capabilities,
            greeting_capability(SUPPORTED_SERVER_CAPABILITIES, true)
        );
    }

    /// The greeting carries exactly the low 32 bits of the `u64`
    /// connection id, matching Go `MakeInitialHandshake`.
    #[test]
    fn greeting_truncates_connection_id_like_go() {
        let salt = [1_u8; 20];
        let at_max = build_greeting(
            SUPPORTED_SERVER_CAPABILITIES,
            &salt,
            b"v",
            u64::from(u32::MAX),
            0x21,
            StatusFlags::from_bits_retain(0),
        );
        assert_eq!(at_max.connection_id, u32::MAX);
        let wrapped = build_greeting(
            SUPPORTED_SERVER_CAPABILITIES,
            &salt,
            b"v",
            u64::from(u32::MAX) + 1,
            0x21,
            StatusFlags::from_bits_retain(0),
        );
        assert_eq!(wrapped.connection_id, 0);
        let high_and_low = build_greeting(
            SUPPORTED_SERVER_CAPABILITIES,
            &salt,
            b"v",
            (7_u64 << 32) | 42,
            0x21,
            StatusFlags::from_bits_retain(0),
        );
        assert_eq!(high_and_low.connection_id, 42);
    }

    /// Missing `PROTOCOL_41` produces the fixed Go error triple; nothing
    /// about the client's actual mask reaches the response.
    #[test]
    fn missing_protocol41_returns_fixed_error() {
        let old_client = CapabilityFlags::LONG_PASSWORD.union(CapabilityFlags::SSL);
        let error = match negotiate_frontend(old_client, SUPPORTED_SERVER_CAPABILITIES) {
            Err(error) => error,
            Ok(ok) => unreachable!("pre-4.1 client accepted: {ok:?}"),
        };
        assert_eq!(error.missing, CapabilityFlags::PROTOCOL_41);
        let (code, state, message) = error.client_response();
        assert_eq!(code, 1251);
        assert_eq!(&state, b"08004");
        assert_eq!(
            message,
            "Client does not support authentication protocol requested by \
             server; consider upgrading MySQL client"
        );
        assert!(!message.contains("{}") && !message.contains('%'));
    }

    /// The intersection drops what either side lacks, reports the client's
    /// unsupported extras, and force-sets `PLUGIN_AUTH` (Go tolerance for
    /// clients that support it without advertising it).
    #[test]
    fn frontend_negotiation_matches_go() {
        let frontend = CapabilityFlags::PROTOCOL_41
            .union(CapabilityFlags::SECURE_CONNECTION)
            .union(CapabilityFlags::QUERY_ATTRIBUTES)
            .union(CapabilityFlags::SESSION_TRACK);
        let negotiation = match negotiate_frontend(frontend, SUPPORTED_SERVER_CAPABILITIES) {
            Ok(negotiation) => negotiation,
            Err(error) => unreachable!("negotiation failed: {error}"),
        };
        assert!(negotiation.plugin_auth_forced());
        assert_eq!(
            negotiation.negotiated(),
            CapabilityFlags::PROTOCOL_41
                .union(CapabilityFlags::SECURE_CONNECTION)
                .union(CapabilityFlags::PLUGIN_AUTH)
        );
        assert_eq!(
            negotiation.unsupported_by_proxy(),
            CapabilityFlags::QUERY_ATTRIBUTES.union(CapabilityFlags::SESSION_TRACK)
        );

        let modern = frontend.union(CapabilityFlags::PLUGIN_AUTH);
        let negotiation = match negotiate_frontend(modern, SUPPORTED_SERVER_CAPABILITIES) {
            Ok(negotiation) => negotiation,
            Err(error) => unreachable!("negotiation failed: {error}"),
        };
        assert!(!negotiation.plugin_auth_forced());
    }

    /// The `SSLRequest` mask wins over a differing response mask
    /// (Go: some drivers drop `SSL` in the second packet).
    #[test]
    fn tls_reconciliation_trusts_first_packet() {
        let ssl_request = CapabilityFlags::PROTOCOL_41
            .union(CapabilityFlags::SSL)
            .union(CapabilityFlags::PLUGIN_AUTH);
        let response_missing_ssl = ssl_request.without(CapabilityFlags::SSL);
        let reconciliation = reconcile_tls_capabilities(ssl_request, response_missing_ssl);
        assert_eq!(reconciliation.trusted, ssl_request);
        assert_eq!(reconciliation.mismatched, CapabilityFlags::SSL);

        let consistent = reconcile_tls_capabilities(ssl_request, ssl_request);
        assert_eq!(consistent.trusted, ssl_request);
        assert_eq!(consistent.mismatched.bits(), 0);
    }

    /// Backend verification requires `DEPRECATE_EOF` only when the session
    /// negotiated it, enforces `require-backend-tls`, and reports the
    /// ignored under-advertised set excluding `SSL`.
    #[test]
    fn backend_verification_matches_go() {
        let negotiated = CapabilityFlags::PROTOCOL_41
            .union(CapabilityFlags::PLUGIN_AUTH)
            .union(CapabilityFlags::DEPRECATE_EOF);
        let backend_without_eof = CapabilityFlags::PROTOCOL_41.union(CapabilityFlags::PLUGIN_AUTH);
        assert_eq!(
            verify_backend(
                backend_without_eof,
                negotiated,
                SUPPORTED_SERVER_CAPABILITIES,
                false
            ),
            Err(BackendVerificationError::MissingCapabilities(
                CapabilityFlags::DEPRECATE_EOF
            ))
        );

        // A session that never negotiated DEPRECATE_EOF does not require it.
        let no_eof_session = negotiated.without(CapabilityFlags::DEPRECATE_EOF);
        let verification = match verify_backend(
            backend_without_eof,
            no_eof_session,
            SUPPORTED_SERVER_CAPABILITIES,
            false,
        ) {
            Ok(verification) => verification,
            Err(error) => unreachable!("verification failed: {error}"),
        };
        assert!(
            !verification
                .ignored_by_backend
                .contains(CapabilityFlags::SSL)
        );
        assert!(
            verification
                .ignored_by_backend
                .contains(CapabilityFlags::COMPRESS),
            "under-advertised proxy capabilities are reported for logging"
        );

        // require-backend-tls without a backend SSL offer.
        assert_eq!(
            verify_backend(
                backend_without_eof.union(CapabilityFlags::DEPRECATE_EOF),
                negotiated,
                SUPPORTED_SERVER_CAPABILITIES,
                true
            ),
            Err(BackendVerificationError::TlsRequired)
        );
        // With SSL offered, TLS enforcement passes.
        let tls_backend = backend_without_eof
            .union(CapabilityFlags::DEPRECATE_EOF)
            .union(CapabilityFlags::SSL);
        assert!(
            verify_backend(tls_backend, negotiated, SUPPORTED_SERVER_CAPABILITIES, true).is_ok()
        );
    }

    /// Size gates at the exact boundaries: 1-MiB maximum (declared,
    /// pre-read) and 32-byte minimum (post-read).
    #[test]
    fn handshake_size_gates_match_go() {
        let max = mysql_wire::limits::MAX_PRE_HANDSHAKE_PACKET_LEN;
        assert!(check_handshake_packet_size(max - 1).is_ok());
        assert!(check_handshake_packet_size(max).is_ok());
        assert!(check_handshake_packet_size(max + 1).is_err());

        assert!(check_min_client_handshake(MIN_CLIENT_HANDSHAKE_LEN - 1).is_err());
        assert!(check_min_client_handshake(MIN_CLIENT_HANDSHAKE_LEN).is_ok());
        assert!(check_min_client_handshake(MIN_CLIENT_HANDSHAKE_LEN + 1).is_ok());
        let Err(error) = check_min_client_handshake(31) else {
            unreachable!("31 bytes accepted")
        };
        assert_eq!(error.length, 31);
        assert!(error.to_string().contains("32-byte minimum"));
    }
}
