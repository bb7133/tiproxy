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

//! Backend authentication relay (SES-02), frozen from Go
//! `pkg/proxy/backend/authenticator.go`.
//!
//! Three pieces:
//!
//! 1. [`plan_backend_handshake`] — the decisions of Go `writeAuthHandshake`:
//!    the capability mask sent to the backend, whether backend TLS activates
//!    (and that it activates **between** the 32-byte `SSLRequest` prefix and
//!    the full response), and the Go error routes for each failure point.
//! 2. [`AuthRelay`] — the pure sub-FSM of Go's auth-forward loop: the proxy
//!    relays authentication exchanges between backend and client without
//!    interpreting them, tracking only what Go tracks (the packet index for
//!    first-packet PROXY-protocol detection, the announced plugin for the
//!    `caching_sha2_password` fast path, and whose turn it is). Compression
//!    activates for both sides only on the final OK.
//! 3. Secret redaction by construction: events and effects are
//!    classifications and never carry authentication bytes — passwords,
//!    tokens, and scrambles stay in the runtime's buffers. `Debug` output
//!    of every type in this module is therefore secret-free, and a test
//!    sweeps the whole event/effect/error surface to prove it.
//!
//! Go parity notes:
//! - The proxy forwards the client's credentials with the sentinel
//!   [`UNKNOWN_AUTH_PLUGIN`] so the backend always re-requests auth data.
//! - The fast path (`0x01 0x03` → keep waiting for the backend) applies
//!   only when the announced plugin is `caching_sha2_password`; every other
//!   plugin (including `tidb_sm3_password`, clear, socket, LDAP) is a
//!   plain pass-through.
//! - First-packet backend errors `1156` (packets out of order), `8052`
//!   (`TiDB` invalid sequence), and **any** error whose message contains
//!   "PROXY Protocol" (Go's substring check has no code guard) classify
//!   as `BackendProxyProtocol`; later errors classify as
//!   `AuthenticationFailed` (Go `handleHandshakeError`).
//!   [`classify_backend_auth_packet`] performs the classification over a
//!   transiently borrowed payload; the event carries only the resulting
//!   class, never the message or any auth bytes.
//! - A handler-approved error triggers a backend reconnect
//!   (Go `HandleHandshakeErr` → `RECONNECT`). The reconnect is an explicit
//!   gate: the relay accepts nothing until [`AuthEvent::BackendReconnected`]
//!   delivers the **new** backend capability (Go re-reads the greeting and
//!   compression later uses the new mask).

use core::fmt;

use mysql_wire::CapabilityFlags;

use crate::error_source::FailureKind;
use crate::handshake::RoutingHandshake;

/// Go `unknownAuthPlugin`: sent to the backend so it re-requests the auth
/// data with its own plugin choice.
pub const UNKNOWN_AUTH_PLUGIN: &[u8] = b"auth_unknown_plugin";

/// Known authentication plugins (Go `pkg/proxy/net/auth.go`). The relay
/// only *dispatches* on these; it never interprets auth payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPluginName {
    /// `mysql_native_password`.
    NativePassword,
    /// `caching_sha2_password` (the only plugin with the fast path).
    CachingSha2Password,
    /// `tidb_sm3_password` (pass-through; no fast path in Go's loop).
    TidbSm3Password,
    /// `mysql_clear_password` (pass-through).
    MysqlClearPassword,
    /// `auth_socket` (pass-through).
    AuthSocket,
    /// `tidb_session_token` (session migration).
    TidbSessionToken,
    /// `tidb_auth_token` (pass-through).
    TidbAuthToken,
    /// `authentication_ldap_simple` (pass-through).
    LdapSimple,
    /// `authentication_ldap_sasl` (pass-through).
    LdapSasl,
    /// Any other plugin: relayed untouched, dispatched as pass-through.
    Other,
}

impl AuthPluginName {
    /// Classifies a plugin-name byte string. Unknown names map to
    /// [`Self::Other`] without retaining the bytes.
    #[must_use]
    pub fn classify(name: &[u8]) -> Self {
        match name {
            b"mysql_native_password" => Self::NativePassword,
            b"caching_sha2_password" => Self::CachingSha2Password,
            b"tidb_sm3_password" => Self::TidbSm3Password,
            b"mysql_clear_password" => Self::MysqlClearPassword,
            b"auth_socket" => Self::AuthSocket,
            b"tidb_session_token" => Self::TidbSessionToken,
            b"tidb_auth_token" => Self::TidbAuthToken,
            b"authentication_ldap_simple" => Self::LdapSimple,
            b"authentication_ldap_sasl" => Self::LdapSasl,
            _ => Self::Other,
        }
    }
}

/// Compression selected from a capability mask, mirroring Go `setCompress`:
/// zlib wins when both bits are present (Go's `if`/`else if` order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionSelection {
    /// No compression negotiated.
    None,
    /// Classic zlib.
    Zlib,
    /// zstd at the client-requested level.
    Zstd {
        /// The zstd level from the handshake response.
        level: u8,
    },
}

/// Selects the compression algorithm for one side, mirroring Go
/// `setCompress` exactly.
#[must_use]
pub const fn compression_selection(
    capability: CapabilityFlags,
    zstd_level: u8,
) -> CompressionSelection {
    if capability.contains(CapabilityFlags::COMPRESS) {
        CompressionSelection::Zlib
    } else if capability.contains(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM) {
        CompressionSelection::Zstd { level: zstd_level }
    } else {
        CompressionSelection::None
    }
}

/// How the backend handshake carries TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendTlsMode {
    /// Send the 32-byte `SSLRequest` prefix, run the backend TLS
    /// handshake, then send the full response over TLS.
    Enabled,
    /// Send the full response in plaintext with `SSL` cleared.
    Disabled,
}

/// The planned backend handshake: the capability mask to send and the TLS
/// mode, plus the fixed failure routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendHandshakePlan {
    /// The capability mask for the backend handshake response.
    pub capabilities: CapabilityFlags,
    /// Whether and how TLS activates (always before credentials leave).
    pub tls: BackendTlsMode,
}

/// `require-backend-tls` is set but the proxy has no backend TLS
/// configuration (Go `ErrProxyNoTLS`;
/// [`FailureKind::ProxyNoTls`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendTlsUnavailable;

impl fmt::Display for BackendTlsUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("require-backend-tls is set but no backend TLS configuration exists")
    }
}

impl std::error::Error for BackendTlsUnavailable {}

/// Plans the backend handshake, mirroring Go `writeAuthHandshake`:
///
/// - The mask is `negotiated ∩ backend`, plus `CONNECT_ATTRS` when the
///   client sent attributes, plus `SSL` when TLS activates (cleared when
///   not).
/// - Under `require-backend-tls`, a missing TLS configuration is
///   [`BackendTlsUnavailable`] (Go `ErrProxyNoTLS`). Otherwise TLS is
///   opportunistic: it activates only when the client negotiated `SSL`,
///   the backend offers `SSL`, and a configuration exists ("when client
///   TLS is disabled, also disables proxy TLS").
/// - Failure routes (for the runtime): a backend TLS handshake error is
///   [`FailureKind::BackendProxyProtocol`] (Go wraps `ErrBackendPPV2` —
///   a PROXY-protocol mismatch surfaces as an unrecognized TLS packet);
///   response write errors are [`FailureKind::BackendHandshake`].
///
/// # Errors
///
/// Returns [`BackendTlsUnavailable`] as described above.
pub fn plan_backend_handshake(
    routing: &RoutingHandshake<'_>,
    backend: CapabilityFlags,
    require_backend_tls: bool,
    backend_tls_available: bool,
) -> Result<BackendHandshakePlan, BackendTlsUnavailable> {
    let mut capabilities =
        CapabilityFlags::from_bits_retain(routing.negotiated().bits() & backend.bits());
    if routing.has_attributes() {
        capabilities = capabilities.union(CapabilityFlags::CONNECT_ATTRS);
    }
    let enable_tls = if require_backend_tls {
        if !backend_tls_available {
            return Err(BackendTlsUnavailable);
        }
        true
    } else {
        routing.negotiated().contains(CapabilityFlags::SSL)
            && backend.contains(CapabilityFlags::SSL)
            && backend_tls_available
    };
    Ok(if enable_tls {
        BackendHandshakePlan {
            capabilities: capabilities.union(CapabilityFlags::SSL),
            tls: BackendTlsMode::Enabled,
        }
    } else {
        BackendHandshakePlan {
            capabilities: capabilities.without(CapabilityFlags::SSL),
            tls: BackendTlsMode::Disabled,
        }
    })
}

/// Go `mysql.ER_NET_PACKETS_OUT_OF_ORDER`: a PROXY-protocol suspect in
/// the first backend packet.
pub const ER_NET_PACKETS_OUT_OF_ORDER: u16 = 1156;
/// Go/`TiDB` `ER_INVALID_SEQUENCE` (`authenticator.go` local constant).
pub const ER_INVALID_SEQUENCE: u16 = 8052;
/// The message marker Go sniffs for (`strings.Contains`, **no code
/// guard** — any error code qualifies).
pub const PROXY_PROTOCOL_MESSAGE_MARKER: &[u8] = b"PROXY Protocol";

/// A backend authentication packet that cannot be classified safely.
/// Carries only the observed length and a static reason — never payload
/// bytes. (Go's loop would panic slicing an auth-switch without a NUL
/// terminator; returning this typed error instead is a recorded
/// divergence, SES-02-D1.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedAuthPacket {
    /// The payload length observed.
    pub length: usize,
    /// A static description of the violated shape.
    pub reason: &'static str,
}

impl fmt::Display for MalformedAuthPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "malformed backend auth packet ({} bytes): {}",
            self.length, self.reason
        )
    }
}

impl std::error::Error for MalformedAuthPacket {}

fn contains_marker(haystack: &[u8]) -> bool {
    haystack
        .windows(PROXY_PROTOCOL_MESSAGE_MARKER.len())
        .any(|window| window == PROXY_PROTOCOL_MESSAGE_MARKER)
}

/// Classifies one backend authentication packet into a secret-free
/// [`AuthEvent`] without panicking on any input. The payload is borrowed
/// transiently: nothing from it (message bytes, plugin names, auth data)
/// enters the returned event or any `Debug` output.
///
/// Rules, mirroring Go's auth-forward loop and `handleHandshakeError`:
/// - `0x00` → [`AuthEvent::BackendOk`].
/// - `0xff` → [`AuthEvent::BackendError`] with
///   [`AuthErrorClass::ProxyProtocolSuspect`] when the code is `1156` or
///   `8052`, **or** the message contains "PROXY Protocol" (no code
///   guard, exactly like Go); `handler_reconnect` is always `false` —
///   the handshake-handler decision belongs to the runtime.
/// - `0xfe` → [`AuthEvent::AuthSwitchRequest`] with the plugin name
///   classified up to the NUL terminator. A missing NUL is
///   [`MalformedAuthPacket`] (Go would panic here; SES-02-D1).
/// - `0x01` with exactly two bytes and `0x03` →
///   [`AuthEvent::FastAuthSuccess`] (the plugin gate stays in the relay).
/// - Anything else non-empty → [`AuthEvent::ExtraAuthData`].
///
/// # Errors
///
/// Returns [`MalformedAuthPacket`] for an empty payload, an unparsable
/// error packet, or an unterminated auth-switch plugin name.
pub fn classify_backend_auth_packet(
    payload: &[u8],
    capabilities: CapabilityFlags,
) -> Result<AuthEvent, MalformedAuthPacket> {
    let Some(&header) = payload.first() else {
        return Err(MalformedAuthPacket {
            length: 0,
            reason: "empty payload",
        });
    };
    match header {
        0x00 => Ok(AuthEvent::BackendOk),
        0xff => {
            let Ok(error) = mysql_wire::parse_error_packet(payload, capabilities) else {
                return Err(MalformedAuthPacket {
                    length: payload.len(),
                    reason: "unparsable error packet",
                });
            };
            let suspect = error.code == ER_NET_PACKETS_OUT_OF_ORDER
                || error.code == ER_INVALID_SEQUENCE
                || contains_marker(error.message);
            Ok(AuthEvent::BackendError {
                class: if suspect {
                    AuthErrorClass::ProxyProtocolSuspect
                } else {
                    AuthErrorClass::Other
                },
                handler_reconnect: false,
            })
        }
        0xfe => {
            let name_and_rest = &payload[1..];
            let Some(nul) = name_and_rest.iter().position(|&b| b == 0) else {
                return Err(MalformedAuthPacket {
                    length: payload.len(),
                    reason: "auth switch without a NUL-terminated plugin name",
                });
            };
            Ok(AuthEvent::AuthSwitchRequest {
                plugin: AuthPluginName::classify(&name_and_rest[..nul]),
            })
        }
        0x01 if payload.len() == 2 && payload[1] == 0x03 => Ok(AuthEvent::FastAuthSuccess),
        _ => Ok(AuthEvent::ExtraAuthData),
    }
}

/// Classified backend error during authentication.
/// [`classify_backend_auth_packet`] performs the classification (codes
/// `1156`/`8052`, or the "PROXY Protocol" message substring under **any**
/// code); the event carries only the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthErrorClass {
    /// `1156` packets out of order, `8052` `TiDB` invalid sequence, or any
    /// error whose message mentions "PROXY Protocol" (no code guard) — a
    /// PROXY-protocol mismatch when seen in the **first** backend packet.
    ProxyProtocolSuspect,
    /// Any other backend error.
    Other,
}

/// Classified events for the authentication relay. No variant carries
/// authentication bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEvent {
    /// The backend sent OK: authentication succeeded.
    BackendOk,
    /// The backend sent an error packet.
    BackendError {
        /// The wire-layer classification of the error.
        class: AuthErrorClass,
        /// The handshake handler approved a reconnect for this error
        /// (Go `HandleHandshakeErr`).
        handler_reconnect: bool,
    },
    /// The backend requested an auth switch (`0xfe`) to `plugin`.
    AuthSwitchRequest {
        /// The announced plugin, classified without retaining bytes.
        plugin: AuthPluginName,
    },
    /// The backend sent `0x01 0x03` — the `caching_sha2_password` fast
    /// path indicator (only meaningful under that plugin).
    FastAuthSuccess,
    /// The backend sent other extra auth data (`0x01 …` or any
    /// plugin-specific packet requiring a client response).
    ExtraAuthData,
    /// The client's next authentication packet arrived.
    ClientAuthResponse,
    /// After a handler-approved reconnect: the new backend's greeting was
    /// read and verified; carries the new capability mask (Go re-reads
    /// `backendCapability` after `RECONNECT`).
    BackendReconnected {
        /// The new backend's capability mask.
        backend: CapabilityFlags,
    },
}

/// Relay effects. No effect carries authentication bytes: forwarding
/// refers to the runtime's buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEffect {
    /// Forward the backend packet to the client unchanged.
    ForwardBackendToClient,
    /// Forward the client packet to the backend unchanged.
    ForwardClientToBackend,
    /// Activate client-side compression.
    ActivateClientCompression(CompressionSelection),
    /// Activate backend-side compression.
    ActivateBackendCompression(CompressionSelection),
    /// Close the backend and redo the backend handshake
    /// (Go `RECONNECT`).
    ReconnectBackend,
}

/// The relay finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authentication succeeded; compression is activated by the
    /// accompanying effects.
    Success,
    /// Authentication failed with the Go route the runtime must use.
    Failed(FailureKind),
}

/// An illegal `(relay state, event)` pair. Carries the pair only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRelayError {
    /// The turn the relay was in.
    pub state: AuthTurn,
    /// The event that is not legal on that turn.
    pub event: AuthEvent,
}

impl fmt::Display for AuthRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal auth event {:?} while {:?}",
            self.event, self.state
        )
    }
}

impl std::error::Error for AuthRelayError {}

/// Whose packet the relay expects next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTurn {
    /// Waiting for a backend packet.
    AwaitingBackend,
    /// Waiting for the client's response to relayed auth data.
    AwaitingClient,
    /// A handler-approved reconnect is in flight: nothing is legal until
    /// [`AuthEvent::BackendReconnected`] delivers the new capability.
    AwaitingReconnect,
    /// The relay reached a terminal outcome.
    Finished,
}

/// One step's result: effects plus an optional terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStep {
    /// Effects to execute, in order.
    pub effects: Vec<AuthEffect>,
    /// The terminal outcome, when this step finished the relay.
    pub outcome: Option<AuthOutcome>,
}

/// The pure authentication relay machine (Go's auth-forward loop).
///
/// Single owner of its mutable state; `Clone` yields an independent value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRelay {
    turn: AuthTurn,
    packet_index: u32,
    plugin: Option<AuthPluginName>,
    negotiated: CapabilityFlags,
    backend: CapabilityFlags,
    zstd_level: u8,
}

impl AuthRelay {
    /// Starts a relay after the backend handshake response was sent, with
    /// the session's negotiated mask, the backend mask, and the client's
    /// requested zstd level (0 when absent).
    #[must_use]
    pub const fn new(
        negotiated: CapabilityFlags,
        backend: CapabilityFlags,
        zstd_level: u8,
    ) -> Self {
        Self {
            turn: AuthTurn::AwaitingBackend,
            packet_index: 0,
            plugin: None,
            negotiated,
            backend,
            zstd_level,
        }
    }

    /// The current turn.
    #[must_use]
    pub const fn turn(&self) -> AuthTurn {
        self.turn
    }

    /// The most recently announced plugin, when any.
    #[must_use]
    pub const fn plugin(&self) -> Option<AuthPluginName> {
        self.plugin
    }

    /// Applies one classified event.
    ///
    /// # Errors
    ///
    /// Returns [`AuthRelayError`] for an illegal pair; the relay is
    /// unchanged.
    pub fn on_event(&mut self, event: AuthEvent) -> Result<AuthStep, AuthRelayError> {
        match (self.turn, event) {
            (AuthTurn::AwaitingBackend, AuthEvent::BackendOk) => {
                self.turn = AuthTurn::Finished;
                Ok(AuthStep {
                    effects: vec![
                        AuthEffect::ForwardBackendToClient,
                        AuthEffect::ActivateClientCompression(compression_selection(
                            self.negotiated,
                            self.zstd_level,
                        )),
                        AuthEffect::ActivateBackendCompression(compression_selection(
                            CapabilityFlags::from_bits_retain(
                                self.negotiated.bits() & self.backend.bits(),
                            ),
                            self.zstd_level,
                        )),
                    ],
                    outcome: Some(AuthOutcome::Success),
                })
            }
            (
                AuthTurn::AwaitingBackend,
                AuthEvent::BackendError {
                    class,
                    handler_reconnect,
                },
            ) => {
                if handler_reconnect {
                    // Go: close the backend and redo the handshake without
                    // forwarding the error to the client. The relay then
                    // waits for the new backend's verified greeting.
                    self.packet_index = 0;
                    self.plugin = None;
                    self.turn = AuthTurn::AwaitingReconnect;
                    Ok(AuthStep {
                        effects: vec![AuthEffect::ReconnectBackend],
                        outcome: None,
                    })
                } else {
                    self.turn = AuthTurn::Finished;
                    let kind = if self.packet_index == 0
                        && matches!(class, AuthErrorClass::ProxyProtocolSuspect)
                    {
                        FailureKind::BackendProxyProtocol
                    } else {
                        FailureKind::AuthenticationFailed
                    };
                    Ok(AuthStep {
                        // Go forwards the error packet before classifying.
                        effects: vec![AuthEffect::ForwardBackendToClient],
                        outcome: Some(AuthOutcome::Failed(kind)),
                    })
                }
            }
            (AuthTurn::AwaitingBackend, AuthEvent::AuthSwitchRequest { plugin }) => {
                self.packet_index += 1;
                self.plugin = Some(plugin);
                self.turn = AuthTurn::AwaitingClient;
                Ok(AuthStep {
                    effects: vec![AuthEffect::ForwardBackendToClient],
                    outcome: None,
                })
            }
            (AuthTurn::AwaitingBackend, AuthEvent::FastAuthSuccess) => {
                self.packet_index += 1;
                if self.plugin == Some(AuthPluginName::CachingSha2Password) {
                    // Fast path: relay the indicator and keep waiting for
                    // the backend's OK — no client turn.
                    Ok(AuthStep {
                        effects: vec![AuthEffect::ForwardBackendToClient],
                        outcome: None,
                    })
                } else {
                    // Any other plugin treats it as ordinary extra data.
                    self.turn = AuthTurn::AwaitingClient;
                    Ok(AuthStep {
                        effects: vec![AuthEffect::ForwardBackendToClient],
                        outcome: None,
                    })
                }
            }
            (AuthTurn::AwaitingBackend, AuthEvent::ExtraAuthData) => {
                self.packet_index += 1;
                self.turn = AuthTurn::AwaitingClient;
                Ok(AuthStep {
                    effects: vec![AuthEffect::ForwardBackendToClient],
                    outcome: None,
                })
            }
            (AuthTurn::AwaitingReconnect, AuthEvent::BackendReconnected { backend }) => {
                // The new backend's capability replaces the old one; later
                // compression activation uses the new mask.
                self.backend = backend;
                self.turn = AuthTurn::AwaitingBackend;
                Ok(AuthStep {
                    effects: Vec::new(),
                    outcome: None,
                })
            }
            (AuthTurn::AwaitingClient, AuthEvent::ClientAuthResponse) => {
                self.turn = AuthTurn::AwaitingBackend;
                Ok(AuthStep {
                    effects: vec![AuthEffect::ForwardClientToBackend],
                    outcome: None,
                })
            }
            (state, event) => Err(AuthRelayError { state, event }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(bits: u32) -> CapabilityFlags {
        CapabilityFlags::from_bits_retain(bits)
    }

    fn new_relay() -> AuthRelay {
        AuthRelay::new(
            caps(
                CapabilityFlags::PROTOCOL_41.bits()
                    | CapabilityFlags::COMPRESS.bits()
                    | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits(),
            ),
            caps(
                CapabilityFlags::PROTOCOL_41.bits()
                    | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits(),
            ),
            5,
        )
    }

    fn step(relay: &mut AuthRelay, event: AuthEvent) -> AuthStep {
        match relay.on_event(event) {
            Ok(step) => step,
            Err(error) => unreachable!("relay step failed: {error}"),
        }
    }

    /// Plugin classification covers Go's list; unknown names retain no
    /// bytes.
    #[test]
    fn plugin_classification_matches_go_list() {
        let table: [(&[u8], AuthPluginName); 9] = [
            (b"mysql_native_password", AuthPluginName::NativePassword),
            (
                b"caching_sha2_password",
                AuthPluginName::CachingSha2Password,
            ),
            (b"tidb_sm3_password", AuthPluginName::TidbSm3Password),
            (b"mysql_clear_password", AuthPluginName::MysqlClearPassword),
            (b"auth_socket", AuthPluginName::AuthSocket),
            (b"tidb_session_token", AuthPluginName::TidbSessionToken),
            (b"tidb_auth_token", AuthPluginName::TidbAuthToken),
            (b"authentication_ldap_simple", AuthPluginName::LdapSimple),
            (b"authentication_ldap_sasl", AuthPluginName::LdapSasl),
        ];
        for (name, expected) in table {
            assert_eq!(AuthPluginName::classify(name), expected);
        }
        assert_eq!(
            AuthPluginName::classify(b"secret-custom-plugin"),
            AuthPluginName::Other
        );
        assert_eq!(UNKNOWN_AUTH_PLUGIN, b"auth_unknown_plugin");
    }

    /// Go `setCompress`: zlib wins over zstd; zstd carries the level.
    #[test]
    fn compression_selection_matches_go() {
        let both = caps(
            CapabilityFlags::COMPRESS.bits() | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits(),
        );
        assert_eq!(compression_selection(both, 9), CompressionSelection::Zlib);
        assert_eq!(
            compression_selection(caps(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits()), 9),
            CompressionSelection::Zstd { level: 9 }
        );
        assert_eq!(
            compression_selection(caps(CapabilityFlags::PROTOCOL_41.bits()), 9),
            CompressionSelection::None
        );
    }

    /// Success: OK forwards to the client and activates compression per
    /// side — client from the negotiated mask, backend from the
    /// negotiated∩backend mask.
    #[test]
    fn success_activates_compression_per_side() {
        let mut relay = new_relay();
        let step = step(&mut relay, AuthEvent::BackendOk);
        assert_eq!(
            step.effects,
            vec![
                AuthEffect::ForwardBackendToClient,
                AuthEffect::ActivateClientCompression(CompressionSelection::Zlib),
                AuthEffect::ActivateBackendCompression(CompressionSelection::Zstd { level: 5 }),
            ]
        );
        assert_eq!(step.outcome, Some(AuthOutcome::Success));
        assert_eq!(relay.turn(), AuthTurn::Finished);
        // Nothing after the terminal outcome.
        assert!(relay.on_event(AuthEvent::BackendOk).is_err());
    }

    /// Plugin switch: relay to the client, wait for the client, forward
    /// back, then OK.
    #[test]
    fn plugin_switch_roundtrip() {
        let mut relay = new_relay();
        let switch = step(
            &mut relay,
            AuthEvent::AuthSwitchRequest {
                plugin: AuthPluginName::NativePassword,
            },
        );
        assert_eq!(switch.effects, vec![AuthEffect::ForwardBackendToClient]);
        assert_eq!(relay.turn(), AuthTurn::AwaitingClient);
        assert_eq!(relay.plugin(), Some(AuthPluginName::NativePassword));
        // A backend packet during the client's turn is illegal.
        assert!(relay.on_event(AuthEvent::BackendOk).is_err());
        let response = step(&mut relay, AuthEvent::ClientAuthResponse);
        assert_eq!(response.effects, vec![AuthEffect::ForwardClientToBackend]);
        let done = step(&mut relay, AuthEvent::BackendOk);
        assert_eq!(done.outcome, Some(AuthOutcome::Success));
    }

    /// The `caching_sha2_password` fast path skips the client turn; under
    /// any other plugin the same byte pattern is ordinary extra data.
    #[test]
    fn sha2_fast_path_is_plugin_gated() {
        let mut relay = new_relay();
        let _ = step(
            &mut relay,
            AuthEvent::AuthSwitchRequest {
                plugin: AuthPluginName::CachingSha2Password,
            },
        );
        let _ = step(&mut relay, AuthEvent::ClientAuthResponse);
        let fast = step(&mut relay, AuthEvent::FastAuthSuccess);
        assert_eq!(fast.effects, vec![AuthEffect::ForwardBackendToClient]);
        assert_eq!(relay.turn(), AuthTurn::AwaitingBackend, "no client turn");
        let done = step(&mut relay, AuthEvent::BackendOk);
        assert_eq!(done.outcome, Some(AuthOutcome::Success));

        // tidb_sm3_password: Go's loop has no fast path for it.
        let mut relay = relay_with_plugin(AuthPluginName::TidbSm3Password);
        let data = step(&mut relay, AuthEvent::FastAuthSuccess);
        assert_eq!(data.effects, vec![AuthEffect::ForwardBackendToClient]);
        assert_eq!(relay.turn(), AuthTurn::AwaitingClient, "ordinary turn");
    }

    fn relay_with_plugin(plugin: AuthPluginName) -> AuthRelay {
        let mut relay = new_relay();
        let _ = step(&mut relay, AuthEvent::AuthSwitchRequest { plugin });
        let _ = step(&mut relay, AuthEvent::ClientAuthResponse);
        relay
    }

    #[test]
    fn pass_through_plugins_have_no_fast_path() {
        // caching_sha2_password is the only plugin with a fast path; every
        // other named plugin — and any unknown `Other` — is a plain
        // pass-through in Go's loop (see the module doc, frozen from
        // pkg/proxy/backend/authenticator.go). A `0x01 0x03`-shaped
        // FastAuthSuccess packet is therefore NOT a short-circuit for them: it
        // is forwarded untouched and the exchange keeps its ordinary client
        // turn, so the whole handshake is relayed. This is the live matrix's
        // stand-in for the plugins a stock mysql client cannot exercise
        // against a bare TiUP playground (sm3/clear/socket/token/LDAP).
        for plugin in [
            AuthPluginName::TidbSm3Password,
            AuthPluginName::MysqlClearPassword,
            AuthPluginName::AuthSocket,
            AuthPluginName::TidbSessionToken,
            AuthPluginName::TidbAuthToken,
            AuthPluginName::LdapSimple,
            AuthPluginName::LdapSasl,
            AuthPluginName::Other,
        ] {
            let mut relay = relay_with_plugin(plugin);
            let data = step(&mut relay, AuthEvent::FastAuthSuccess);
            assert_eq!(
                data.effects,
                vec![AuthEffect::ForwardBackendToClient],
                "{plugin:?}: the packet is relayed untouched, not consumed as a fast path"
            );
            assert_eq!(
                relay.turn(),
                AuthTurn::AwaitingClient,
                "{plugin:?}: no fast-path short-circuit — ordinary pass-through turn"
            );
        }
    }

    /// First-packet PROXY-protocol suspects route to `BackendProxyProtocol`;
    /// later errors and non-suspects route to `AuthenticationFailed`. The
    /// error packet is forwarded either way (Go forwards before
    /// classifying).
    #[test]
    fn error_routes_match_handle_handshake_error() {
        let mut relay = new_relay();
        let step_result = step(
            &mut relay,
            AuthEvent::BackendError {
                class: AuthErrorClass::ProxyProtocolSuspect,
                handler_reconnect: false,
            },
        );
        assert_eq!(
            step_result.effects,
            vec![AuthEffect::ForwardBackendToClient]
        );
        assert_eq!(
            step_result.outcome,
            Some(AuthOutcome::Failed(FailureKind::BackendProxyProtocol))
        );

        // The same class after the first packet is an auth failure.
        let mut relay = relay_with_plugin(AuthPluginName::NativePassword);
        let step_result = step(
            &mut relay,
            AuthEvent::BackendError {
                class: AuthErrorClass::ProxyProtocolSuspect,
                handler_reconnect: false,
            },
        );
        assert_eq!(
            step_result.outcome,
            Some(AuthOutcome::Failed(FailureKind::AuthenticationFailed))
        );

        // A non-suspect first-packet error is an auth failure too.
        let mut relay = new_relay();
        let step_result = step(
            &mut relay,
            AuthEvent::BackendError {
                class: AuthErrorClass::Other,
                handler_reconnect: false,
            },
        );
        assert_eq!(
            step_result.outcome,
            Some(AuthOutcome::Failed(FailureKind::AuthenticationFailed))
        );
    }

    /// A handler-approved error reconnects: state resets (packet index and
    /// plugin) and the error is not forwarded to the client.
    #[test]
    fn handler_reconnect_resets_the_relay() {
        let mut relay = relay_with_plugin(AuthPluginName::NativePassword);
        let step_result = step(
            &mut relay,
            AuthEvent::BackendError {
                class: AuthErrorClass::Other,
                handler_reconnect: true,
            },
        );
        assert_eq!(step_result.effects, vec![AuthEffect::ReconnectBackend]);
        assert_eq!(step_result.outcome, None);
        assert_eq!(relay.turn(), AuthTurn::AwaitingReconnect);
        assert_eq!(relay.plugin(), None);
        // The reconnect is a hard gate: nothing is legal until the new
        // backend's verified greeting arrives.
        for event in [
            AuthEvent::BackendOk,
            AuthEvent::ClientAuthResponse,
            AuthEvent::ExtraAuthData,
            AuthEvent::FastAuthSuccess,
        ] {
            assert!(relay.on_event(event).is_err(), "{event:?} before greeting");
        }
        let step_result = step(
            &mut relay,
            AuthEvent::BackendReconnected {
                backend: caps(CapabilityFlags::PROTOCOL_41.bits()),
            },
        );
        assert_eq!(step_result.effects, Vec::new());
        assert_eq!(relay.turn(), AuthTurn::AwaitingBackend);
        // After reconnect, a first-packet PROXY-protocol suspect routes
        // as such again (the packet index reset).
        let step_result = step(
            &mut relay,
            AuthEvent::BackendError {
                class: AuthErrorClass::ProxyProtocolSuspect,
                handler_reconnect: false,
            },
        );
        assert_eq!(
            step_result.outcome,
            Some(AuthOutcome::Failed(FailureKind::BackendProxyProtocol))
        );
    }

    /// Compression after a reconnect uses the **new** backend capability
    /// (Go re-reads the greeting and `setCompress` sees the new mask).
    #[test]
    fn reconnect_swaps_backend_capability_for_compression() {
        // Old backend: zstd. New backend: no compression bits at all.
        let mut relay = new_relay();
        let _ = step(
            &mut relay,
            AuthEvent::BackendError {
                class: AuthErrorClass::Other,
                handler_reconnect: true,
            },
        );
        let _ = step(
            &mut relay,
            AuthEvent::BackendReconnected {
                backend: caps(CapabilityFlags::PROTOCOL_41.bits()),
            },
        );
        let done = step(&mut relay, AuthEvent::BackendOk);
        assert_eq!(
            done.effects,
            vec![
                AuthEffect::ForwardBackendToClient,
                // Client side still uses the negotiated mask (zlib wins).
                AuthEffect::ActivateClientCompression(CompressionSelection::Zlib),
                // Backend side reflects the NEW backend: no compression.
                AuthEffect::ActivateBackendCompression(CompressionSelection::None),
            ]
        );
        // BackendReconnected outside the reconnect gate is illegal.
        let mut relay = new_relay();
        assert!(
            relay
                .on_event(AuthEvent::BackendReconnected { backend: caps(0) })
                .is_err()
        );
    }

    /// The classifier maps every packet shape without panicking and never
    /// retains payload bytes.
    #[test]
    fn classifier_matches_go_rules() {
        let caps41 = caps(CapabilityFlags::PROTOCOL_41.bits());
        assert_eq!(
            classify_backend_auth_packet(&[0x00, 0x00, 0x00], caps41),
            Ok(AuthEvent::BackendOk)
        );
        // Auth switch with a NUL-terminated plugin name.
        let mut switch = vec![0xfe];
        switch.extend_from_slice(b"caching_sha2_password\0salt-bytes");
        assert_eq!(
            classify_backend_auth_packet(&switch, caps41),
            Ok(AuthEvent::AuthSwitchRequest {
                plugin: AuthPluginName::CachingSha2Password
            })
        );
        // Fast-auth success is exactly two bytes.
        assert_eq!(
            classify_backend_auth_packet(&[0x01, 0x03], caps41),
            Ok(AuthEvent::FastAuthSuccess)
        );
        assert_eq!(
            classify_backend_auth_packet(&[0x01, 0x03, 0x00], caps41),
            Ok(AuthEvent::ExtraAuthData)
        );
        assert_eq!(
            classify_backend_auth_packet(&[0x01, 0x04], caps41),
            Ok(AuthEvent::ExtraAuthData)
        );

        // Error classification: 1156 and 8052 by code.
        for code in [ER_NET_PACKETS_OUT_OF_ORDER, ER_INVALID_SEQUENCE] {
            let mut packet = vec![0xff];
            packet.extend_from_slice(&code.to_le_bytes());
            packet.extend_from_slice(b"#HY000ordinary text");
            assert_eq!(
                classify_backend_auth_packet(&packet, caps41),
                Ok(AuthEvent::BackendError {
                    class: AuthErrorClass::ProxyProtocolSuspect,
                    handler_reconnect: false,
                }),
                "code {code}"
            );
        }
        // The message sniff has NO code guard (Go strings.Contains): a
        // non-1105 code with the marker is still a suspect.
        let mut packet = vec![0xff];
        packet.extend_from_slice(&9999_u16.to_le_bytes());
        packet.extend_from_slice(b"#HY000invalid PROXY Protocol header");
        assert_eq!(
            classify_backend_auth_packet(&packet, caps41),
            Ok(AuthEvent::BackendError {
                class: AuthErrorClass::ProxyProtocolSuspect,
                handler_reconnect: false,
            })
        );
        // An ordinary auth error is not a suspect.
        let mut packet = vec![0xff];
        packet.extend_from_slice(&1045_u16.to_le_bytes());
        packet.extend_from_slice(b"#28000Access denied for user");
        assert_eq!(
            classify_backend_auth_packet(&packet, caps41),
            Ok(AuthEvent::BackendError {
                class: AuthErrorClass::Other,
                handler_reconnect: false,
            })
        );
    }

    /// Malformed and truncated packets return typed errors — never a
    /// panic, and never payload bytes in the error (Go would panic on the
    /// unterminated auth switch; SES-02-D1).
    #[test]
    fn classifier_rejects_malformed_without_panic() {
        let caps41 = caps(CapabilityFlags::PROTOCOL_41.bits());
        let empty = classify_backend_auth_packet(&[], caps41);
        assert_eq!(
            empty,
            Err(MalformedAuthPacket {
                length: 0,
                reason: "empty payload",
            })
        );
        // Auth switch without a NUL terminator.
        let mut switch = vec![0xfe];
        switch.extend_from_slice(b"secret-plugin-no-nul");
        let error = match classify_backend_auth_packet(&switch, caps41) {
            Err(error) => error,
            Ok(event) => unreachable!("accepted: {event:?}"),
        };
        assert!(!format!("{error:?}").contains("secret-plugin"));
        assert!(!error.to_string().contains("secret-plugin"));
        // Truncated error packets (header only, partial code).
        for truncated in [&[0xff][..], &[0xff, 0x12][..]] {
            assert!(
                classify_backend_auth_packet(truncated, caps41).is_err(),
                "{truncated:?}"
            );
        }
        // Every prefix of a full error packet classifies or rejects —
        // no panic on any cut.
        let mut full = vec![0xff];
        full.extend_from_slice(&1045_u16.to_le_bytes());
        full.extend_from_slice(b"#28000Access denied");
        for cut in 0..=full.len() {
            let _ = classify_backend_auth_packet(&full[..cut], caps41);
        }
    }

    /// Malformed/unexpected sequences are typed errors and change nothing:
    /// client packets during the backend's turn, anything after Finished.
    #[test]
    fn illegal_pairs_are_typed_and_inert() {
        let mut relay = new_relay();
        let before = relay.clone();
        let error = match relay.on_event(AuthEvent::ClientAuthResponse) {
            Err(error) => error,
            Ok(step) => unreachable!("accepted: {step:?}"),
        };
        assert_eq!(error.state, AuthTurn::AwaitingBackend);
        assert_eq!(relay, before, "a rejection changes nothing");

        let _ = step(&mut relay, AuthEvent::BackendOk);
        for event in [
            AuthEvent::BackendOk,
            AuthEvent::ClientAuthResponse,
            AuthEvent::ExtraAuthData,
            AuthEvent::FastAuthSuccess,
        ] {
            assert!(relay.on_event(event).is_err(), "{event:?} after Finished");
        }
    }

    /// The whole event/effect/error surface is secret-free by
    /// construction: no type carries auth bytes, so `Debug` output cannot
    /// leak passwords, tokens, or scrambles.
    #[test]
    fn debug_surface_carries_no_auth_bytes() {
        let secret = "s3cr3t-p4ssw0rd";
        let events = [
            AuthEvent::BackendOk,
            AuthEvent::BackendError {
                class: AuthErrorClass::ProxyProtocolSuspect,
                handler_reconnect: true,
            },
            AuthEvent::AuthSwitchRequest {
                plugin: AuthPluginName::classify(secret.as_bytes()),
            },
            AuthEvent::FastAuthSuccess,
            AuthEvent::ExtraAuthData,
            AuthEvent::ClientAuthResponse,
        ];
        for event in events {
            assert!(!format!("{event:?}").contains(secret));
        }
        let error = AuthRelayError {
            state: AuthTurn::AwaitingClient,
            event: AuthEvent::ClientAuthResponse,
        };
        assert!(!format!("{error:?}").contains(secret));
        assert!(!error.to_string().contains(secret));
        let step = AuthStep {
            effects: vec![AuthEffect::ForwardClientToBackend],
            outcome: Some(AuthOutcome::Failed(FailureKind::AuthenticationFailed)),
        };
        assert!(!format!("{step:?}").contains(secret));
    }
}
