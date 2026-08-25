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

//! SES-00 model tests: exhaustive reachability over the full state × flag ×
//! event space (stronger than sampled property tests — every reachable node
//! is visited), plus table-driven scenario walks.

use std::collections::{BTreeSet, HashSet, VecDeque};

use session_core::fsm::{
    Effects, SessionEffect, SessionEvent, SessionFlags, SessionFsm, SessionState, TRANSITIONS,
};

/// Every event, so exploration and illegal-pair checks cover the whole
/// alphabet. A new variant that is not added here fails the count pin.
const ALL_EVENTS: [SessionEvent; 27] = [
    SessionEvent::ConnectionAccepted,
    SessionEvent::BackendGreetingReceived,
    SessionEvent::ClientSslRequest,
    SessionEvent::TlsActivated,
    SessionEvent::ClientHandshakeResponse,
    SessionEvent::BackendAuthOk,
    SessionEvent::BackendAuthFailed,
    SessionEvent::ClientCommand,
    SessionEvent::ClientCommandQuit,
    SessionEvent::BackendResponsePart,
    SessionEvent::BackendResponseTxnDone,
    SessionEvent::BackendResponseTxnOpen,
    SessionEvent::BackendLocalInfileRequest,
    SessionEvent::ClientInfileChunk,
    SessionEvent::ClientInfileEnd,
    SessionEvent::ControlRedirect,
    SessionEvent::ControlGracefulClose,
    SessionEvent::ControlCloseImmediate,
    SessionEvent::RedirectBackendReady,
    SessionEvent::RedirectBackendFailed,
    SessionEvent::ClientEof,
    SessionEvent::BackendEof,
    SessionEvent::ClientIoError,
    SessionEvent::BackendIoError,
    SessionEvent::HandshakeTimerExpired,
    SessionEvent::DrainTimerExpired,
    SessionEvent::TeardownComplete,
];

/// States that require an authenticated session with an attached owner.
const AUTHENTICATED_STATES: [SessionState; 6] = [
    SessionState::Ready,
    SessionState::Command,
    SessionState::Response,
    SessionState::LocalInfile,
    SessionState::RedirectPending,
    SessionState::Draining,
];

/// Effects that must only run while a backend owner is attached.
const OWNER_REQUIRED_EFFECTS: [SessionEffect; 4] = [
    SessionEffect::ForwardCommandToBackend,
    SessionEffect::ForwardResponseToClient,
    SessionEffect::ForwardInfileChunkToBackend,
    SessionEffect::ForwardInfileEndToBackend,
];

/// Checks ownership accounting for one transition's effect list against the
/// pre- and post-transition flags.
fn check_ownership(pre: SessionFlags, post: SessionFlags, effects: &Effects) {
    for effect in effects {
        match effect {
            SessionEffect::AttachBackend => {
                assert!(
                    !pre.backend_owner && post.backend_owner,
                    "attach requires no current owner and must install one"
                );
            }
            SessionEffect::SwapBackend => {
                assert!(
                    pre.backend_owner && post.backend_owner,
                    "swap requires exactly one owner before and after"
                );
            }
            SessionEffect::ReleaseBackend => {
                assert!(
                    pre.backend_owner && !post.backend_owner,
                    "release requires an owner and must remove it"
                );
            }
            SessionEffect::StartRedirectHandshake => {
                assert!(
                    pre.backend_owner && post.backend_owner,
                    "a redirect candidate never displaces the current owner"
                );
            }
            _ => {}
        }
    }
    let attaches = effects
        .iter()
        .filter(|e| matches!(e, SessionEffect::AttachBackend | SessionEffect::SwapBackend))
        .count();
    assert!(attaches <= 1, "one transition never grants ownership twice");
    for required in OWNER_REQUIRED_EFFECTS {
        if effects.contains(&required) {
            assert!(pre.backend_owner, "{required:?} requires an attached owner");
        }
    }
}

/// Exhaustive reachability: from `Accept`, apply every event at every
/// reachable `(state, flags)` node. Proves the SES-00 acceptance
/// invariants and that [`TRANSITIONS`] equals the machine exactly.
#[test]
fn exhaustive_model_check() {
    let mut queue = VecDeque::from([SessionFsm::new()]);
    let mut visited: HashSet<(SessionState, SessionFlags)> = HashSet::new();
    let mut observed: BTreeSet<(SessionState, SessionEvent, SessionState)> = BTreeSet::new();
    let mut closed_reached = false;

    while let Some(fsm) = queue.pop_front() {
        if !visited.insert((fsm.state(), fsm.flags())) {
            continue;
        }
        closed_reached |= fsm.state() == SessionState::Closed;
        for event in ALL_EVENTS {
            let mut next = fsm.clone();
            match next.on_event(event) {
                Ok(effects) => {
                    assert_ne!(
                        fsm.state(),
                        SessionState::Closed,
                        "no effects may follow Closed"
                    );
                    check_ownership(fsm.flags(), next.flags(), &effects);
                    if AUTHENTICATED_STATES.contains(&next.state()) {
                        assert!(
                            next.flags().authenticated && next.flags().backend_owner,
                            "{:?} is unreachable without authentication and an owner",
                            next.state()
                        );
                    }
                    observed.insert((fsm.state(), event, next.state()));
                    queue.push_back(next);
                }
                Err(error) => {
                    assert_eq!(error.state, fsm.state());
                    assert_eq!(error.event, event);
                    assert_eq!(next.state(), fsm.state(), "a rejection changes nothing");
                    assert_eq!(next.flags(), fsm.flags(), "a rejection changes nothing");
                }
            }
        }
    }

    assert!(closed_reached, "the terminal state must be reachable");

    // The declared table and the observed relation are exactly equal.
    let declared: BTreeSet<(SessionState, SessionEvent, SessionState)> = TRANSITIONS
        .iter()
        .map(|row| (row.from, row.event, row.to))
        .collect();
    assert_eq!(
        declared.len(),
        TRANSITIONS.len(),
        "the transition table must not contain duplicates"
    );
    let undeclared: Vec<_> = observed.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "undeclared transitions: {undeclared:?}"
    );
    let unreachable: Vec<_> = declared.difference(&observed).collect();
    assert!(
        unreachable.is_empty(),
        "unreachable table rows: {unreachable:?}"
    );
}

/// Runs a scenario: applies each event, asserting the resulting state and
/// effects, and returns the machine for further inspection.
fn run(fsm: &mut SessionFsm, steps: &[(SessionEvent, SessionState, &[SessionEffect])]) {
    for (event, expected_state, expected_effects) in steps {
        let effects = match fsm.on_event(*event) {
            Ok(effects) => effects,
            Err(error) => unreachable!("scenario step failed: {error}"),
        };
        assert_eq!(fsm.state(), *expected_state, "after {event:?}");
        assert_eq!(effects.as_slice(), *expected_effects, "after {event:?}");
    }
}

/// The plain lifecycle: handshake, one query, quit.
#[test]
fn plain_lifecycle_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = SessionFsm::new();
    run(
        &mut fsm,
        &[
            (E::ConnectionAccepted, S::Greeting, &[F::DialInitialBackend]),
            (
                E::BackendGreetingReceived,
                S::FrontendHandshake,
                &[F::RelayGreetingToClient],
            ),
            (
                E::ClientSslRequest,
                S::SslRequest,
                &[F::ActivateFrontendTls],
            ),
            (E::TlsActivated, S::FrontendHandshake, &[]),
            (
                E::ClientHandshakeResponse,
                S::BackendHandshake,
                &[F::ForwardHandshakeToBackend],
            ),
            (
                E::BackendAuthOk,
                S::Ready,
                &[F::AttachBackend, F::ForwardAuthResultToClient],
            ),
            (E::ClientCommand, S::Command, &[F::ForwardCommandToBackend]),
            (
                E::BackendResponsePart,
                S::Response,
                &[F::ForwardResponseToClient],
            ),
            (
                E::BackendResponseTxnDone,
                S::Ready,
                &[F::ForwardResponseToClient],
            ),
            (
                E::ClientCommandQuit,
                S::Closing,
                &[
                    F::ReleaseBackend,
                    F::CloseBackend,
                    F::CloseClient,
                    F::ClassifySessionEnd,
                ],
            ),
            (E::TeardownComplete, S::Closed, &[]),
        ],
    );
    assert!(!fsm.flags().backend_owner);
}

/// Reaches `Ready` without TLS, used by the remaining scenarios.
fn authenticated_session() -> SessionFsm {
    use SessionEvent as E;
    let mut fsm = SessionFsm::new();
    for event in [
        E::ConnectionAccepted,
        E::BackendGreetingReceived,
        E::ClientHandshakeResponse,
        E::BackendAuthOk,
    ] {
        match fsm.on_event(event) {
            Ok(_) => {}
            Err(error) => unreachable!("setup failed: {error}"),
        }
    }
    assert_eq!(fsm.state(), SessionState::Ready);
    fsm
}

/// Redirect at an idle boundary: migration succeeds, the held command is
/// replayed, ownership swaps exactly once.
#[test]
fn redirect_success_with_held_command_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = authenticated_session();
    run(
        &mut fsm,
        &[
            (
                E::ControlRedirect,
                S::RedirectPending,
                &[F::StartRedirectHandshake],
            ),
            (
                E::ClientCommand,
                S::RedirectPending,
                &[F::HoldClientCommand],
            ),
            (
                E::RedirectBackendReady,
                S::Ready,
                &[
                    F::SwapBackend,
                    F::NotifyRedirectSucceeded,
                    F::ReplayHeldCommand,
                ],
            ),
        ],
    );
    assert!(fsm.flags().backend_owner);
    assert!(!fsm.flags().redirect_pending);
    assert!(!fsm.flags().held_command);

    // A second in-flight request during migration is a protocol violation.
    let mut migrating = authenticated_session();
    for event in [E::ControlRedirect, E::ClientCommand] {
        match migrating.on_event(event) {
            Ok(_) => {}
            Err(error) => unreachable!("setup failed: {error}"),
        }
    }
    assert!(migrating.on_event(E::ClientCommand).is_err());
}

/// A failed migration keeps the current backend attached (Go parity).
#[test]
fn redirect_failure_keeps_owner_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = authenticated_session();
    run(
        &mut fsm,
        &[
            (
                E::ControlRedirect,
                S::RedirectPending,
                &[F::StartRedirectHandshake],
            ),
            (
                E::RedirectBackendFailed,
                S::Ready,
                &[F::NotifyRedirectFailed],
            ),
        ],
    );
    assert!(fsm.flags().backend_owner);
}

/// Redirect waits for the transaction boundary; graceful close wins over a
/// pending redirect at that boundary (Go `tryGracefulClose`/`tryRedirect`).
#[test]
fn boundary_priority_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = authenticated_session();
    run(
        &mut fsm,
        &[
            // Open a transaction.
            (E::ClientCommand, S::Command, &[F::ForwardCommandToBackend]),
            (
                E::BackendResponseTxnOpen,
                S::Ready,
                &[F::ForwardResponseToClient],
            ),
            // Redirect must wait: no handshake starts inside the txn.
            (E::ControlRedirect, S::Ready, &[]),
            (E::ClientCommand, S::Command, &[F::ForwardCommandToBackend]),
            // Graceful close arrives mid-command; drain timer armed.
            (E::ControlGracefulClose, S::Command, &[F::BeginDrainTimer]),
            // At the boundary the close wins and the redirect is refused.
            (
                E::BackendResponseTxnDone,
                S::Closing,
                &[
                    F::ForwardResponseToClient,
                    F::NotifyRedirectFailed,
                    F::ReleaseBackend,
                    F::CloseBackend,
                    F::CloseClient,
                    F::ClassifySessionEnd,
                ],
            ),
        ],
    );
}

/// Graceful close on an idle session inside a transaction: `Draining`
/// accepts further commands and closes at the boundary or the deadline.
#[test]
fn draining_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = authenticated_session();
    run(
        &mut fsm,
        &[
            (E::ClientCommand, S::Command, &[F::ForwardCommandToBackend]),
            (
                E::BackendResponseTxnOpen,
                S::Ready,
                &[F::ForwardResponseToClient],
            ),
            (E::ControlGracefulClose, S::Draining, &[F::BeginDrainTimer]),
            // A redirect while draining is refused immediately.
            (E::ControlRedirect, S::Draining, &[F::NotifyRedirectFailed]),
            (E::ClientCommand, S::Command, &[F::ForwardCommandToBackend]),
            // The transaction stays open: back to Draining.
            (
                E::BackendResponseTxnOpen,
                S::Draining,
                &[F::ForwardResponseToClient],
            ),
            // The deadline forces the close.
            (
                E::DrainTimerExpired,
                S::Closing,
                &[
                    F::ReleaseBackend,
                    F::CloseBackend,
                    F::CloseClient,
                    F::ClassifySessionEnd,
                ],
            ),
        ],
    );
}

/// `LOCAL INFILE` duplex flow.
#[test]
fn local_infile_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = authenticated_session();
    run(
        &mut fsm,
        &[
            (E::ClientCommand, S::Command, &[F::ForwardCommandToBackend]),
            (
                E::BackendLocalInfileRequest,
                S::LocalInfile,
                &[F::RequestLocalInfileFromClient],
            ),
            (
                E::ClientInfileChunk,
                S::LocalInfile,
                &[F::ForwardInfileChunkToBackend],
            ),
            (
                E::ClientInfileEnd,
                S::Response,
                &[F::ForwardInfileEndToBackend],
            ),
            (
                E::BackendResponseTxnDone,
                S::Ready,
                &[F::ForwardResponseToClient],
            ),
        ],
    );
}

/// Authentication failure relays the result and tears down.
#[test]
fn auth_failure_walk() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = SessionFsm::new();
    run(
        &mut fsm,
        &[
            (E::ConnectionAccepted, S::Greeting, &[F::DialInitialBackend]),
            (
                E::BackendGreetingReceived,
                S::FrontendHandshake,
                &[F::RelayGreetingToClient],
            ),
            (
                E::ClientHandshakeResponse,
                S::BackendHandshake,
                &[F::ForwardHandshakeToBackend],
            ),
            (
                E::BackendAuthFailed,
                S::Closing,
                &[
                    F::ForwardAuthResultToClient,
                    F::CloseBackend,
                    F::CloseClient,
                    F::ClassifySessionEnd,
                ],
            ),
        ],
    );
    assert!(!fsm.flags().authenticated);
}

/// A migration completing while closing reports failure (Go `ErrClosing`),
/// and `Closed` rejects the whole event alphabet with the typed error.
#[test]
fn closing_tolerance_and_closed_rejection() {
    use SessionEffect as F;
    use SessionEvent as E;
    use SessionState as S;
    let mut fsm = authenticated_session();
    run(
        &mut fsm,
        &[
            (
                E::ControlRedirect,
                S::RedirectPending,
                &[F::StartRedirectHandshake],
            ),
            (
                E::ClientEof,
                S::Closing,
                &[
                    F::ReleaseBackend,
                    F::CloseBackend,
                    F::CloseClient,
                    F::ClassifySessionEnd,
                ],
            ),
            // The in-flight migration result arrives late.
            (
                E::RedirectBackendReady,
                S::Closing,
                &[F::NotifyRedirectFailed],
            ),
            // Stray traffic is tolerated without effects.
            (E::BackendResponsePart, S::Closing, &[]),
            (E::TeardownComplete, S::Closed, &[]),
        ],
    );
    for event in ALL_EVENTS {
        let result = fsm.on_event(event);
        match result {
            Err(error) => {
                assert_eq!(error.state, SessionState::Closed);
                assert!(!error.to_string().is_empty());
            }
            Ok(effects) => unreachable!("Closed accepted {event:?} with {effects:?}"),
        }
    }
}
