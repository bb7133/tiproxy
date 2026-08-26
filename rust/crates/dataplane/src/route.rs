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

//! Route client, dial retry, and assignment lifecycle (DPL-02).
//!
//! Rust never duplicates balance policy: backend choice stays on the Go
//! side behind the control protocol's route messages. The engine here
//! implements the **consumer** half exactly as `pkg/controlbridge`'s
//! `RouterAdapter` expects it:
//!
//! - One [`RouteChannel::request_route`] opens the exchange; the adapter
//!   then pushes one `RouteAssignment` immediately and **another after
//!   every failed `RouteResult`** (`handleRouteResult` calls
//!   `nextAssignmentLocked` on `connected=false`). The engine therefore
//!   never re-sends `RouteRequest` for retries — it reports and awaits.
//! - Every assignment the adapter hands out reserves router score until
//!   exactly one terminal `RouteResult` (or close/reconcile) retires it.
//!   The engine enforces **exactly one report per assignment id**
//!   structurally: an assignment is consumed by the one report the
//!   engine makes for it, including on budget exhaustion, terminal
//!   channel failure, and handshake-driven re-selection.
//! - A `RouteAssignment` whose `code` is not OK is the adapter's
//!   terminal answer (`NO_BACKEND` after enumerating candidates, or an
//!   internal error); it carries no backend and needs no result.
//!
//! Dial parity with Go `BackendConnManager.getBackendIO`:
//! - a **per-dial** timeout bounds each attempt (`DialTimeout`, 1s);
//! - a **total** budget bounds the whole acquisition
//!   (`ConnectTimeout` via `backoff.MaxElapsedTime`);
//! - failed attempts back off exponentially: initial 100ms, multiplier
//!   2, randomization factor 0.5, capped at the max interval. The jitter
//!   source is **injected** ([`DialSchedule::jitter`]) so production can
//!   seed it per connection while tests fix it — the crate has no
//!   global randomness.
//!
//! Cluster-aware dialing stays a seam: [`BackendDialer::dial`] receives
//! the assignment's `cluster_name` (Go `BackendDialer.DialContext`
//! carries it for serverless multi-cluster DNS); resolver logic belongs
//! to the namespace/multi-cluster integration (DPL-07), not here.
//!
//! No `MySQL` payload bytes appear anywhere in this module: route
//! messages carry identifiers and addresses only.

use std::time::Duration;

use control_proto::v1::{ErrorCode, ErrorSource, RouteAssignment, RouteResult};
use tokio::time::{Instant, sleep, timeout, timeout_at};

/// How one dial attempt failed. Payload-free by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailure {
    /// The transport-level connect failed (refused, unreachable, reset).
    Connect,
    /// The per-dial deadline elapsed before the connect finished.
    Timeout,
    /// The backend accepted TCP but its handshake failed before
    /// authentication (TLS or protocol failure attributable to the
    /// backend).
    Handshake,
}

impl DialFailure {
    const fn error_source(self) -> ErrorSource {
        match self {
            Self::Connect | Self::Timeout | Self::Handshake => ErrorSource::BackendNetwork,
        }
    }
}

/// Classified route-channel failure: the control conversation itself
/// broke (not a candidate failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteChannelError {
    /// The control channel closed or the send/receive failed.
    ControlLost,
    /// The adapter answered with a protocol-level rejection that is not
    /// an assignment (identity mismatch, not eligible, reconciliation
    /// required).
    Rejected,
}

/// The adapter's terminal answers and local terminal outcomes for one
/// acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireError {
    /// The adapter enumerated all candidates: `NO_BACKEND`.
    NoBackend {
        /// Bounded adapter-provided detail.
        detail: String,
    },
    /// The adapter answered a terminal non-OK assignment other than
    /// `NO_BACKEND` (internal routing failure).
    Routing {
        /// The adapter's error code.
        code: ErrorCode,
        /// Bounded adapter-provided detail.
        detail: String,
    },
    /// The total acquisition budget elapsed; the last candidate failure
    /// is attached.
    BudgetExhausted {
        /// The failure that consumed the final attempt, if any dial ran.
        last_failure: Option<DialFailure>,
    },
    /// The control conversation broke mid-acquisition.
    Channel(RouteChannelError),
}

/// The engine's view of the control-plane route conversation. The
/// transport (control-proto client) implements this; tests fake it.
pub trait RouteChannel: Send {
    /// Sends the initial `RouteRequest` for this connection. Called
    /// exactly once per acquisition sequence.
    fn request_route(
        &mut self,
        excluded_backend_ids: Vec<String>,
    ) -> impl Future<Output = Result<(), RouteChannelError>> + Send;

    /// Awaits the next pushed `RouteAssignment`. The adapter pushes one
    /// after `request_route` and one after every failed result.
    fn next_assignment(
        &mut self,
    ) -> impl Future<Output = Result<RouteAssignment, RouteChannelError>> + Send;

    /// Reports the terminal outcome for one assignment. Exactly one
    /// report per assignment id.
    fn report_result(
        &mut self,
        result: RouteResult,
    ) -> impl Future<Output = Result<(), RouteChannelError>> + Send;
}

/// Dials one backend candidate. `cluster_name` travels with every dial
/// (Go `BackendDialer.DialContext`); implementations that ignore it get
/// plain TCP semantics. Resolver logic is deliberately out of scope
/// (DPL-07).
pub trait BackendDialer: Send {
    /// The established, not-yet-authenticated backend connection.
    type Conn: Send;

    /// Attempts one connect. The engine bounds this call with the
    /// per-dial timeout; implementations need no internal deadline.
    fn dial(
        &mut self,
        address: &str,
        cluster_name: &str,
    ) -> impl Future<Output = Result<Self::Conn, DialFailure>> + Send;
}

/// Dial budgets and backoff shape (Go `getBackendIO` /
/// `newExponentialBackOff` parity).
#[derive(Debug, Clone, Copy)]
pub struct DialSchedule {
    /// Per-attempt bound (Go `DialTimeout`, default 1s).
    pub per_dial: Duration,
    /// Total acquisition budget (Go `ConnectTimeout` as
    /// `MaxElapsedTime`).
    pub total: Duration,
    /// First backoff interval (Go 100ms).
    pub initial_interval: Duration,
    /// Backoff multiplier (Go 2.0).
    pub multiplier: f64,
    /// Randomization factor (Go 0.5): each delay is
    /// `interval * (1 + factor * (2*jitter - 1))` with `jitter ∈ [0,1]`.
    pub randomization: f64,
    /// Interval cap (Go `MaxInterval`).
    pub max_interval: Duration,
    /// Injected jitter source returning values in `[0, 1]`; the attempt
    /// index makes deterministic schedules expressible. Production seeds
    /// this per connection; tests pin it.
    pub jitter: fn(attempt: u32) -> f64,
}

/// Centered jitter: every delay uses exactly the nominal interval.
const fn centered_jitter(_attempt: u32) -> f64 {
    0.5
}

impl Default for DialSchedule {
    fn default() -> Self {
        Self {
            per_dial: Duration::from_secs(1),
            total: Duration::from_secs(15),
            initial_interval: Duration::from_millis(100),
            multiplier: 2.0,
            randomization: 0.5,
            max_interval: Duration::from_secs(2),
            jitter: centered_jitter,
        }
    }
}

impl DialSchedule {
    /// The backoff delay before attempt `attempt` (attempt 0 dials
    /// immediately).
    fn delay_before(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let exponent = attempt.saturating_sub(1);
        let nominal = self.initial_interval.as_secs_f64().mul_add(
            self.multiplier
                .powi(i32::try_from(exponent).unwrap_or(i32::MAX)),
            0.0,
        );
        let nominal = nominal.min(self.max_interval.as_secs_f64());
        let jitter = (self.jitter)(attempt).clamp(0.0, 1.0);
        let factor = self.randomization.mul_add(2.0 * jitter - 1.0, 1.0);
        Duration::from_secs_f64((nominal * factor).max(0.0))
    }
}

/// Backend metadata surfaced with an established connection; mirrors the
/// assignment fields the Go router tracks per backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInfo {
    /// Stable backend id (router accounting key).
    pub backend_id: String,
    /// The dialed address.
    pub address: String,
    /// Owning cluster (serverless multi-cluster).
    pub cluster_name: String,
    /// Keyspace label.
    pub keyspace: String,
    /// Router-reported health at assignment time.
    pub healthy: bool,
    /// Whether the backend is local to the proxy's zone.
    pub local: bool,
}

impl BackendInfo {
    fn from_assignment(assignment: &RouteAssignment) -> Self {
        Self {
            backend_id: assignment.backend_id.clone(),
            address: assignment.backend_address.clone(),
            cluster_name: assignment.cluster_name.clone(),
            keyspace: assignment.keyspace.clone(),
            healthy: assignment.healthy,
            local: assignment.local,
        }
    }
}

/// An established (pre-authentication) backend plus its metadata.
#[derive(Debug)]
pub struct AcquiredBackend<C> {
    /// The dialed connection.
    pub conn: C,
    /// Router metadata for the chosen backend.
    pub backend: BackendInfo,
    /// The assignment id whose successful result reserved this backend;
    /// later close/redirect accounting keys on it.
    pub assignment_id: String,
    /// Dial attempts spent (including the successful one).
    pub attempts: u32,
}

/// Acquisition accounting for logs/metrics (payload-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AcquireStats {
    /// Assignments received (including a terminal non-OK one).
    pub assignments: u32,
    /// Dial attempts started.
    pub dials: u32,
    /// Results reported (must equal OK assignments consumed).
    pub results_reported: u32,
}

/// The route/dial engine for one connection: drives request →
/// assignment → dial → result cycles under the budgets, reporting every
/// assignment's outcome exactly once.
pub struct RouteEngine<Ch, D> {
    channel: Ch,
    dialer: D,
    schedule: DialSchedule,
    connection_id: u64,
    stats: AcquireStats,
}

impl<Ch: RouteChannel, D: BackendDialer> RouteEngine<Ch, D> {
    /// Builds the engine for one connection.
    pub const fn new(channel: Ch, dialer: D, schedule: DialSchedule, connection_id: u64) -> Self {
        Self {
            channel,
            dialer,
            schedule,
            connection_id,
            stats: AcquireStats {
                assignments: 0,
                dials: 0,
                results_reported: 0,
            },
        }
    }

    /// Acquisition accounting so far.
    #[must_use]
    pub const fn stats(&self) -> AcquireStats {
        self.stats
    }

    /// Releases the channel and dialer (accounting inspection, reuse).
    #[must_use]
    pub fn into_parts(self) -> (Ch, D) {
        (self.channel, self.dialer)
    }

    /// Acquires a backend: sends the route request and runs the
    /// assignment/dial/result loop under the per-dial and total budgets.
    /// Every OK assignment received is retired with exactly one result,
    /// including on the failure paths.
    ///
    /// # Errors
    ///
    /// [`AcquireError::NoBackend`]/[`AcquireError::Routing`] relay the
    /// adapter's terminal assignment; [`AcquireError::BudgetExhausted`]
    /// reports the total budget elapsing; [`AcquireError::Channel`]
    /// reports the control conversation breaking.
    pub async fn acquire(
        &mut self,
        excluded_backend_ids: Vec<String>,
    ) -> Result<AcquiredBackend<D::Conn>, AcquireError> {
        let total_deadline = Instant::now() + self.schedule.total;
        self.channel
            .request_route(excluded_backend_ids)
            .await
            .map_err(AcquireError::Channel)?;
        self.assignment_loop(total_deadline).await
    }

    /// Continues acquisition after a backend-handshake failure that the
    /// Go handler decided to retry: the adapter (having processed the
    /// handshake result) pushes the next assignment; the same budgets
    /// apply to the continuation.
    ///
    /// # Errors
    ///
    /// Same taxonomy as [`Self::acquire`].
    pub async fn reacquire_after_handshake(
        &mut self,
    ) -> Result<AcquiredBackend<D::Conn>, AcquireError> {
        let total_deadline = Instant::now() + self.schedule.total;
        self.assignment_loop(total_deadline).await
    }

    async fn assignment_loop(
        &mut self,
        total_deadline: Instant,
    ) -> Result<AcquiredBackend<D::Conn>, AcquireError> {
        let mut attempt: u32 = 0;
        loop {
            let assignment = match timeout_at(total_deadline, self.channel.next_assignment()).await
            {
                Ok(Ok(assignment)) => assignment,
                Ok(Err(error)) => return Err(AcquireError::Channel(error)),
                Err(_) => {
                    return Err(AcquireError::BudgetExhausted { last_failure: None });
                }
            };
            self.stats.assignments = self.stats.assignments.saturating_add(1);
            match assignment.code() {
                ErrorCode::Ok | ErrorCode::Unspecified => {}
                ErrorCode::NoBackend => {
                    return Err(AcquireError::NoBackend {
                        detail: assignment.detail,
                    });
                }
                code => {
                    return Err(AcquireError::Routing {
                        code,
                        detail: assignment.detail,
                    });
                }
            }

            // Backoff before this attempt (the first dials immediately).
            let delay = self.schedule.delay_before(attempt);
            if Instant::now() + delay >= total_deadline {
                // The budget cannot fit another attempt: retire this
                // assignment and stop.
                self.report(&assignment, None).await?;
                return Err(AcquireError::BudgetExhausted { last_failure: None });
            }
            if !delay.is_zero() {
                sleep(delay).await;
            }

            self.stats.dials = self.stats.dials.saturating_add(1);
            attempt = attempt.saturating_add(1);
            let outcome = match timeout(
                self.schedule.per_dial,
                self.dialer
                    .dial(&assignment.backend_address, &assignment.cluster_name),
            )
            .await
            {
                Ok(Ok(conn)) => Ok(conn),
                Ok(Err(failure)) => Err(failure),
                Err(_) => Err(DialFailure::Timeout),
            };

            match outcome {
                Ok(conn) => {
                    self.report(&assignment, Some(Ok(()))).await?;
                    return Ok(AcquiredBackend {
                        conn,
                        backend: BackendInfo::from_assignment(&assignment),
                        assignment_id: assignment.assignment_id,
                        attempts: attempt,
                    });
                }
                Err(failure) => {
                    self.report(&assignment, Some(Err(failure))).await?;
                    if Instant::now() >= total_deadline {
                        return Err(AcquireError::BudgetExhausted {
                            last_failure: Some(failure),
                        });
                    }
                    // The adapter pushes the next assignment after a
                    // failed result; loop to await it.
                }
            }
        }
    }

    /// Retires one assignment with exactly one `RouteResult`.
    ///
    /// `outcome`: `Some(Ok(()))` connected; `Some(Err(f))` dial failure;
    /// `None` not attempted (budget exhausted before dialing).
    async fn report(
        &mut self,
        assignment: &RouteAssignment,
        outcome: Option<Result<(), DialFailure>>,
    ) -> Result<(), AcquireError> {
        let result = match outcome {
            Some(Ok(())) => RouteResult {
                connection_id: self.connection_id,
                assignment_id: assignment.assignment_id.clone(),
                connected: true,
                error_source: ErrorSource::Unspecified.into(),
                code: ErrorCode::Ok.into(),
                detail: String::new(),
            },
            Some(Err(failure)) => RouteResult {
                connection_id: self.connection_id,
                assignment_id: assignment.assignment_id.clone(),
                connected: false,
                error_source: failure.error_source().into(),
                code: ErrorCode::BackendDialFailed.into(),
                detail: String::new(),
            },
            None => RouteResult {
                connection_id: self.connection_id,
                assignment_id: assignment.assignment_id.clone(),
                connected: false,
                error_source: ErrorSource::Proxy.into(),
                code: ErrorCode::BackendDialFailed.into(),
                detail: String::new(),
            },
        };
        self.stats.results_reported = self.stats.results_reported.saturating_add(1);
        self.channel
            .report_result(result)
            .await
            .map_err(AcquireError::Channel)
    }
}
