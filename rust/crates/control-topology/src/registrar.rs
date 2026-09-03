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

//! The async self-registration loop (the I/O half).
//!
//! [`run`] keeps one `TiProxy` instance published under a per-instance etcd
//! lease against a single backend cluster's PD, mirroring the Go
//! `infosync.InfoSyncer` topology loop
//! (`updateTopologyLivenessLoop` / `syncTopology`):
//!
//! * grant a lease with [`TOPOLOGY_SESSION_TTL_SECS`] and keep it alive at a
//!   third of that interval;
//! * `put` both the `info` and `ttl` keys under that lease, and re-`put` them
//!   every [`TOPOLOGY_REFRESH_INTERVAL_SECS`] so a restarted PD re-learns the
//!   record without waiting for the lease to churn;
//! * if the lease is lost, rebuild the session (Go's `session.Done()` arm);
//! * on shutdown, best-effort delete the registration and return.
//!
//! Every etcd call goes through [`control_external::EtcdConnection`], so it is
//! fenced by the process [`control_plane::OwnerToken`] and never commits work
//! for a retired generation. This loop is deliberately NOT gated on
//! control-plane leadership: self-registration is a per-instance duty.
//!
//! A caller that owns several backend clusters runs one [`run`] per cluster
//! (Go keeps one `InfoSyncer` per cluster), each with its own connector but the
//! same [`TopologyInfo`].
//!
//! NOTE: the live loop is exercised by an embedded-etcd integration test in a
//! follow-up, matching how `control-etcd` covers its own lease session; the
//! pure key/value contract is unit-tested here and in [`crate::register`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_external::{EtcdConnectError, EtcdConnection, EtcdConnector, EtcdOperationError};
use control_plane::OwnerToken;
use etcd_client::{DeleteOptions, LeaseKeepAliveStream, LeaseKeeper, PutOptions};
use thiserror::Error;
use tokio::sync::watch;
use tokio::time::{self, MissedTickBehavior};

use crate::register::{
    TIPROXY_TOPOLOGY_PATH, TOPOLOGY_REFRESH_INTERVAL_SECS, TOPOLOGY_SESSION_TTL_SECS, TopologyInfo,
    info_key, ttl_key, ttl_value,
};

/// Lease keepalive cadence: a third of the lease TTL, so two consecutive missed
/// refreshes still leave headroom before expiry.
const KEEPALIVE_INTERVAL_SECS: u64 = 15;
/// Bound on one keepalive response wait, so a hung stream can never wedge the
/// loop (and therefore never wedge a caller joining this task on shutdown).
const KEEPALIVE_RECEIVE_TIMEOUT: Duration = Duration::from_secs(3);
/// Backoff between failed session-establishment attempts. Matches Go
/// `putRetryIntvl`; establishment itself retries until the caller shuts down.
const ESTABLISH_BACKOFF: Duration = Duration::from_secs(1);

/// A terminal failure of the self-registration loop.
///
/// The loop treats transient etcd faults as recoverable (it retries or rebuilds
/// the lease); these variants surface only the non-recoverable outcomes.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegistrarError {
    /// The process owner generation was released; the loop retired without
    /// publishing for a stale generation.
    #[error("registration owner generation was released")]
    OwnerLost,
    /// A bounded etcd failure class that establishment could not get past.
    #[error("registration etcd failure: {0}")]
    Etcd(&'static str),
}

/// Runs self-registration until `shutdown` is set or the owner is lost.
///
/// The `shutdown` channel is the cooperative stop signal: setting it to `true`
/// makes the loop delete its registration (best effort) and return `Ok(())`.
/// `owner` fences every keepalive round so a retired generation stops
/// publishing even while its keepalive stream is otherwise healthy.
///
/// # Errors
///
/// Returns [`RegistrarError::OwnerLost`] if the process owner generation is
/// released while running, or [`RegistrarError::Etcd`] only if a session can
/// never be established before shutdown is observed on a fatal path.
pub async fn run(
    owner: OwnerToken,
    connector: EtcdConnector,
    info: TopologyInfo,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RegistrarError> {
    if *shutdown.borrow_and_update() {
        return Ok(());
    }
    loop {
        // Establish a session, retrying until it succeeds or shutdown wins.
        let mut session = loop {
            match Session::establish(&owner, &connector, &info).await {
                Ok(session) => break session,
                Err(RegistrarError::OwnerLost) => return Ok(()),
                Err(RegistrarError::Etcd(_)) => {
                    if wait_or_shutdown(&mut shutdown, ESTABLISH_BACKOFF).await {
                        return Ok(());
                    }
                }
            }
        };

        // Serve the established session until the lease is lost or shutdown.
        let mut refresh = time::interval(Duration::from_secs(TOPOLOGY_REFRESH_INTERVAL_SECS));
        refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first `interval` tick fires immediately; the initial publish
        // already happened in `establish`, so consume it.
        refresh.tick().await;
        let mut keepalive = time::interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;

        let rebuild = loop {
            tokio::select! {
                _ = refresh.tick() => {
                    // A refused refresh is non-fatal (Go logs and continues);
                    // an owner loss is terminal.
                    if let Err(RegistrarError::OwnerLost) = session.publish(&info).await {
                        return Ok(());
                    }
                }
                _ = keepalive.tick() => {
                    match session.keep_alive().await {
                        Ok(true) => {}
                        Ok(false) | Err(RegistrarError::Etcd(_)) => break true,
                        Err(RegistrarError::OwnerLost) => return Ok(()),
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        session.deregister().await;
                        return Ok(());
                    }
                }
            }
        };
        if !rebuild {
            return Ok(());
        }
    }
}

/// The two key/value writes that publish one registration heartbeat.
///
/// Splitting this out keeps the exact published bytes unit-testable without an
/// etcd server; the loop only supplies the current clock reading.
struct RegistrationWrite {
    info_key: String,
    info_value: Vec<u8>,
    ttl_key: String,
    ttl_value: Vec<u8>,
}

impl RegistrationWrite {
    fn build(info: &TopologyInfo, now_unix_nanos: i128) -> Result<Self, serde_json::Error> {
        let addr = info.registration_addr();
        Ok(Self {
            info_key: info_key(&addr),
            info_value: info.to_json()?,
            ttl_key: ttl_key(&addr),
            ttl_value: ttl_value(now_unix_nanos).into_bytes(),
        })
    }
}

/// An established registration lease and its keepalive stream.
struct Session {
    owner: OwnerToken,
    connection: EtcdConnection,
    lease_id: i64,
    keeper: LeaseKeeper,
    stream: LeaseKeepAliveStream,
}

impl Session {
    /// Connects, grants a lease, opens its keepalive stream, and performs the
    /// initial publish.
    async fn establish(
        owner: &OwnerToken,
        connector: &EtcdConnector,
        info: &TopologyInfo,
    ) -> Result<Self, RegistrarError> {
        let mut connection = connector
            .connect()
            .await
            .map_err(|error| map_connect_error(&error))?;
        let grant = connection
            .execute(|client| Box::pin(client.lease_grant(TOPOLOGY_SESSION_TTL_SECS, None)))
            .await
            .map_err(|error| map_operation_error(&error))?;
        let lease_id = grant.id();
        if lease_id == 0 || grant.ttl() <= 0 {
            return Err(RegistrarError::Etcd("invalid_lease_grant"));
        }
        let (keeper, stream) = connection
            .execute(move |client| Box::pin(client.lease_keep_alive(lease_id)))
            .await
            .map_err(|error| map_operation_error(&error))?;
        let mut session = Self {
            owner: owner.clone(),
            connection,
            lease_id,
            keeper,
            stream,
        };
        session.publish(info).await?;
        Ok(session)
    }

    /// Puts (or re-puts) the `info` and `ttl` keys under the current lease.
    async fn publish(&mut self, info: &TopologyInfo) -> Result<(), RegistrarError> {
        let write = RegistrationWrite::build(info, now_unix_nanos())
            .map_err(|_| RegistrarError::Etcd("encode_info"))?;
        let lease_id = self.lease_id;
        let RegistrationWrite {
            info_key,
            info_value,
            ttl_key,
            ttl_value,
        } = write;
        self.connection
            .execute(move |client| {
                Box::pin(client.put(
                    info_key,
                    info_value,
                    Some(PutOptions::new().with_lease(lease_id)),
                ))
            })
            .await
            .map_err(|error| map_operation_error(&error))?;
        self.connection
            .execute(move |client| {
                Box::pin(client.put(
                    ttl_key,
                    ttl_value,
                    Some(PutOptions::new().with_lease(lease_id)),
                ))
            })
            .await
            .map_err(|error| map_operation_error(&error))?;
        Ok(())
    }

    /// Drives one lease keepalive round. `Ok(false)` means the lease is gone and
    /// the session must be rebuilt.
    ///
    /// The owner generation is checked before and after the round so a retired
    /// generation stops renewing even while its stream is healthy, and the
    /// response wait is bounded so a hung stream can never wedge the loop.
    async fn keep_alive(&mut self) -> Result<bool, RegistrarError> {
        if !self.owner.is_current() {
            return Err(RegistrarError::OwnerLost);
        }
        self.keeper
            .keep_alive()
            .await
            .map_err(|_| RegistrarError::Etcd("keep_alive_send"))?;
        let response = time::timeout(KEEPALIVE_RECEIVE_TIMEOUT, self.stream.message())
            .await
            .map_err(|_| RegistrarError::Etcd("keep_alive_timeout"))?
            .map_err(|_| RegistrarError::Etcd("keep_alive_receive"))?;
        if !self.owner.is_current() {
            return Err(RegistrarError::OwnerLost);
        }
        match response {
            Some(response) if response.id() == self.lease_id && response.ttl() > 0 => Ok(true),
            _ => Ok(false),
        }
    }

    /// Best-effort de-registration on shutdown.
    ///
    /// Mirrors Go `removeTopology`, which deletes the whole `/topology/tiproxy`
    /// prefix (not only this instance's keys) and tolerates any error, leaving
    /// the lease to expire. Preserved verbatim for Go differential parity; a
    /// narrower per-address delete is a deliberate future decision, not a
    /// defensive change to make here.
    async fn deregister(&mut self) {
        let _ = self
            .connection
            .execute(|client| {
                Box::pin(client.delete(
                    TIPROXY_TOPOLOGY_PATH,
                    Some(DeleteOptions::new().with_prefix()),
                ))
            })
            .await;
    }
}

/// Current wall-clock time in unix nanoseconds, saturating a pre-epoch clock to
/// zero so a misconfigured host never panics the loop.
fn now_unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i128::try_from(elapsed.as_nanos()).ok())
        .unwrap_or(0)
}

/// Sleeps for `delay`, returning `true` if a shutdown was signalled meanwhile.
async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        () = time::sleep(delay) => *shutdown.borrow(),
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

fn map_connect_error(error: &EtcdConnectError) -> RegistrarError {
    match error {
        EtcdConnectError::StaleOwner => RegistrarError::OwnerLost,
        EtcdConnectError::Dependency(_) => RegistrarError::Etcd("connect"),
    }
}

fn map_operation_error(error: &EtcdOperationError) -> RegistrarError {
    match error {
        EtcdOperationError::StaleOwner => RegistrarError::OwnerLost,
        EtcdOperationError::Dependency(_) => RegistrarError::Etcd("operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::RegistrationWrite;
    use crate::register::TopologyInfo;

    #[test]
    fn registration_write_matches_go_key_value_contract() {
        let info = TopologyInfo::new(
            "10.0.0.7",
            4000,
            10080,
            "v8",
            "hash",
            "/deploy",
            1_700_000_000,
        );
        let write = RegistrationWrite::build(&info, 1_700_000_000_123_456_789_i128)
            .unwrap_or_else(|_| unreachable!("fixed struct serializes"));
        assert_eq!(write.info_key, "/topology/tiproxy/10.0.0.7:4000/info");
        assert_eq!(write.ttl_key, "/topology/tiproxy/10.0.0.7:4000/ttl");
        assert_eq!(write.ttl_value, b"1700000000123456789");
        let info_json = String::from_utf8(write.info_value)
            .unwrap_or_else(|_| unreachable!("serde emits utf8"));
        assert_eq!(
            info_json,
            r#"{"version":"v8","git_hash":"hash","ip":"10.0.0.7","port":"4000","status_port":"10080","deploy_path":"/deploy","start_timestamp":1700000000}"#
        );
    }

    #[test]
    fn ipv6_registration_write_brackets_the_address_in_keys() {
        let info = TopologyInfo::new("::1", 4000, 10080, "v", "h", "/d", 1);
        let write = RegistrationWrite::build(&info, 1)
            .unwrap_or_else(|_| unreachable!("fixed struct serializes"));
        assert_eq!(write.info_key, "/topology/tiproxy/[::1]:4000/info");
        assert_eq!(write.ttl_key, "/topology/tiproxy/[::1]:4000/ttl");
    }
}
