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

use std::time::Duration;

use control_external::{
    EtcdClientConfig, EtcdConnectError, EtcdConnection, EtcdConnector, EtcdOperationError,
};
use control_plane::OwnerToken;
use etcd_client::{
    Compare, CompareOp, EventType, GetOptions, LeaderKey, LeaseKeepAliveStream, LeaseKeeper,
    PutOptions, ResignOptions, SortOrder, SortTarget, Txn, TxnOp, TxnOpResponse, WatchOptions,
    WatchStream,
};
use thiserror::Error;
use tokio::sync::watch;

use crate::ElectionConfig;

const MAX_TXN_KEY_BYTES: usize = 2_048;
const MAX_TXN_VALUE_BYTES: usize = 64 * 1_024;

/// Distributed ownership phase for one election member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElectionState {
    /// A lease exists and the member is waiting to acquire leadership.
    Campaigning,
    /// The member's exact lease and creation revision own the election key.
    Leader,
    /// The last-known owner is retained while etcd reachability is ambiguous.
    Uncertain,
    /// A definitive fence proved that this member no longer owns the election.
    Retired,
    /// Explicit shutdown completed locally.
    Stopped,
}

impl ElectionState {
    /// Returns the stable observation spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Campaigning => "campaigning",
            Self::Leader => "leader",
            Self::Uncertain => "uncertain",
            Self::Retired => "retired",
            Self::Stopped => "stopped",
        }
    }
}

/// Definitive reason why local owner work must stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementReason {
    /// Etcd proved that the session lease no longer exists.
    LeaseNotFound,
    /// Etcd proved that a different key, lease, revision, or value is leader.
    OwnerChanged,
    /// The containing Rust process-owner generation was released.
    ProcessOwnerLost,
    /// The caller explicitly stopped this session.
    Shutdown,
}

impl RetirementReason {
    /// Returns the stable observation spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseNotFound => "lease_not_found",
            Self::OwnerChanged => "owner_changed",
            Self::ProcessOwnerLost => "process_owner_lost",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Payload-free public projection of the session/election state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectionSnapshot {
    /// Current ownership phase.
    pub state: ElectionState,
    /// Stable configured member identity.
    pub member_id: Vec<u8>,
    /// Current etcd lease, or zero before a lease was granted.
    pub lease_id: i64,
    /// Creation revision fencing the elected leader key.
    pub session_revision: i64,
    /// Highest etcd header or event revision observed by this member.
    pub observed_revision: i64,
    /// Number of transport failures and explicit recovery attempts.
    pub retry_count: u64,
    /// Number of canceled stale watches recovered through a fresh leader read.
    pub compaction_recoveries: u64,
    /// Definitive retirement reason, if one has been observed.
    pub retirement_reason: Option<RetirementReason>,
}

impl ElectionSnapshot {
    /// Returns whether owner-only effects may be committed now.
    #[must_use]
    pub const fn may_commit_owner_work(&self) -> bool {
        matches!(self.state, ElectionState::Leader)
    }

    /// Returns whether this member still retains last-known local ownership.
    #[must_use]
    pub const fn retains_local_ownership(&self) -> bool {
        matches!(self.state, ElectionState::Leader | ElectionState::Uncertain)
    }
}

/// Result of verifying an uncertain session against etcd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The exact lease, owner value, and creation revision remain current.
    Restored,
    /// A definitive lease or leader fence retired the member.
    Retired(RetirementReason),
}

/// Semantic outcome of consuming one watch response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchOutcome {
    /// A progress response advanced the watch revision.
    Progress,
    /// A non-terminal put event was observed.
    Event,
    /// A compacted start revision was relisted and resumed safely.
    CompactionRecovered,
    /// A definitive leader change retired the member.
    Retired(RetirementReason),
}

/// Stateful etcd election failure.
#[derive(Debug, Error)]
pub enum ElectionError {
    /// The containing process owner is no longer current.
    #[error("stale control owner")]
    StaleOwner,
    /// Initial or reconnecting etcd transport construction failed.
    #[error("etcd election connection failed")]
    Connect(#[source] EtcdConnectError),
    /// One semantic etcd operation failed while the process owner remained current.
    #[error("etcd election {operation} failed")]
    Operation {
        /// Stable operation class.
        operation: &'static str,
        /// Underlying typed operation failure.
        #[source]
        source: EtcdOperationError,
    },
    /// An escaped keepalive or watch stream failed.
    #[error("etcd election {operation} stream failed")]
    Stream {
        /// Stable operation class.
        operation: &'static str,
        /// Underlying etcd-client stream failure.
        #[source]
        source: etcd_client::Error,
    },
    /// A bounded stream response did not arrive before the request timeout.
    #[error("etcd election {operation} timed out")]
    Timeout {
        /// Stable operation class.
        operation: &'static str,
    },
    /// Etcd returned a structurally incomplete or inconsistent success response.
    #[error("invalid etcd election response: {class}")]
    InvalidResponse {
        /// Payload-free response classification.
        class: &'static str,
    },
    /// The requested operation requires confirmed current leadership.
    #[error("owner-only operation requires confirmed leadership")]
    NotLeader,
    /// A caller-provided transaction key or value exceeded its public bound.
    #[error("invalid owner transaction input")]
    InvalidTransactionInput,
    /// A watch was canceled without a compaction revision.
    #[error("etcd election watch was canceled")]
    WatchCanceled,
}

/// One in-process etcd session and election owner.
///
/// The object deliberately separates `Leader` from `Uncertain`: callers may
/// keep already-established local service during a transient control outage,
/// but new owner-only writes are accepted only in `Leader`.  Recovery verifies
/// the exact lease, value, and creation revision before returning to `Leader`.
pub struct ElectionSession {
    owner: OwnerToken,
    connector: EtcdConnector,
    config: ElectionConfig,
    request_timeout: Duration,
    connection: EtcdConnection,
    lease_keeper: Option<LeaseKeeper>,
    keep_alive_stream: Option<LeaseKeepAliveStream>,
    watch_stream: Option<WatchStream>,
    leader_key: Option<LeaderKey>,
    next_watch_revision: i64,
    snapshot_tx: watch::Sender<ElectionSnapshot>,
}

impl ElectionSession {
    /// Connects, grants a lease, campaigns, writes the fenced ephemeral session
    /// key, and installs the first revisioned watch.
    ///
    /// # Errors
    ///
    /// Returns a typed stale-owner, dependency, timeout, or malformed-response
    /// failure. The per-request timeout must be shorter than the session TTL,
    /// leaving time for the bounded campaign keepalive path. A successful
    /// return always has confirmed `Leader` state.
    pub async fn campaign(
        owner: OwnerToken,
        client_config: EtcdClientConfig,
        config: ElectionConfig,
    ) -> Result<Self, ElectionError> {
        if !owner.is_current() {
            return Err(ElectionError::StaleOwner);
        }
        if client_config.request_timeout()
            >= Duration::from_secs(config.session_ttl_seconds().try_into().unwrap_or(u64::MAX))
        {
            return Err(ElectionError::InvalidResponse {
                class: "request_timeout_not_below_session_ttl",
            });
        }
        let connector = EtcdConnector::new(owner.clone(), client_config.clone());
        let mut connection = connector.connect().await.map_err(map_connect_error)?;
        let ttl = config.session_ttl_seconds();
        let grant = connection
            .execute(move |client| Box::pin(client.lease_grant(ttl, None)))
            .await
            .map_err(|source| map_operation_error("lease_grant", source))?;
        let lease_id = grant.id();
        if lease_id == 0 || grant.ttl() <= 0 {
            return Err(ElectionError::InvalidResponse {
                class: "invalid_lease_grant",
            });
        }
        let grant_revision = revision(grant.header())?;
        let (mut lease_keeper, mut keep_alive_stream) = connection
            .execute(move |client| Box::pin(client.lease_keep_alive(lease_id)))
            .await
            .map_err(|source| map_operation_error("lease_keep_alive", source))?;
        let keep_alive = send_keep_alive(
            &owner,
            &mut lease_keeper,
            &mut keep_alive_stream,
            client_config.request_timeout(),
        )
        .await?;
        verify_keep_alive(&keep_alive, lease_id)?;

        let election_name = config.election_name().to_vec();
        let member_id = config.member_id().to_vec();
        let (leader_key, campaign_revision) = {
            let mut campaign_io = CampaignIo {
                owner: &owner,
                connection: &mut connection,
                lease_keeper: &mut lease_keeper,
                keep_alive_stream: &mut keep_alive_stream,
                lease_id,
                heartbeat_interval: campaign_heartbeat_interval(config.session_ttl_seconds()),
                request_timeout: client_config.request_timeout(),
            };
            campaign_candidate(&mut campaign_io, &election_name, &member_id).await?
        };

        let snapshot = ElectionSnapshot {
            state: ElectionState::Campaigning,
            member_id: config.member_id().to_vec(),
            lease_id,
            session_revision: leader_key.rev(),
            observed_revision: grant_revision.max(campaign_revision),
            retry_count: 0,
            compaction_recoveries: 0,
            retirement_reason: None,
        };
        let (snapshot_tx, _) = watch::channel(snapshot);
        let mut session = Self {
            owner,
            connector,
            config,
            request_timeout: client_config.request_timeout(),
            connection,
            lease_keeper: Some(lease_keeper),
            keep_alive_stream: Some(keep_alive_stream),
            watch_stream: None,
            leader_key: Some(leader_key),
            next_watch_revision: campaign_revision.saturating_add(1),
            snapshot_tx,
        };
        session.attach_ephemeral_session_key().await?;
        let next_revision = session.snapshot().observed_revision.saturating_add(1);
        session.start_watch(next_revision).await?;
        session.ensure_process_owner()?;
        session.update_snapshot(|snapshot| snapshot.state = ElectionState::Leader);
        Ok(session)
    }

    /// Returns the current payload-free state projection.
    #[must_use]
    pub fn snapshot(&self) -> ElectionSnapshot {
        self.snapshot_tx.borrow().clone()
    }

    /// Subscribes to state transitions for later owner-only control modules.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ElectionSnapshot> {
        self.snapshot_tx.subscribe()
    }

    /// Sends and receives one lease keepalive.
    ///
    /// A transport failure enters `Uncertain` without retiring the last-known
    /// owner.  A zero TTL is a definitive lease-loss fence.
    ///
    /// # Errors
    ///
    /// Returns a typed stale-owner, stream, timeout, or malformed-response
    /// failure.
    pub async fn keep_alive(&mut self) -> Result<RecoveryOutcome, ElectionError> {
        self.ensure_process_owner()?;
        if let Some(reason) = self.snapshot().retirement_reason {
            return Ok(RecoveryOutcome::Retired(reason));
        }
        let mut keeper = self
            .lease_keeper
            .take()
            .ok_or(ElectionError::InvalidResponse {
                class: "missing_lease_keeper",
            })?;
        let mut stream = self
            .keep_alive_stream
            .take()
            .ok_or(ElectionError::InvalidResponse {
                class: "missing_keep_alive_stream",
            })?;
        let result =
            send_keep_alive(&self.owner, &mut keeper, &mut stream, self.request_timeout).await;
        self.lease_keeper = Some(keeper);
        self.keep_alive_stream = Some(stream);
        match result {
            Ok(response) if response.ttl() > 0 && response.id() == self.snapshot().lease_id => {
                if let Some(header) = response.header() {
                    self.advance_revision(header.revision());
                }
                Ok(RecoveryOutcome::Restored)
            }
            Ok(_) => {
                self.retire_local(RetirementReason::LeaseNotFound);
                Ok(RecoveryOutcome::Retired(RetirementReason::LeaseNotFound))
            }
            Err(error) => {
                self.record_runtime_failure(&error);
                Err(error)
            }
        }
    }

    /// Reconnects and verifies the exact lease, owner value, and creation
    /// revision after uncertain transport state.
    ///
    /// # Errors
    ///
    /// Returns a typed dependency error while retaining uncertain ownership;
    /// definitive lease or owner mismatches return a successful `Retired`
    /// outcome so callers cannot mistake them for a retryable transport fault.
    pub async fn recover(&mut self) -> Result<RecoveryOutcome, ElectionError> {
        self.ensure_process_owner()?;
        if let Some(reason) = self.snapshot().retirement_reason {
            return Ok(RecoveryOutcome::Retired(reason));
        }
        self.mark_uncertain();
        let mut connection = match self.connector.connect().await {
            Ok(connection) => connection,
            Err(source) => {
                let error = map_connect_error(source);
                self.retire_if_stale(&error);
                return Err(error);
            }
        };
        let lease_id = self.snapshot().lease_id;
        let verification = self.verify_recovery(&mut connection, lease_id).await?;
        self.connection = connection;
        let (lease_keeper, keep_alive_stream) = match verification {
            RecoveryVerification::Active(handles) => *handles,
            RecoveryVerification::Retired(reason) => {
                self.clear_transport_handles();
                self.retire_local(reason);
                return Ok(RecoveryOutcome::Retired(reason));
            }
        };
        self.lease_keeper = Some(lease_keeper);
        self.keep_alive_stream = Some(keep_alive_stream);
        // Resume from the last consumed watch revision first.  If etcd has
        // compacted it, watch_once performs the required fresh leader read and
        // installs a new watch from that response's revision.
        let watch_revision = self.next_watch_revision.max(1);
        self.start_watch(watch_revision).await?;
        self.ensure_process_owner()?;
        self.update_snapshot(|snapshot| {
            snapshot.state = ElectionState::Leader;
            snapshot.retirement_reason = None;
        });
        Ok(RecoveryOutcome::Restored)
    }

    async fn verify_recovery(
        &mut self,
        connection: &mut EtcdConnection,
        lease_id: i64,
    ) -> Result<RecoveryVerification, ElectionError> {
        let ttl = match connection
            .execute(move |client| Box::pin(client.lease_time_to_live(lease_id, None)))
            .await
        {
            Ok(ttl) => ttl,
            Err(source) => {
                let error = map_operation_error("lease_time_to_live", source);
                self.retire_if_stale(&error);
                return Err(error);
            }
        };
        if ttl.ttl() <= 0 || ttl.id() != lease_id {
            return Ok(RecoveryVerification::Retired(
                RetirementReason::LeaseNotFound,
            ));
        }
        self.advance_optional_header(ttl.header());

        let election_name = self.config.election_name().to_vec();
        let leader = match connection
            .execute(move |client| Box::pin(client.leader(election_name)))
            .await
        {
            Ok(leader) => leader,
            Err(source) => {
                let error = map_operation_error("leader", source);
                self.retire_if_stale(&error);
                return Err(error);
            }
        };
        self.advance_optional_header(leader.header());
        let Some(kv) = leader.kv() else {
            return Ok(RecoveryVerification::Retired(
                RetirementReason::OwnerChanged,
            ));
        };
        let leader_key = self
            .leader_key
            .as_ref()
            .ok_or(ElectionError::InvalidResponse {
                class: "missing_local_leader_key",
            })?;
        let same_owner = kv.key() == leader_key.key()
            && kv.value() == self.config.member_id()
            && kv.lease() == lease_id
            && kv.create_revision() == self.snapshot().session_revision;
        if !same_owner {
            return Ok(RecoveryVerification::Retired(
                RetirementReason::OwnerChanged,
            ));
        }

        let (mut lease_keeper, mut keep_alive_stream) = match connection
            .execute(move |client| Box::pin(client.lease_keep_alive(lease_id)))
            .await
        {
            Ok(handles) => handles,
            Err(source) => {
                let error = map_operation_error("lease_keep_alive", source);
                self.retire_if_stale(&error);
                return Err(error);
            }
        };
        let response = match send_keep_alive(
            &self.owner,
            &mut lease_keeper,
            &mut keep_alive_stream,
            self.request_timeout,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                self.retire_if_stale(&error);
                return Err(error);
            }
        };
        if response.ttl() <= 0 || response.id() != lease_id {
            return Ok(RecoveryVerification::Retired(
                RetirementReason::LeaseNotFound,
            ));
        }
        self.advance_optional_header(response.header());
        Ok(RecoveryVerification::Active(Box::new((
            lease_keeper,
            keep_alive_stream,
        ))))
    }

    /// Consumes one semantic watch response, including stale-revision
    /// compaction recovery.
    ///
    /// # Errors
    ///
    /// Returns typed stale-owner, stream, dependency, canceled-watch, or
    /// malformed-response failures.
    pub async fn watch_once(&mut self) -> Result<WatchOutcome, ElectionError> {
        self.ensure_process_owner()?;
        if let Some(reason) = self.snapshot().retirement_reason {
            return Ok(WatchOutcome::Retired(reason));
        }
        let result = {
            let stream = self
                .watch_stream
                .as_mut()
                .ok_or(ElectionError::InvalidResponse {
                    class: "missing_watch_stream",
                })?;
            stream.message().await
        };
        self.ensure_process_owner()?;
        let response = match result {
            Ok(Some(response)) => response,
            Ok(None) => {
                self.mark_uncertain();
                return Err(ElectionError::WatchCanceled);
            }
            Err(source) => {
                self.mark_uncertain();
                return Err(ElectionError::Stream {
                    operation: "watch",
                    source,
                });
            }
        };
        let response_revision = response
            .header()
            .map_or(0, etcd_client::ResponseHeader::revision);
        self.advance_revision(response_revision);
        if response.canceled() {
            if response.compact_revision() > 0 {
                return self
                    .recover_compacted_watch(response.compact_revision())
                    .await;
            }
            self.mark_uncertain();
            return Err(ElectionError::WatchCanceled);
        }

        let mut saw_event = false;
        let mut saw_delete = false;
        for event in response.events() {
            saw_event = true;
            if let Some(kv) = event.kv() {
                self.advance_revision(kv.mod_revision());
                self.next_watch_revision = self.next_watch_revision.max(kv.mod_revision() + 1);
            }
            saw_delete |= matches!(event.event_type(), EventType::Delete);
        }
        self.next_watch_revision = self
            .next_watch_revision
            .max(response_revision.saturating_add(1));
        if saw_delete {
            return match self.recover().await? {
                RecoveryOutcome::Restored => Ok(WatchOutcome::Event),
                RecoveryOutcome::Retired(reason) => Ok(WatchOutcome::Retired(reason)),
            };
        }
        Ok(if saw_event {
            WatchOutcome::Event
        } else {
            WatchOutcome::Progress
        })
    }

    /// Reopens a lost watch from the last consumed revision.
    ///
    /// This is the reconnect seam used after a watch transport closes while
    /// the lease remains valid.  The first subsequent [`Self::watch_once`]
    /// either consumes ordered events or handles an etcd compaction
    /// cancellation through a fresh leader read.
    ///
    /// # Errors
    ///
    /// Returns a stale-owner or typed dependency failure while installing the
    /// replacement stream.
    pub async fn resume_watch(&mut self) -> Result<(), ElectionError> {
        self.ensure_process_owner()?;
        if !self.snapshot().may_commit_owner_work() {
            return Err(ElectionError::NotLeader);
        }
        self.watch_stream = None;
        self.start_watch(self.next_watch_revision.max(1)).await
    }

    /// Commits one lease-backed transaction only while the exact election key
    /// still matches its creation revision, lease, and exact member value.
    ///
    /// # Errors
    ///
    /// Rejects uncertain/retired owners, oversized inputs, stale process
    /// owners, and dependency failures.  A failed etcd comparison definitively
    /// retires this member before returning `NotLeader`.
    pub async fn fenced_put(
        &mut self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), ElectionError> {
        self.ensure_process_owner()?;
        if !self.snapshot().may_commit_owner_work() {
            return Err(ElectionError::NotLeader);
        }
        let key = key.into();
        let value = value.into();
        if key.is_empty()
            || key.len() > MAX_TXN_KEY_BYTES
            || key.contains(&0)
            || value.len() > MAX_TXN_VALUE_BYTES
            || self.is_reserved_election_key(&key)
        {
            return Err(ElectionError::InvalidTransactionInput);
        }
        self.execute_fenced_put(key, value).await
    }

    async fn execute_fenced_put(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), ElectionError> {
        let leader_key = self
            .leader_key
            .as_ref()
            .ok_or(ElectionError::InvalidResponse {
                class: "missing_local_leader_key",
            })?;
        let elected_key = leader_key.key().to_vec();
        let revision = leader_key.rev();
        let lease_id = self.snapshot().lease_id;
        let member_id = self.config.member_id().to_vec();
        let txn = Txn::new()
            .when([
                Compare::create_revision(elected_key.clone(), CompareOp::Equal, revision),
                Compare::lease(elected_key.clone(), CompareOp::Equal, lease_id),
                Compare::value(elected_key, CompareOp::Equal, member_id),
            ])
            .and_then([TxnOp::put(
                key,
                value,
                Some(PutOptions::new().with_lease(lease_id)),
            )]);
        let response = match self
            .connection
            .execute(move |client| Box::pin(client.txn(txn)))
            .await
        {
            Ok(response) => response,
            Err(source) => {
                let error = map_operation_error("fenced_txn", source);
                self.record_runtime_failure(&error);
                return Err(error);
            }
        };
        self.advance_optional_header(response.header());
        if !response.succeeded() {
            self.retire_local(RetirementReason::OwnerChanged);
            return Err(ElectionError::NotLeader);
        }
        Ok(())
    }

    /// Resigns, revokes the lease, and crosses the local retirement fence.
    ///
    /// Local state always becomes `Stopped`, even if etcd is unavailable; a
    /// failed revoke is safe because all attached keys still expire by TTL.
    ///
    /// # Errors
    ///
    /// Returns the first typed dependency failure after stopping locally.
    pub async fn shutdown(mut self) -> Result<(), ElectionError> {
        let mut first_error = None;
        if self.owner.is_current() && self.snapshot().retains_local_ownership() {
            if let Some(leader_key) = self.leader_key.take() {
                let options = ResignOptions::new().with_leader(leader_key);
                if let Err(source) = self
                    .connection
                    .execute(move |client| Box::pin(client.resign(Some(options))))
                    .await
                {
                    first_error = Some(map_operation_error("resign", source));
                }
            }
            let lease_id = self.snapshot().lease_id;
            if lease_id != 0
                && let Err(source) = self
                    .connection
                    .execute(move |client| Box::pin(client.lease_revoke(lease_id)))
                    .await
            {
                first_error.get_or_insert_with(|| map_operation_error("lease_revoke", source));
            }
        }
        self.clear_transport_handles();
        self.update_snapshot(|snapshot| {
            snapshot.state = ElectionState::Stopped;
            snapshot.retirement_reason = Some(RetirementReason::Shutdown);
        });
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    async fn attach_ephemeral_session_key(&mut self) -> Result<(), ElectionError> {
        let key = self.config.session_key().to_vec();
        let value = self.config.member_id().to_vec();
        // The session is still Campaigning here. This internal transaction is
        // the proof that permits the later Leader transition; callers cannot
        // observe a transient committable state before the session key exists.
        self.execute_fenced_put(key, value).await
    }

    async fn recover_compacted_watch(
        &mut self,
        compact_revision: i64,
    ) -> Result<WatchOutcome, ElectionError> {
        let election_name = self.config.election_name().to_vec();
        let leader = match self
            .connection
            .execute(move |client| Box::pin(client.leader(election_name)))
            .await
        {
            Ok(leader) => leader,
            Err(source) => {
                let error = map_operation_error("compaction_relist", source);
                self.record_runtime_failure(&error);
                return Err(error);
            }
        };
        let revision = match revision(leader.header()) {
            Ok(revision) => revision.max(compact_revision),
            Err(error) => {
                self.record_runtime_failure(&error);
                return Err(error);
            }
        };
        let Some(kv) = leader.kv() else {
            self.retire_local(RetirementReason::OwnerChanged);
            return Ok(WatchOutcome::Retired(RetirementReason::OwnerChanged));
        };
        let leader_key = self
            .leader_key
            .as_ref()
            .ok_or(ElectionError::InvalidResponse {
                class: "missing_local_leader_key",
            })?;
        let snapshot = self.snapshot();
        if kv.key() != leader_key.key()
            || kv.value() != self.config.member_id()
            || kv.lease() != snapshot.lease_id
            || kv.create_revision() != snapshot.session_revision
        {
            self.retire_local(RetirementReason::OwnerChanged);
            return Ok(WatchOutcome::Retired(RetirementReason::OwnerChanged));
        }
        self.advance_revision(revision);
        self.start_watch(revision.saturating_add(1)).await?;
        self.ensure_process_owner()?;
        self.update_snapshot(|snapshot| {
            snapshot.compaction_recoveries = snapshot.compaction_recoveries.saturating_add(1);
            snapshot.state = ElectionState::Leader;
        });
        Ok(WatchOutcome::CompactionRecovered)
    }

    async fn start_watch(&mut self, revision: i64) -> Result<(), ElectionError> {
        self.ensure_process_owner()?;
        let leader_key = self
            .leader_key
            .as_ref()
            .ok_or(ElectionError::InvalidResponse {
                class: "missing_local_leader_key",
            })?
            .key()
            .to_vec();
        let options = WatchOptions::new()
            .with_start_revision(revision.max(1))
            .with_progress_notify();
        let stream = match self
            .connection
            .execute(move |client| Box::pin(client.watch(leader_key, Some(options))))
            .await
        {
            Ok(stream) => stream,
            Err(source) => {
                let error = map_operation_error("watch", source);
                self.record_runtime_failure(&error);
                return Err(error);
            }
        };
        self.watch_stream = Some(stream);
        self.next_watch_revision = revision.max(1);
        Ok(())
    }

    fn ensure_process_owner(&mut self) -> Result<(), ElectionError> {
        if self.owner.is_current() {
            return Ok(());
        }
        self.clear_transport_handles();
        self.retire_local(RetirementReason::ProcessOwnerLost);
        Err(ElectionError::StaleOwner)
    }

    fn mark_uncertain(&mut self) {
        self.update_snapshot(|snapshot| {
            if snapshot.retains_local_ownership() {
                snapshot.state = ElectionState::Uncertain;
            }
            snapshot.retry_count = snapshot.retry_count.saturating_add(1);
        });
    }

    fn record_runtime_failure(&mut self, error: &ElectionError) {
        if matches!(error, ElectionError::StaleOwner) {
            self.clear_transport_handles();
            self.retire_local(RetirementReason::ProcessOwnerLost);
        } else {
            self.mark_uncertain();
        }
    }

    fn retire_if_stale(&mut self, error: &ElectionError) {
        if matches!(error, ElectionError::StaleOwner) {
            self.clear_transport_handles();
            self.retire_local(RetirementReason::ProcessOwnerLost);
        }
    }

    fn retire_local(&mut self, reason: RetirementReason) {
        self.update_snapshot(|snapshot| {
            snapshot.state = ElectionState::Retired;
            snapshot.retirement_reason = Some(reason);
        });
    }

    fn clear_transport_handles(&mut self) {
        self.lease_keeper = None;
        self.keep_alive_stream = None;
        self.watch_stream = None;
    }

    fn is_reserved_election_key(&self, key: &[u8]) -> bool {
        let mut election_prefix = self.config.election_name().to_vec();
        election_prefix.push(b'/');
        key.starts_with(&election_prefix) || key == self.config.session_key()
    }

    fn advance_optional_header(&mut self, header: Option<&etcd_client::ResponseHeader>) {
        if let Some(header) = header {
            self.advance_revision(header.revision());
        }
    }

    fn advance_revision(&mut self, revision: i64) {
        self.update_snapshot(|snapshot| {
            snapshot.observed_revision = snapshot.observed_revision.max(revision);
        });
    }

    fn update_snapshot(&self, update: impl FnOnce(&mut ElectionSnapshot)) {
        let mut snapshot = self.snapshot_tx.borrow().clone();
        update(&mut snapshot);
        self.snapshot_tx.send_replace(snapshot);
    }
}

enum RecoveryVerification {
    Active(Box<(LeaseKeeper, LeaseKeepAliveStream)>),
    Retired(RetirementReason),
}

struct CampaignIo<'a> {
    owner: &'a OwnerToken,
    connection: &'a mut EtcdConnection,
    lease_keeper: &'a mut LeaseKeeper,
    keep_alive_stream: &'a mut LeaseKeepAliveStream,
    lease_id: i64,
    heartbeat_interval: Duration,
    request_timeout: Duration,
}

async fn campaign_candidate(
    io: &mut CampaignIo<'_>,
    election_name: &[u8],
    member_id: &[u8],
) -> Result<(LeaderKey, i64), ElectionError> {
    let mut election_prefix = election_name.to_vec();
    // Match etcd's concurrency.NewElection and Election service exactly: the
    // caller's name is a namespace and every contender lives under name + "/".
    election_prefix.push(b'/');
    let mut candidate_key = election_prefix.clone();
    candidate_key.extend_from_slice(format!("{:x}", io.lease_id).as_bytes());

    let (candidate_revision, mut observed_revision) =
        create_candidate(io.connection, &candidate_key, member_id, io.lease_id).await?;

    loop {
        let response = send_keep_alive(
            io.owner,
            io.lease_keeper,
            io.keep_alive_stream,
            io.request_timeout,
        )
        .await?;
        verify_keep_alive(&response, io.lease_id)?;
        if let Some(header) = response.header() {
            observed_revision = observed_revision.max(header.revision());
        }

        let options = GetOptions::new()
            .with_prefix()
            .with_sort(SortTarget::Create, SortOrder::Descend)
            .with_limit(1)
            .with_max_create_revision(candidate_revision.saturating_sub(1));
        let prefix = election_prefix.clone();
        let predecessor = io
            .connection
            .execute(move |client| Box::pin(client.get(prefix, Some(options))))
            .await
            .map_err(|source| map_operation_error("campaign_predecessor", source))?;
        let predecessor_revision = revision(predecessor.header())?;
        observed_revision = observed_revision.max(predecessor_revision);
        let Some(predecessor_key) = predecessor.kvs().first().map(|kv| kv.key().to_vec()) else {
            let leader_key = LeaderKey::new()
                .with_name(election_name)
                .with_key(candidate_key)
                .with_rev(candidate_revision)
                .with_lease(io.lease_id);
            return Ok((leader_key, observed_revision));
        };

        let options = WatchOptions::new().with_start_revision(predecessor_revision);
        let mut stream = io
            .connection
            .execute(move |client| Box::pin(client.watch(predecessor_key, Some(options))))
            .await
            .map_err(|source| map_operation_error("campaign_watch", source))?;
        let watch_revision = wait_for_predecessor_delete(io, &mut stream).await?;
        observed_revision = observed_revision.max(watch_revision);
    }
}

async fn create_candidate(
    connection: &mut EtcdConnection,
    candidate_key: &[u8],
    member_id: &[u8],
    lease_id: i64,
) -> Result<(i64, i64), ElectionError> {
    let txn = Txn::new()
        .when([Compare::create_revision(candidate_key, CompareOp::Equal, 0)])
        .and_then([TxnOp::put(
            candidate_key,
            member_id,
            Some(PutOptions::new().with_lease(lease_id)),
        )])
        .or_else([TxnOp::get(candidate_key, None)]);
    let response = connection
        .execute(move |client| Box::pin(client.txn(txn)))
        .await
        .map_err(|source| map_operation_error("campaign_create", source))?;
    let header_revision = revision(response.header())?;
    if response.succeeded() {
        return Ok((header_revision, header_revision));
    }

    let responses = response.op_responses();
    let [TxnOpResponse::Get(existing)] = responses.as_slice() else {
        return Err(ElectionError::InvalidResponse {
            class: "invalid_existing_candidate_response",
        });
    };
    let [candidate] = existing.kvs() else {
        return Err(ElectionError::InvalidResponse {
            class: "missing_existing_candidate",
        });
    };
    if candidate.key() != candidate_key
        || candidate.value() != member_id
        || candidate.lease() != lease_id
        || candidate.create_revision() <= 0
    {
        return Err(ElectionError::InvalidResponse {
            class: "mismatched_existing_candidate",
        });
    }
    Ok((candidate.create_revision(), header_revision))
}

async fn wait_for_predecessor_delete(
    io: &mut CampaignIo<'_>,
    stream: &mut WatchStream,
) -> Result<i64, ElectionError> {
    let mut observed_revision = 0;
    loop {
        tokio::select! {
            response = stream.message() => {
                if !io.owner.is_current() {
                    return Err(ElectionError::StaleOwner);
                }
                let response = response
                    .map_err(|source| ElectionError::Stream {
                        operation: "campaign_watch",
                        source,
                    })?
                    .ok_or(ElectionError::InvalidResponse {
                        class: "closed_campaign_watch",
                    })?;
                if let Some(header) = response.header() {
                    observed_revision = observed_revision.max(header.revision());
                }
                if response.canceled() {
                    if response.compact_revision() > 0 {
                        return Ok(observed_revision.max(response.compact_revision()));
                    }
                    return Err(ElectionError::WatchCanceled);
                }
                if response.events().iter().any(|event| {
                    matches!(event.event_type(), EventType::Delete)
                }) {
                    return Ok(observed_revision);
                }
            }
            () = tokio::time::sleep(io.heartbeat_interval) => {
                let response = send_keep_alive(
                    io.owner,
                    io.lease_keeper,
                    io.keep_alive_stream,
                    io.request_timeout,
                ).await?;
                verify_keep_alive(&response, io.lease_id)?;
                if let Some(header) = response.header() {
                    observed_revision = observed_revision.max(header.revision());
                }
            }
        }
    }
}

fn campaign_heartbeat_interval(session_ttl_seconds: i64) -> Duration {
    let ttl_millis = u64::try_from(session_ttl_seconds)
        .unwrap_or(1)
        .saturating_mul(1_000);
    Duration::from_millis((ttl_millis / 3).max(100))
}

async fn send_keep_alive(
    owner: &OwnerToken,
    keeper: &mut LeaseKeeper,
    stream: &mut LeaseKeepAliveStream,
    timeout: Duration,
) -> Result<etcd_client::LeaseKeepAliveResponse, ElectionError> {
    if !owner.is_current() {
        return Err(ElectionError::StaleOwner);
    }
    keeper
        .keep_alive()
        .await
        .map_err(|source| ElectionError::Stream {
            operation: "keep_alive_send",
            source,
        })?;
    let response = tokio::time::timeout(timeout, stream.message())
        .await
        .map_err(|_| ElectionError::Timeout {
            operation: "keep_alive_receive",
        })?
        .map_err(|source| ElectionError::Stream {
            operation: "keep_alive_receive",
            source,
        })?
        .ok_or(ElectionError::InvalidResponse {
            class: "closed_keep_alive_stream",
        })?;
    if !owner.is_current() {
        return Err(ElectionError::StaleOwner);
    }
    Ok(response)
}

fn verify_keep_alive(
    response: &etcd_client::LeaseKeepAliveResponse,
    lease_id: i64,
) -> Result<(), ElectionError> {
    if response.id() != lease_id || response.ttl() <= 0 {
        return Err(ElectionError::InvalidResponse {
            class: "invalid_keep_alive_response",
        });
    }
    Ok(())
}

fn revision(header: Option<&etcd_client::ResponseHeader>) -> Result<i64, ElectionError> {
    let revision = header
        .ok_or(ElectionError::InvalidResponse {
            class: "missing_response_header",
        })?
        .revision();
    if revision <= 0 {
        return Err(ElectionError::InvalidResponse {
            class: "invalid_response_revision",
        });
    }
    Ok(revision)
}

fn map_connect_error(error: EtcdConnectError) -> ElectionError {
    match error {
        EtcdConnectError::StaleOwner => ElectionError::StaleOwner,
        dependency @ EtcdConnectError::Dependency(_) => ElectionError::Connect(dependency),
    }
}

fn map_operation_error(operation: &'static str, error: EtcdOperationError) -> ElectionError {
    match error {
        EtcdOperationError::StaleOwner => ElectionError::StaleOwner,
        dependency @ EtcdOperationError::Dependency(_) => ElectionError::Operation {
            operation,
            source: dependency,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use control_external::EtcdClientConfig;
    use control_plane::{OwnerScope, OwnershipRegistry};

    use super::{
        ElectionError, ElectionSession, ElectionSnapshot, ElectionState, RetirementReason,
        campaign_heartbeat_interval,
    };
    use crate::ElectionConfig;

    #[test]
    fn uncertain_retains_but_cannot_commit_ownership() {
        let snapshot = ElectionSnapshot {
            state: ElectionState::Uncertain,
            member_id: b"member-A".to_vec(),
            lease_id: 7,
            session_revision: 9,
            observed_revision: 10,
            retry_count: 1,
            compaction_recoveries: 0,
            retirement_reason: None,
        };
        assert!(snapshot.retains_local_ownership());
        assert!(!snapshot.may_commit_owner_work());
    }

    #[test]
    fn process_owner_generation_is_unique() {
        let registry = OwnershipRegistry::new();
        let first = registry
            .claim(OwnerScope::Process, "process-A")
            .unwrap_or_else(|error| unreachable!("first owner: {error}"));
        let stale = first.token();
        drop(first);
        assert!(!stale.is_current());
        let second = registry
            .claim(OwnerScope::Process, "process-B")
            .unwrap_or_else(|error| unreachable!("second owner: {error}"));
        assert_eq!(second.generation(), 2);
        assert_eq!(
            RetirementReason::ProcessOwnerLost.as_str(),
            "process_owner_lost"
        );
    }

    #[tokio::test]
    async fn request_timeout_must_leave_room_for_campaign_keep_alive() {
        let registry = OwnershipRegistry::new();
        let process = registry
            .claim(OwnerScope::Process, "process-A")
            .unwrap_or_else(|error| unreachable!("process owner: {error}"));
        let client_config = EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], None)
            .and_then(|config| {
                config.with_timeouts(
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
            })
            .unwrap_or_else(|error| unreachable!("client config: {error}"));
        let election_config = ElectionConfig::new("election", "member-A", "session-A", 2)
            .unwrap_or_else(|error| unreachable!("election config: {error}"));
        assert!(matches!(
            ElectionSession::campaign(process.token(), client_config, election_config).await,
            Err(ElectionError::InvalidResponse {
                class: "request_timeout_not_below_session_ttl"
            })
        ));
        assert_eq!(campaign_heartbeat_interval(2), Duration::from_millis(666));
    }
}
