// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Live-only v2 envelope. V1 witness-free events can never qualify here.
use super::{Error, MAX_FRAME_BYTES};
use control_router::shadow::{
    Epoch, Event,
    live::{AccountWitness, Batch, ConnectionState, LiveEvent, Witness},
};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Decimal(u64);
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let text = String::deserialize(decoder)?;
        let value = text
            .parse::<u64>()
            .map_err(|_| D::Error::custom("u64 decimal"))?;
        if value.to_string() != text {
            return Err(D::Error::custom("canonical u64 decimal"));
        }
        Ok(Self(value))
    }
}
#[derive(Clone, Copy, Debug)]
struct Signed(i64);
impl<'de> Deserialize<'de> for Signed {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let text = String::deserialize(decoder)?;
        let value = text
            .parse::<i64>()
            .map_err(|_| D::Error::custom("i64 decimal"))?;
        if value.to_string() != text {
            return Err(D::Error::custom("canonical i64 decimal"));
        }
        Ok(Self(value))
    }
}

struct Bounded<T, const N: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Values<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Values<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "array of at most {N} values")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::with_capacity(N);
                while let Some(value) = access.next_element()? {
                    if values.len() == N {
                        return Err(A::Error::custom("array bound"));
                    }
                    values.push(value);
                }
                Ok(Bounded(values))
            }
        }
        decoder.deserialize_seq(Values::<T, N>(std::marker::PhantomData))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    kind: String,
    id: Decimal,
    group: Decimal,
    session: Decimal,
    operation: Decimal,
    account: Decimal,
    target: Decimal,
    success: bool,
}
impl WireEvent {
    #[allow(clippy::too_many_lines)] // Keep the complete fixed-field allowlist in one auditable match.
    fn domain(self) -> Result<LiveEvent, Error> {
        let (id, group, session, operation, account, target) = (
            self.id.0,
            self.group.0,
            self.session.0,
            self.operation.0,
            self.account.0,
            self.target.0,
        );
        let mut expected = Self {
            kind: self.kind.clone(),
            id: Decimal(0),
            group: Decimal(0),
            session: Decimal(0),
            operation: Decimal(0),
            account: Decimal(0),
            target: Decimal(0),
            success: false,
        };
        let mut source = 0;
        let mut examined_target = 0;
        let event = match self.kind.as_str() {
            "begin" => Event::Begin,
            "account" => {
                expected.id = self.id;
                expected.group = self.group;
                Event::Account { id, group }
            }
            "remove_account" => {
                expected.account = self.account;
                Event::RemoveAccount(account)
            }
            "open" => {
                expected.session = self.session;
                Event::Open(session)
            }
            "reserve" => {
                expected.session = self.session;
                expected.operation = self.operation;
                expected.account = self.account;
                Event::Reserve {
                    session,
                    operation,
                    account,
                }
            }
            "created" => {
                expected.session = self.session;
                expected.operation = self.operation;
                expected.success = self.success;
                Event::Created {
                    session,
                    operation,
                    success: self.success,
                }
            }
            "redirect" | "redirected" | "rejected" => {
                expected.session = self.session;
                expected.operation = self.operation;
                expected.account = self.account;
                expected.target = self.target;
                source = account;
                examined_target = target;
                match self.kind.as_str() {
                    "redirect" => Event::Redirect {
                        session,
                        operation,
                        target,
                    },
                    "redirected" => {
                        expected.success = self.success;
                        Event::Redirected {
                            session,
                            operation,
                            success: self.success,
                        }
                    }
                    _ => Event::Rejected { session },
                }
            }
            "closing" => {
                expected.session = self.session;
                expected.operation = self.operation;
                Event::Closing { session, operation }
            }
            "closed" => {
                expected.session = self.session;
                Event::Closed(session)
            }
            "rehydrate" => {
                expected.session = self.session;
                expected.account = self.account;
                Event::Rehydrate { session, account }
            }
            "retire" => Event::Retire,
            "end" => Event::End,
            "watermark" => Event::Watermark,
            "group_created" | "group_removed" | "selection_done" | "route_rejected"
            | "reconnect" => {
                let event = match self.kind.as_str() {
                    "group_created" => {
                        expected.group = self.group;
                        LiveEvent::GroupCreated(group)
                    }
                    "group_removed" => {
                        expected.group = self.group;
                        LiveEvent::GroupRemoved(group)
                    }
                    "selection_done" => {
                        expected.session = self.session;
                        LiveEvent::SelectionDone(session)
                    }
                    "route_rejected" => {
                        expected.session = self.session;
                        expected.group = self.group;
                        LiveEvent::RouteRejected { session, group }
                    }
                    _ => {
                        expected.session = self.session;
                        expected.operation = self.operation;
                        expected.account = self.account;
                        expected.success = self.success;
                        LiveEvent::Reconnect {
                            session,
                            operation,
                            account,
                            accepted: self.success,
                        }
                    }
                };
                return if self == expected {
                    Ok(event)
                } else {
                    Err(Error::Schema)
                };
            }
            _ => return Err(Error::Schema),
        };
        if self != expected {
            return Err(Error::Schema);
        }
        Ok(LiveEvent::Lifecycle {
            event,
            source,
            target: examined_target,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAccount {
    id: Decimal,
    score: Signed,
    physical: Decimal,
    head: Decimal,
    tail: Decimal,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Exact independent witness dimensions.
struct WireConnection {
    present: bool,
    physical: Decimal,
    score_owner: Decimal,
    redirect_pending: bool,
    closing: bool,
    closed: bool,
}
impl From<WireConnection> for ConnectionState {
    fn from(w: WireConnection) -> Self {
        Self {
            present: w.present,
            physical: w.physical.0,
            score_owner: w.score_owner.0,
            redirect_pending: w.redirect_pending,
            closing: w.closing,
            closed: w.closed,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWitness {
    accounts: Bounded<WireAccount, 2>,
    session: Decimal,
    predecessor: Decimal,
    before: WireConnection,
    after: WireConnection,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireFrame {
    Batch {
        version: u32,
        process: Decimal,
        owner: Decimal,
        nonce: Decimal,
        lifecycle_only: bool,
        factors: bool,
        selection: bool,
        scheduler: bool,
        sequence: Decimal,
        events: Bounded<WireEvent, 4>,
        witness: WireWitness,
    },
    Invalid {
        version: u32,
        process: Decimal,
        owner: Decimal,
        nonce: Decimal,
        lifecycle_only: bool,
        factors: bool,
        selection: bool,
        scheduler: bool,
        last_admitted: Decimal,
        reason: String,
    },
    Coverage {
        version: u32,
        process: Decimal,
        owner: Decimal,
        nonce: Decimal,
        lifecycle_only: bool,
        factors: bool,
        selection: bool,
        scheduler: bool,
    },
}

/// Decoded value envelope. No transport identifier grants production authority.
pub enum Frame {
    /// Actual Go atomic transition and output witnesses.
    Batch(Batch),
    /// Out-of-band permanent disqualification, never a compared event sequence.
    Invalid {
        /// Full owner identity.
        epoch: Epoch,
        /// Last sequence admitted by Go; not last successfully compared in Rust.
        last_admitted: u64,
        /// Bounded allowlisted producer diagnostic.
        reason: InvalidCause,
    },
    /// Stream identity with lifecycle-only coverage explicitly enforced.
    Coverage {
        /// Authoritative process incarnation.
        process: u64,
        /// Stream start nonce.
        nonce: u64,
    },
}
/// Bounded producer reasons, independent of any SQL lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidCause {
    /// A fixed registry or journal budget was exhausted.
    Capacity,
    /// Encoder or fixed-value validation failed.
    Malformed,
    /// An identity or sequence would wrap.
    SequenceExhausted,
    /// The original consuming socket disconnected.
    TransportLost,
    /// Namespace disappeared without production retirement.
    OwnerDisappeared,
    /// Observer shutdown cannot claim full tail settlement.
    Shutdown,
    /// Freshness deadline expired.
    Stale,
    /// An actual discarded selector retained an unrefunded Go reservation.
    UnpairedDiscard,
}

/// Decode one strict v2 frame, including its big-endian length prefix.
///
/// # Errors
/// Rejects unknown versions/fields, missing/duplicate keys, noncanonical IDs,
/// oversized frames, oversized collections and witness-free v1 records.
pub fn decode(frame: &[u8]) -> Result<Frame, Error> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(Error::Framing)?
        .try_into()
        .map_err(|_| Error::Framing)?;
    let size = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Oversized)?;
    if size > MAX_FRAME_BYTES {
        return Err(Error::Oversized);
    }
    if size == 0 || frame.len() != size + 4 {
        return Err(Error::Framing);
    }
    let value: WireFrame = serde_json::from_slice(&frame[4..]).map_err(|_| Error::Schema)?;
    value.domain()
}

// Nested bodies reuse every v2 event/witness/coverage check; invalid and coverage
// messages remain out-of-band and are never accepted as caller children.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct NestedBatch(WireFrame);
impl NestedBatch {
    pub(crate) fn domain(self) -> Result<Batch, Error> {
        match self.0.domain()? {
            Frame::Batch(batch) => Ok(batch),
            _ => Err(Error::Schema),
        }
    }
}
impl WireFrame {
    #[allow(clippy::too_many_lines)] // Complete existing allowlist remains shared with v2.
    fn domain(self) -> Result<Frame, Error> {
        let (version, epoch, coverage, result) = match self {
            WireFrame::Batch {
                version,
                process,
                owner,
                nonce,
                lifecycle_only,
                factors,
                selection,
                scheduler,
                sequence,
                events,
                witness,
            } => {
                let epoch = Epoch {
                    process: process.0,
                    owner: owner.0,
                    nonce: nonce.0,
                };
                if sequence.0 == 0 || events.0.is_empty() {
                    return Err(Error::Schema);
                }
                let events = events
                    .0
                    .into_iter()
                    .map(WireEvent::domain)
                    .collect::<Result<Vec<_>, _>>()?;
                let accounts = witness
                    .accounts
                    .0
                    .into_iter()
                    .map(|a| AccountWitness {
                        id: a.id.0,
                        score: a.score.0,
                        physical: a.physical.0,
                        head: a.head.0,
                        tail: a.tail.0,
                    })
                    .collect();
                let batch = Batch {
                    epoch,
                    sequence: sequence.0,
                    events,
                    witness: Witness {
                        accounts,
                        session: witness.session.0,
                        predecessor: witness.predecessor.0,
                        before: witness.before.into(),
                        after: witness.after.into(),
                    },
                };
                (
                    version,
                    epoch,
                    (lifecycle_only, factors, selection, scheduler),
                    Frame::Batch(batch),
                )
            }
            WireFrame::Invalid {
                version,
                process,
                owner,
                nonce,
                lifecycle_only,
                factors,
                selection,
                scheduler,
                last_admitted,
                reason,
            } => {
                let epoch = Epoch {
                    process: process.0,
                    owner: owner.0,
                    nonce: nonce.0,
                };
                let reason = match reason.as_str() {
                    "capacity" => InvalidCause::Capacity,
                    "malformed" => InvalidCause::Malformed,
                    "sequence_exhausted" => InvalidCause::SequenceExhausted,
                    "transport_lost" => InvalidCause::TransportLost,
                    "owner_disappeared" => InvalidCause::OwnerDisappeared,
                    "shutdown" => InvalidCause::Shutdown,
                    "stale" => InvalidCause::Stale,
                    "unpaired_discard" => InvalidCause::UnpairedDiscard,
                    _ => return Err(Error::Schema),
                };
                (
                    version,
                    epoch,
                    (lifecycle_only, factors, selection, scheduler),
                    Frame::Invalid {
                        epoch,
                        last_admitted: last_admitted.0,
                        reason,
                    },
                )
            }
            WireFrame::Coverage {
                version,
                process,
                owner,
                nonce,
                lifecycle_only,
                factors,
                selection,
                scheduler,
            } => {
                let epoch = Epoch {
                    process: process.0,
                    owner: owner.0,
                    nonce: nonce.0,
                };
                (
                    version,
                    epoch,
                    (lifecycle_only, factors, selection, scheduler),
                    Frame::Coverage {
                        process: process.0,
                        nonce: nonce.0,
                    },
                )
            }
        };
        if version != 2 {
            return Err(Error::Version);
        }
        if epoch.process == 0
            || epoch.nonce == 0
            || coverage != (true, false, false, false)
            || matches!(result, Frame::Coverage { .. }) != (epoch.owner == 0)
        {
            return Err(Error::Schema);
        }
        Ok(result)
    }
}
