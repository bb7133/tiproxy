// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Actual router reads and Group/selector comparison in one caller transaction.
use super::metadata::{Classification, Rule};
use super::selection::{DerivedResult, ErrorClass};
use super::{Batch, Epoch, InvalidReason, LiveEvent, LiveState, Progress, Scope, route};
use control_routing::group::ClientInfo;

/// One actual Group match; absence of an address means no String read occurred.
#[derive(Clone, Debug)]
pub struct MatchRead {
    /// Visited Group identity, in the retained router order.
    pub group: u64,
    /// Exact original String result, at most 512 bytes; nil is not an empty string.
    pub address: Option<String>,
    /// Go return witness; Rust derives the match independently.
    pub matched: bool,
}

/// Original router-lock reads preceding the nested Group call or rejection.
#[derive(Clone, Debug)]
pub struct Prefix {
    /// Caller identity shared by the Group child.
    pub caller: u64,
    /// Last complete metadata generation seen under the router lock.
    pub generation: u64,
    /// Actual sequential selector identity and invocation number.
    pub session: u64,
    /// Actual Next ordinal.
    pub next: u64,
    /// First or second routeOnce invocation of Next.
    pub attempt: u8,
    /// Router rule, checked against independent metadata.
    pub rule: Rule,
    /// Exact error equality class at the original observer-error branch.
    pub observer_error: ErrorClass,
    /// Full router group order; never an inventory seed.
    pub groups: Vec<u64>,
    /// Actual exclusion identities, checked against the retained selector.
    pub excluded: Vec<u64>,
    /// Whether the port branch was visited.
    pub port_visited: bool,
    /// Whether the detector existed at that branch.
    pub detector_present: bool,
    /// Listener read only when the detector exists.
    pub listener: Option<String>,
    /// Actual visited prefix with a distinct address read for every Group.
    pub reads: Vec<MatchRead>,
    /// Actual selected Group; zero on a router-only error/rejection.
    pub target: u64,
    /// Actual returned backend identity.
    pub backend: u64,
    /// Actual final routeOnce error class.
    pub error: ErrorClass,
}

/// Complete child path, owned by the same original parent lease.
#[derive(Clone, Debug)]
pub enum Path {
    /// Complete existing `GroupRoute` body; no independent commit is allowed.
    Group(Box<route::Envelope>),
    /// Original router-only `RouteRejected` batch.
    Rejected(Batch),
}

/// One complete router attempt. No production routing capability is installed.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Immutable owner identity.
    pub epoch: Epoch,
    /// First child sequence.
    pub sequence: u64,
    /// All children and the single final caller check.
    pub span: u64,
    /// Original router reads and final witnesses.
    pub prefix: Prefix,
    /// Exactly one complete Group or rejected path.
    pub path: Path,
}

impl Envelope {
    /// Bound all incoming values before using even a caller-supplied domain value.
    ///
    /// # Errors
    /// Identity, shape, ordering, string or population violations.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        let p = &self.prefix;
        if [
            self.epoch.process,
            self.epoch.owner,
            self.epoch.nonce,
            self.sequence,
            p.caller,
            p.session,
            p.next,
        ]
        .contains(&0)
            || !(1..=2).contains(&p.attempt)
            || (p.backend == 0) != (p.error != ErrorClass::None)
        {
            return Err(InvalidReason::Identity);
        }
        if p.generation == 0 && (!p.groups.is_empty() || !p.reads.is_empty()) {
            return Err(InvalidReason::Identity);
        }
        if p.groups.len() > 64 || p.excluded.len() > 64 || p.reads.len() > p.groups.len() {
            return Err(InvalidReason::Capacity);
        }
        for ids in [&p.groups, &p.excluded] {
            for (i, id) in ids.iter().enumerate() {
                if *id == 0 || ids[..i].contains(id) {
                    return Err(InvalidReason::Identity);
                }
            }
        }
        let mut strings = 0;
        for value in p
            .reads
            .iter()
            .filter_map(|r| r.address.as_ref())
            .chain(p.listener.iter())
        {
            if value.len() > 512 {
                return Err(InvalidReason::Capacity);
            }
            strings += value.len();
        }
        match &self.path {
            Path::Group(group) => {
                group.validate()?;
                if group.epoch != self.epoch
                    || group.sequence != self.sequence
                    || group.span != self.span
                    || group.route.group != p.target
                    || group.route.caller != p.caller
                    || group.route.session != p.session
                    || usize::from(group.route.excluded_count) != p.excluded.len()
                    || group.route.result.account != p.backend
                {
                    return Err(InvalidReason::Identity);
                }
                for read in &group.route.reads {
                    match read {
                        route::Read::BackendId { value, .. }
                        | route::Read::ExcludedId { value, .. } => strings += value.len(),
                        route::Read::Healthy { .. } => (),
                    }
                }
            }
            Path::Rejected(batch) => {
                if p.target != 0
                    || p.backend != 0
                    || self.span != 2
                    || batch.epoch != self.epoch
                    || batch.sequence != self.sequence
                    || batch.events.as_slice()
                        != [LiveEvent::RouteRejected {
                            session: p.session,
                            group: 0,
                        }]
                {
                    return Err(InvalidReason::Identity);
                }
            }
        }
        if strings > 64 << 10 {
            return Err(InvalidReason::Capacity);
        }
        Ok(())
    }
}

impl LiveState {
    /// Compare router classification, its complete child path and retained
    /// selector attempt atomically. A late Group/return mismatch cannot retain
    /// a factor update, reservation, selector change or compared sequence.
    #[must_use]
    pub fn observe_router_route(
        &mut self,
        envelope: &Envelope,
        frame_bytes: usize,
    ) -> (Progress, Option<DerivedResult>) {
        let expected = envelope
            .validate()
            .and_then(|()| self.derive_router_route(envelope.epoch, &envelope.prefix));
        let expected = match expected {
            Ok(expected) => expected,
            Err(reason) => return (self.invalidate(envelope.epoch, reason), None),
        };
        let p = &envelope.prefix;
        let previous = self.progress(envelope.epoch).compared_sequence;
        let prepared = self.begin_caller(Scope {
            epoch: envelope.epoch,
            group: p.target,
            sequence: envelope.sequence,
            span: envelope.span,
            sessions: &[p.session],
            frame_bytes,
        });
        match prepared {
            Ok(mut transaction) => {
                let comparison = match &envelope.path {
                    Path::Group(group) => transaction.compare_route(group),
                    Path::Rejected(batch) => transaction.batch(batch).map(|()| DerivedResult {
                        backend: 0,
                        error: expected.1,
                        binding: None,
                    }),
                }
                .and_then(|derived| {
                    if expected.0 != p.target
                        || derived.backend != p.backend
                        || derived.error != p.error
                    {
                        return Err(InvalidReason::Witness);
                    }
                    transaction.selector_attempt(
                        p.session,
                        p.next,
                        p.attempt,
                        &p.excluded,
                        derived,
                    )?;
                    Ok(derived)
                });
                let progress = transaction.finish(comparison.map(|_| ()));
                let derived = if progress.status == super::Status::Comparing {
                    comparison.ok()
                } else {
                    None
                };
                (progress, derived)
            }
            Err(reason) => (
                Progress {
                    status: super::Status::Invalid(reason),
                    compared_sequence: previous,
                    transition: None,
                },
                None,
            ),
        }
    }

    fn derive_router_route(
        &self,
        epoch: Epoch,
        p: &Prefix,
    ) -> Result<(u64, ErrorClass), InvalidReason> {
        let metadata = self
            .router_metadata(epoch)
            .ok_or(InvalidReason::MissingBegin)?;
        let (rule, observer_error) = metadata.route_header(p.generation)?;
        if rule != p.rule
            || observer_error != p.observer_error
            || metadata.known_groups()?.as_slice() != p.groups
        {
            return Err(InvalidReason::Witness);
        }
        if observer_error != ErrorClass::None {
            if !p.reads.is_empty() || p.port_visited || p.detector_present || p.listener.is_some() {
                return Err(InvalidReason::Witness);
            }
            return Ok((0, observer_error));
        }
        if rule == Rule::Port {
            if !p.port_visited
                || p.detector_present != metadata.detector_present()
                || !p.reads.is_empty()
            {
                return Err(InvalidReason::Witness);
            }
            if !metadata.detector_present() {
                if p.listener.is_some() {
                    return Err(InvalidReason::Witness);
                }
                return Ok((0, ErrorClass::NoBackend));
            }
            let listener = p.listener.as_deref().ok_or(InvalidReason::Witness)?;
            return match metadata.classify(p.generation, ClientInfo::default(), listener)? {
                Classification::Group(group) => Ok((group, ErrorClass::None)),
                Classification::NoGroup => Ok((0, ErrorClass::NoBackend)),
                Classification::Conflict => Ok((0, ErrorClass::Other)),
                Classification::ObserverError(_) => Err(InvalidReason::Witness),
            };
        }
        if p.port_visited || p.detector_present || p.listener.is_some() {
            return Err(InvalidReason::Witness);
        }
        for (i, id) in p.groups.iter().enumerate() {
            let read = p.reads.get(i).ok_or(InvalidReason::Witness)?;
            if read.group != *id || rule == Rule::All && read.address.is_some() {
                return Err(InvalidReason::Witness);
            }
            let address = read.address.as_deref();
            let client = ClientInfo {
                client_address: address,
                proxy_address: address,
            };
            let matches = metadata
                .matcher(*id)?
                .ok_or(InvalidReason::Identity)?
                .matches(client);
            if matches != read.matched {
                return Err(InvalidReason::Witness);
            }
            if matches {
                if p.reads.len() != i + 1 {
                    return Err(InvalidReason::Witness);
                }
                return Ok((*id, ErrorClass::None));
            }
        }
        if p.reads.len() != p.groups.len() {
            return Err(InvalidReason::Witness);
        }
        Ok((0, ErrorClass::NoBackend))
    }
}
