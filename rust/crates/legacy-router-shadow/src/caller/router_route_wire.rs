// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{
    Decimal, Epoch, Error, Groups, Origin, metadata,
    route_wire::{Bounded, WireRoute},
    router_route,
    selection::ErrorClass,
};
use crate::live::NestedBatch;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMatch {
    group: Decimal,
    address_read: bool,
    address: String,
    matched: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum WirePath {
    GroupRoute(Box<WireRoute>),
    Rejected(NestedBatch),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRouterRoute {
    caller: Decimal,
    generation: Decimal,
    session: Decimal,
    next: Decimal,
    attempt: u8,
    rule: u8,
    observer_error: u8,
    groups: Groups,
    excluded: Groups,
    port_visited: bool,
    detector_present: bool,
    listener: String,
    reads: Bounded<WireMatch, 64>,
    target: Decimal,
    backend: Decimal,
    error: u8,
    path: WirePath,
}

fn error_class(value: u8) -> Result<ErrorClass, Error> {
    match value {
        1 => Ok(ErrorClass::None),
        2 => Ok(ErrorClass::NoBackend),
        3 => Ok(ErrorClass::Other),
        _ => Err(Error::Schema),
    }
}

impl WireRouterRoute {
    pub(super) fn domain(
        self,
        epoch: Epoch,
        sequence: u64,
        span: u64,
        origin: Option<Origin>,
    ) -> Result<router_route::Envelope, Error> {
        if !self.detector_present && !self.listener.is_empty() {
            return Err(Error::Schema);
        }
        let mut reads = Vec::with_capacity(self.reads.0.len());
        for read in self.reads.0 {
            if !read.address_read && !read.address.is_empty() {
                return Err(Error::Schema);
            }
            reads.push(router_route::MatchRead {
                group: read.group.0,
                address: read.address_read.then_some(read.address),
                matched: read.matched,
            });
        }
        let envelope = router_route::Envelope {
            epoch,
            sequence,
            span,
            prefix: router_route::Prefix {
                caller: self.caller.0,
                generation: self.generation.0,
                session: self.session.0,
                next: self.next.0,
                attempt: self.attempt,
                rule: metadata::Rule::from_wire(self.rule).ok_or(Error::Schema)?,
                observer_error: error_class(self.observer_error)?,
                groups: self.groups.0.as_slice().to_vec(),
                excluded: self.excluded.0.as_slice().to_vec(),
                port_visited: self.port_visited,
                detector_present: self.detector_present,
                listener: self.detector_present.then_some(self.listener),
                reads,
                target: self.target.0,
                backend: self.backend.0,
                error: error_class(self.error)?,
            },
            path: match self.path {
                WirePath::GroupRoute(group) => router_route::Path::Group(Box::new(
                    group.domain(epoch, sequence, span, origin)?,
                )),
                WirePath::Rejected(batch) => router_route::Path::Rejected(batch.domain()?),
            },
        };
        envelope.validate().map_err(|_| Error::Schema)?;
        Ok(envelope)
    }
}
