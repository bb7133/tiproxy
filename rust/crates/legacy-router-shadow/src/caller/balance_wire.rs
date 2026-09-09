// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{Decimal, Epoch, Error, Groups, Origin, balance, route_wire::Bounded};
use crate::{
    live::NestedBatch,
    native::{NestedEvaluation, WireTime},
};
use serde::{Deserialize, Deserializer};

// A missing nullable field is malformed; only an explicit null means no read.
fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireClock {
    now: WireTime,
    from_keyspace: String,
    to_keyspace: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRedirect {
    from_keyspace: String,
    to_keyspace: String,
    #[serde(deserialize_with = "required")]
    callback: Option<bool>,
    batch: NestedBatch,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVisit {
    session: Decimal,
    #[serde(deserialize_with = "required")]
    redirect: Option<WireRedirect>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireBalance {
    caller: Decimal,
    group: Decimal,
    members: Groups,
    evaluation: Box<NestedEvaluation>,
    #[serde(deserialize_with = "required")]
    clock: Option<WireClock>,
    contexts: Bounded<bool, 65>,
    visits: Bounded<WireVisit, 64>,
    accepted: u16,
}
impl WireBalance {
    pub(super) fn domain(
        self,
        epoch: Epoch,
        sequence: u64,
        span: u64,
        origin: Option<Origin>,
    ) -> Result<balance::Envelope, Error> {
        let origin = origin.ok_or(Error::Schema)?;
        let clock = match self.clock {
            Some(clock) => Some(balance::Clock {
                now: clock.now.domain(origin)?,
                from_keyspace: clock.from_keyspace,
                to_keyspace: clock.to_keyspace,
            }),
            None => None,
        };
        let mut visits = Vec::with_capacity(self.visits.0.len());
        for visit in self.visits.0 {
            visits.push(balance::Visit {
                session: visit.session.0,
                redirect: match visit.redirect {
                    Some(r) => Some(balance::Redirect {
                        from_keyspace: r.from_keyspace,
                        to_keyspace: r.to_keyspace,
                        callback: r.callback,
                        batch: r.batch.domain()?,
                    }),
                    None => None,
                },
            });
        }
        let envelope = balance::Envelope {
            epoch,
            sequence,
            span,
            caller: self.caller.0,
            group: self.group.0,
            members: self.members.0.as_slice().to_vec(),
            evaluation: Box::new(self.evaluation.domain(origin)?),
            clock,
            contexts: self.contexts.0,
            visits,
            accepted: self.accepted,
        };
        envelope.validate().map_err(|_| Error::Schema)?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn balance_wire_and_domain_overlap_is_charged() {
        use control_router::shadow::live::native::STAGE_OVERHEAD;
        let fixed = size_of::<super::super::Wire>()
            + size_of::<balance::Envelope>()
            + 2 * size_of::<NestedEvaluation>()
            + 128 * (size_of::<WireVisit>() + size_of::<balance::Visit>())
            + 2 * 128 * size_of::<bool>()
            + 2 * 64 * size_of::<u64>();
        assert!(fixed < STAGE_OVERHEAD, "BALANCE_CODEC_OVERLAP_CHARGED");
        eprintln!(
            "wire_balance={} wire_visit={} domain_visit={} fixed_overlap={fixed}",
            size_of::<WireBalance>(),
            size_of::<WireVisit>(),
            size_of::<balance::Visit>()
        );
    }
}
