// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{Decimal, Epoch, Error, Groups, Origin, route};
use crate::{live::NestedBatch, native::NestedEvaluation};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
};

struct Bounded<T, const N: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Values<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Values<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {N} caller values")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element()? {
                    if values.len() == N {
                        return Err(A::Error::custom("caller array bound"));
                    }
                    values.push(value);
                }
                Ok(Bounded(values))
            }
        }
        decoder.deserialize_seq(Values::<T, N>(std::marker::PhantomData))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum WireRead {
    Healthy {
        completed: u8,
        account: Decimal,
        value: bool,
    },
    BackendId {
        completed: u8,
        account: Decimal,
        value: String,
    },
    ExcludedId {
        completed: u8,
        index: u16,
        value: String,
    },
}
impl From<WireRead> for route::Read {
    fn from(read: WireRead) -> Self {
        match read {
            WireRead::Healthy {
                completed,
                account,
                value,
            } => Self::Healthy {
                completed,
                account: account.0,
                value,
            },
            WireRead::BackendId {
                completed,
                account,
                value,
            } => Self::BackendId {
                completed,
                account: account.0,
                value,
            },
            WireRead::ExcludedId {
                completed,
                index,
                value,
            } => Self::ExcludedId {
                completed,
                index,
                value,
            },
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultValue {
    account: Decimal,
    operation: Decimal,
    completed: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum WireChild {
    Evaluation(Box<NestedEvaluation>),
    Batch(NestedBatch),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRoute {
    caller: Decimal,
    group: Decimal,
    session: Decimal,
    excluded_count: u16,
    members: Groups,
    reads: Bounded<WireRead, 128>,
    result: ResultValue,
    children: Bounded<WireChild, 68>,
}
impl WireRoute {
    pub(super) fn domain(
        self,
        epoch: Epoch,
        sequence: u64,
        span: u64,
        origin: Option<Origin>,
    ) -> Result<route::Envelope, Error> {
        let mut children = Vec::with_capacity(self.children.0.len());
        for child in self.children.0 {
            children.push(match child {
                WireChild::Evaluation(e) => {
                    route::Child::Evaluation(Box::new(e.domain(origin.ok_or(Error::Schema)?)?))
                }
                WireChild::Batch(b) => route::Child::Batch(b.domain()?),
            });
        }
        let envelope = route::Envelope {
            epoch,
            sequence,
            span,
            route: route::Route {
                caller: self.caller.0,
                group: self.group.0,
                session: self.session.0,
                excluded_count: self.excluded_count,
                members: self.members.0.as_slice().to_vec(),
                reads: self.reads.0.into_iter().map(Into::into).collect(),
                result: route::ResultValue {
                    account: self.result.account.0,
                    operation: self.result.operation.0,
                    completed: self.result.completed,
                },
            },
            children,
        };
        envelope.validate().map_err(|_| Error::Schema)?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_wire_overlap_fits_reserved_fixed_allowance() {
        use control_router::shadow::live::native::STAGE_OVERHEAD;
        // Decoder vectors may round capacity up to the next power of two; both
        // wire and domain vectors are simultaneously live during conversion.
        let fixed = size_of::<WireRoute>()
            + 128 * (size_of::<WireChild>() + size_of::<route::Child>())
            + 256 * (size_of::<WireRead>() + size_of::<route::Read>())
            + 2 * 64 * size_of::<u64>()
            + 5 * size_of::<NestedEvaluation>();
        assert!(
            fixed < STAGE_OVERHEAD,
            "ROUTE_WIRE_DOMAIN_OVERLAP_ALLOWANCE"
        );
        eprintln!(
            "wire_route={} wire_child={} wire_read={} nested_eval={} fixed_overlap={fixed}",
            size_of::<WireRoute>(),
            size_of::<WireChild>(),
            size_of::<WireRead>(),
            size_of::<NestedEvaluation>()
        );
    }
}
