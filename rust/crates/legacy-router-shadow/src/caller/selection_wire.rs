// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{Decimal, Error};
use control_router::shadow::{
    Epoch,
    live::caller::selection::{Boundary, BoundaryEvent, ErrorClass},
};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
};

#[derive(Default)]
pub(super) struct Excluded(Vec<u64>);
impl<'de> Deserialize<'de> for Excluded {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Read;
        impl<'de> Visitor<'de> for Read {
            type Value = Excluded;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "at most 64 nonzero exclusion identities, preserving duplicates"
                )
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(Decimal(value)) = access.next_element()? {
                    if values.len() == 64 || value == 0 {
                        return Err(A::Error::custom("exclusion bound/identity"));
                    }
                    values.push(value);
                }
                Ok(Excluded(values))
            }
        }
        decoder.deserialize_seq(Read)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    session: Decimal,
    next: Decimal,
    current: Decimal,
    excluded: Excluded,
}
impl State {
    pub(super) fn domain(
        self,
        epoch: Epoch,
        sequence: u64,
        close: bool,
    ) -> Result<Boundary, Error> {
        let event = if close {
            BoundaryEvent::Close {
                next: self.next.0,
                current: self.current.0,
                excluded: self.excluded.0,
            }
        } else {
            BoundaryEvent::Begin {
                next: self.next.0,
                current: self.current.0,
                excluded: self.excluded.0,
            }
        };
        validated(Boundary {
            epoch,
            sequence,
            session: self.session.0,
            event,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct End {
    session: Decimal,
    next: Decimal,
    current: Decimal,
    excluded: Excluded,
    backend: Decimal,
    error: u8,
}
impl End {
    pub(super) fn domain(self, epoch: Epoch, sequence: u64) -> Result<Boundary, Error> {
        let error = match self.error {
            1 => ErrorClass::None,
            2 => ErrorClass::NoBackend,
            3 => ErrorClass::Other,
            _ => return Err(Error::Schema),
        };
        validated(Boundary {
            epoch,
            sequence,
            session: self.session.0,
            event: BoundaryEvent::End {
                next: self.next.0,
                current: self.current.0,
                excluded: self.excluded.0,
                backend: self.backend.0,
                error,
            },
        })
    }
}
fn validated(value: Boundary) -> Result<Boundary, Error> {
    value.validate().map_err(|_| Error::Schema)?;
    Ok(value)
}
