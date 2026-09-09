// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Preparatory strict v4 router pass boundaries. This codec is deliberately not
//! selected by the existing v2/v3 consumer and confers no coverage capability.
mod route_wire;
use crate::{Error, native::Decimal};
use control_router::shadow::{
    Epoch,
    live::caller::{Budget, MAX_CALLER_FRAME, pass, route},
};
use control_routing::go_time::Origin;
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
};

#[derive(Deserialize)]
enum Kind {
    #[serde(rename = "caller")]
    Caller,
}

struct Groups(pass::Groups);
impl<'de> Deserialize<'de> for Groups {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct GroupVisitor;
        impl<'de> Visitor<'de> for GroupVisitor {
            type Value = Groups;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most 64 distinct nonzero group identities")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut ids = [0; pass::MAX_GROUPS];
                let mut len = 0;
                while let Some(Decimal(id)) = access.next_element()? {
                    if len == ids.len() {
                        return Err(A::Error::custom("group bound"));
                    }
                    if id == 0 || ids[..len].contains(&id) {
                        return Err(A::Error::custom("group identity"));
                    }
                    ids[len] = id;
                    len += 1;
                }
                pass::Groups::new(&ids[..len])
                    .map(Groups)
                    .map_err(|_| A::Error::custom("group identity"))
            }
        }
        decoder.deserialize_seq(GroupVisitor)
    }
}

// External tagging decodes directly into the selected typed variant, without a
// generic JSON tree or untagged retries. Missing/duplicate/unknown fields fail.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::large_enum_variant)] // The full fixed variant is included in the decode budget.
enum Payload {
    #[serde(rename = "group_route")]
    GroupRoute(route_wire::WireRoute),
    #[serde(rename = "pass_begin")]
    Begin {
        pass: Decimal,
        support_redirection: bool,
        groups: Groups,
    },
    #[serde(rename = "pass_end")]
    End {
        pass: Decimal,
        balanced: u16,
        closed: u16,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    kind: Kind,
    process: Decimal,
    owner: Decimal,
    nonce: Decimal,
    sequence: Decimal,
    span: Decimal,
    payload: Payload,
}
impl Wire {
    fn domain(self, origin: Option<Origin>) -> Result<Frame, Error> {
        let Kind::Caller = self.kind;
        if self.version != 4 {
            return Err(Error::Version);
        }
        if [self.process.0, self.owner.0, self.nonce.0, self.sequence.0].contains(&0)
            || self.span.0 == 0
        {
            return Err(Error::Schema);
        }
        let epoch = Epoch {
            process: self.process.0,
            owner: self.owner.0,
            nonce: self.nonce.0,
        };
        if let Payload::GroupRoute(value) = self.payload {
            let envelope = value.domain(epoch, self.sequence.0, self.span.0, origin)?;
            return Ok(Frame::GroupRoute(envelope));
        }
        if self.span.0 != 1 {
            return Err(Error::Schema);
        }
        let event = match self.payload {
            Payload::GroupRoute(_) => return Err(Error::Schema),
            Payload::Begin {
                pass,
                support_redirection,
                groups,
            } => {
                if pass.0 == 0 {
                    return Err(Error::Schema);
                }
                pass::Event::Begin(pass::Begin {
                    pass: pass.0,
                    support_redirection,
                    groups: groups.0,
                })
            }
            Payload::End {
                pass,
                balanced,
                closed,
            } => {
                if pass.0 == 0
                    || usize::from(balanced) > pass::MAX_GROUPS
                    || usize::from(closed) > pass::MAX_GROUPS
                {
                    return Err(Error::Schema);
                }
                pass::Event::End(pass::End {
                    pass: pass.0,
                    balanced,
                    closed,
                })
            }
        };
        Ok(Frame::Pass(pass::Boundary {
            epoch: Epoch {
                process: self.process.0,
                owner: self.owner.0,
                nonce: self.nonce.0,
            },
            sequence: self.sequence.0,
            event,
        }))
    }
}

/// A strictly decoded caller, still requiring its independent domain comparator.
#[allow(clippy::large_enum_variant)] // Bounded fixed pass storage is included in 32F + S.
pub enum Frame {
    /// Router pass boundary; independently derived inventory/gate required.
    Pass(pass::Boundary),
    /// Group Route with complete nested v3/v2 children.
    GroupRoute(route::Envelope),
}

/// Reserve BEFORE allocating an incoming body. `frame_bytes` includes the four
/// prefix bytes; R must include all simultaneously retained caller/pass history.
/// The complete caller composition will separately admit its affected clones.
///
/// # Errors
/// Rejects the prefix-inclusive frame ceiling and combined 32F + R + S budget.
pub fn admission(frame_bytes: usize, retained: usize) -> Result<Budget, Error> {
    if frame_bytes > MAX_CALLER_FRAME {
        return Err(Error::Oversized);
    }
    if frame_bytes < 5 {
        return Err(Error::Framing);
    }
    Budget::new(frame_bytes, retained, 0).map_err(|_| Error::Capacity)
}

/// Decode one complete pass boundary after transport admission. Checks the
/// admission again before parsing; does not commit any domain state or prefix.
///
/// # Errors
/// Rejects bad framing, strict schema violations or exceeded shared budgets.
pub fn decode(frame: &[u8], retained: usize) -> Result<pass::Boundary, Error> {
    match decode_caller(frame, None, retained)? {
        Frame::Pass(pass) => Ok(pass),
        Frame::GroupRoute(_) => Err(Error::Schema),
    }
}

/// Decode a complete caller; native children require the already accepted Go origin.
///
/// # Errors
/// Rejects malformed bounded values, foreign/non-contiguous children and admission failure.
pub fn decode_caller(
    frame: &[u8],
    origin: Option<Origin>,
    retained: usize,
) -> Result<Frame, Error> {
    admission(frame.len(), retained)?;
    let prefix: [u8; 4] = frame[..4].try_into().map_err(|_| Error::Framing)?;
    let body = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Oversized)?;
    if body > MAX_CALLER_FRAME - 4 {
        return Err(Error::Oversized);
    }
    if body == 0 || body != frame.len() - 4 {
        return Err(Error::Framing);
    }
    serde_json::from_slice::<Wire>(&frame[4..])
        .map_err(|_| Error::Schema)?
        .domain(origin)
}

#[cfg(test)]
mod tests;
