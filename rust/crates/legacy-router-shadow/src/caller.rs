// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Preparatory strict v4 router pass boundaries. This codec is deliberately not
//! selected by the existing v2/v3 consumer and confers no coverage capability.
mod balance_wire;
mod finish_wire;
mod route_wire;
mod router_route_wire;
mod selection_wire;
use crate::{Error, native::Decimal};
use control_router::shadow::{
    Epoch,
    live::caller::{
        Budget, MAX_CALLER_FRAME, balance, finish, metadata, pass, route, router_route, selection,
    },
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
    #[serde(rename = "router_route")]
    RouterRoute(router_route_wire::WireRouterRoute),
    #[serde(rename = "group_finish")]
    GroupFinish(finish_wire::WireFinish),
    #[serde(rename = "selector_begin")]
    SelectorBegin(selection_wire::State),
    #[serde(rename = "selector_end")]
    SelectorEnd(selection_wire::End),
    #[serde(rename = "selector_close")]
    SelectorClose(selection_wire::State),
    #[serde(rename = "group_balance")]
    GroupBalance(balance_wire::WireBalance),
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
    #[serde(rename = "metadata_init")]
    MetadataInit { raw_rule: String, rule: u8 },
    #[serde(rename = "metadata_begin")]
    MetadataBegin {
        generation: Decimal,
        observer_error: u8,
        rule: u8,
        inputs: Vec<MetadataInput>,
    },
    #[serde(rename = "metadata_assign")]
    MetadataAssign {
        generation: Decimal,
        index: u16,
        account: Decimal,
        group: Decimal,
        removed: bool,
        created: bool,
        values_read: bool,
        values: Vec<String>,
    },
    #[serde(rename = "metadata_refresh")]
    MetadataRefresh {
        generation: Decimal,
        group: Decimal,
        values_read: bool,
        members: Vec<MetadataMember>,
        values: Vec<String>,
        parsed: bool,
    },
    #[serde(rename = "metadata_end")]
    MetadataEnd {
        generation: Decimal,
        support_redirection: bool,
        groups: u16,
        created: u16,
        removed: u16,
        refresh_failed: u16,
        conflicts: u16,
    },
}
/// One member `Cidr()` read inside `RefreshCidr`, at its read site.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataMember {
    account: Decimal,
    values: Vec<String>,
}
/// One health-loop input; grouping values travel with the decision that read
/// them, and a nonzero account is the held-wrapper statement.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataInput {
    account: Decimal,
    healthy: bool,
    support_redirection: bool,
    present: bool,
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
        if let Payload::GroupBalance(value) = self.payload {
            return Ok(Frame::GroupBalance(value.domain(
                epoch,
                self.sequence.0,
                self.span.0,
                origin,
            )?));
        }
        if let Payload::RouterRoute(value) = self.payload {
            return Ok(Frame::RouterRoute(value.domain(
                epoch,
                self.sequence.0,
                self.span.0,
                origin,
            )?));
        }
        if let Payload::GroupRoute(value) = self.payload {
            let envelope = value.domain(epoch, self.sequence.0, self.span.0, origin)?;
            return Ok(Frame::GroupRoute(envelope));
        }
        if let Payload::GroupFinish(value) = self.payload {
            return Ok(Frame::Finish(value.domain(
                epoch,
                self.sequence.0,
                self.span.0,
            )?));
        }
        if self.span.0 != 1 {
            return Err(Error::Schema);
        }
        if let Some(event) = metadata_event(&self.payload)? {
            return Ok(Frame::Metadata(metadata::Boundary {
                epoch,
                sequence: self.sequence.0,
                event,
            }));
        }
        span_one_boundary(self.payload, epoch, self.sequence.0)
    }
}

/// Convert the remaining span-one payloads: selector boundaries and pass boundaries.
fn span_one_boundary(payload: Payload, epoch: Epoch, sequence: u64) -> Result<Frame, Error> {
    let event = match payload {
        Payload::SelectorBegin(value) => {
            return Ok(Frame::Selector(value.domain(epoch, sequence, false)?));
        }
        Payload::SelectorEnd(value) => {
            return Ok(Frame::Selector(value.domain(epoch, sequence)?));
        }
        Payload::SelectorClose(value) => {
            return Ok(Frame::Selector(value.domain(epoch, sequence, true)?));
        }
        Payload::RouterRoute(_)
        | Payload::GroupFinish(_)
        | Payload::GroupRoute(_)
        | Payload::GroupBalance(_)
        | Payload::MetadataInit { .. }
        | Payload::MetadataBegin { .. }
        | Payload::MetadataAssign { .. }
        | Payload::MetadataRefresh { .. }
        | Payload::MetadataEnd { .. } => {
            return Err(Error::Schema);
        }
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
        epoch,
        sequence,
        event,
    }))
}

/// A strictly decoded caller, still requiring its independent domain comparator.
#[allow(clippy::large_enum_variant)] // Bounded fixed pass storage is included in 32F + S.
pub enum Frame {
    /// Actual router reads with a complete atomic Group or rejected path.
    RouterRoute(router_route::Envelope),
    /// Actual Finish with its complete Created batch.
    Finish(finish::Envelope),
    /// Actual selector entry/return/end requiring retained-state comparison.
    Selector(selection::Boundary),
    /// Group Balance with its native evaluation and paired lifecycle batches.
    GroupBalance(balance::Envelope),
    /// Router pass boundary; independently derived inventory/gate required.
    Pass(pass::Boundary),
    /// Group Route with complete nested v3/v2 children.
    GroupRoute(route::Envelope),
    /// Router metadata refresh boundary; independently derived inventory required.
    Metadata(metadata::Boundary),
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
        Frame::RouterRoute(_)
        | Frame::Finish(_)
        | Frame::Selector(_)
        | Frame::GroupRoute(_)
        | Frame::GroupBalance(_)
        | Frame::Metadata(_) => Err(Error::Schema),
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
mod metadata_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod balance_tests;

/// Strict conversion of the four header-only metadata payloads. Bounds mirror
/// the Go capture: 64 backends, 256 values per frame, 512-byte strings, 64 KiB
/// aggregate, held == identified, and an observer error without inputs. The
/// domain validators are the single source of the shape rules.
fn metadata_event(payload: &Payload) -> Result<Option<metadata::Event>, Error> {
    let event = match payload {
        Payload::MetadataInit { raw_rule, rule } => {
            if raw_rule.len() > metadata::MAX_VALUE_BYTES {
                return Err(Error::Schema);
            }
            metadata::Event::Init(metadata::Init {
                raw_rule: raw_rule.clone(),
                rule: metadata::Rule::from_wire(*rule).ok_or(Error::Schema)?,
            })
        }
        Payload::MetadataBegin {
            generation,
            observer_error,
            rule,
            inputs,
        } => metadata::Event::Begin(metadata_begin(
            generation.0,
            *observer_error,
            *rule,
            inputs,
        )?),
        Payload::MetadataAssign {
            generation,
            index,
            account,
            group,
            removed,
            created,
            values_read,
            values,
        } => {
            let assign = metadata::Assign {
                generation: generation.0,
                index: *index,
                account: account.0,
                group: group.0,
                removed: *removed,
                created: *created,
                values_read: *values_read,
                values: values.clone(),
            };
            assign.validate().map_err(|_| Error::Schema)?;
            metadata::Event::Assign(assign)
        }
        Payload::MetadataRefresh {
            generation,
            group,
            values_read,
            members,
            values,
            parsed,
        } => {
            let refresh = metadata::Refresh {
                generation: generation.0,
                group: group.0,
                values_read: *values_read,
                members: members
                    .iter()
                    .map(|m| metadata::Member {
                        account: m.account.0,
                        values: m.values.clone(),
                    })
                    .collect(),
                values: values.clone(),
                parsed: *parsed,
            };
            refresh.validate().map_err(|_| Error::Schema)?;
            metadata::Event::Refresh(refresh)
        }
        Payload::MetadataEnd {
            generation,
            support_redirection,
            groups,
            created,
            removed,
            refresh_failed,
            conflicts,
        } => {
            if generation.0 == 0
                || usize::from(*groups) > metadata::MAX_GROUPS
                || usize::from(*created) > metadata::MAX_GROUPS
                || usize::from(*removed) > metadata::MAX_GROUPS
                || usize::from(*refresh_failed) > metadata::MAX_GROUPS
                || usize::from(*conflicts) > metadata::MAX_VALUES
            {
                return Err(Error::Schema);
            }
            metadata::Event::End(metadata::End {
                generation: generation.0,
                support_redirection: *support_redirection,
                groups: *groups,
                created: *created,
                removed: *removed,
                refresh_failed: *refresh_failed,
                conflicts: *conflicts,
            })
        }
        _ => return Ok(None),
    };
    Ok(Some(event))
}

fn metadata_begin(
    generation: u64,
    observer_error: u8,
    rule: u8,
    inputs: &[MetadataInput],
) -> Result<metadata::Begin, Error> {
    let observer_error = match observer_error {
        1 => selection::ErrorClass::None,
        2 => selection::ErrorClass::NoBackend,
        3 => selection::ErrorClass::Other,
        _ => return Err(Error::Schema),
    };
    let rule = metadata::Rule::from_wire(rule).ok_or(Error::Schema)?;
    if inputs.len() > metadata::MAX_BACKENDS {
        return Err(Error::Schema);
    }
    let begin = metadata::Begin {
        generation,
        observer_error,
        rule,
        inputs: inputs
            .iter()
            .map(|input| metadata::Input {
                account: input.account.0,
                healthy: input.healthy,
                support_redirection: input.support_redirection,
                present: input.present,
            })
            .collect(),
    };
    begin.validate().map_err(|_| Error::Schema)?;
    Ok(begin)
}
