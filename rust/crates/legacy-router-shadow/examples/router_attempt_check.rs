// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Real raw router reads, Group children and selector lifecycle in one replay.
use control_router::shadow::{
    Epoch, InvalidReason, Limits, Progress, Status,
    live::{LiveState, caller::selection::BoundaryEvent},
};
use control_routing::go_time::Origin;
use legacy_router_shadow::caller::{self, Frame};
use serde::Deserialize;
use serde_json::Value;
use std::{env, fs};
#[path = "support/route_prefix.rs"]
mod prefix;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
struct Version {
    version: u32,
}
struct Replay {
    state: LiveState,
    origin: Option<Origin>,
    owner: Option<Epoch>,
    counts: [usize; 5],
}
impl Replay {
    fn new() -> Self {
        Self {
            state: LiveState::new(Limits::default()),
            origin: None,
            owner: None,
            counts: [0; 5],
        }
    }
    fn frame(&mut self, bytes: &[u8]) -> Result<()> {
        let version: Version = serde_json::from_slice(bytes.get(4..).ok_or("framing")?)?;
        if version.version != 4 {
            return prefix::observe_prefix(
                &mut self.state,
                bytes,
                &mut self.origin,
                &mut self.owner,
            );
        }
        let frame = caller::decode_caller(bytes, self.origin, self.state.native_retained_bytes())?;
        let (progress, sequence) = match frame {
            Frame::Metadata(boundary) => (
                self.state.observe_router_metadata(&boundary, bytes.len()),
                boundary.sequence,
            ),
            Frame::Selector(boundary) => {
                let index = match boundary.event {
                    BoundaryEvent::Begin { .. } => 1,
                    BoundaryEvent::End { .. } => 2,
                    BoundaryEvent::Close { .. } => 3,
                };
                self.counts[index] += 1;
                (
                    self.state.observe_selector_boundary(&boundary, bytes.len()),
                    boundary.sequence,
                )
            }
            Frame::RouterRoute(route) => {
                self.counts[0] += 1;
                let (progress, derived) = self.state.observe_router_route(&route, bytes.len());
                if progress.status == Status::Comparing && derived.is_none() {
                    return Err("ROUTER_ATTEMPT_MISSING_DERIVATION".into());
                }
                (progress, route.sequence + route.span - 1)
            }
            Frame::Finish(finish) => {
                self.counts[4] += 1;
                (
                    self.state.observe_selector_finish(&finish, bytes.len()),
                    finish.sequence + finish.span - 1,
                )
            }
            _ => return Err("ROUTER_ATTEMPT_DOWNGRADED_FAMILY".into()),
        };
        check(progress, sequence)
    }
    fn finish(&self, scenario: &str) -> Result<()> {
        let expected = match scenario {
            "all" => [6, 5, 5, 3, 3],
            "cidr" | "proxy" => [7, 7, 7, 7, 3],
            "port" => [4, 4, 4, 4, 1],
            _ => return Err("scenario".into()),
        };
        let owner = self.owner.ok_or("owner")?;
        if self.counts != expected
            || !self.state.selectors_settled(owner)
            || self.state.totals(owner) != Some((0, 0))
            || self
                .state
                .router_metadata(owner)
                .is_none_or(|m| m.tail().is_err())
        {
            return Err(format!("ROUTER_ATTEMPT_UNSETTLED counts={:?}", self.counts).into());
        }
        Ok(())
    }
}
fn check(progress: Progress, sequence: u64) -> Result<()> {
    if progress.status != Status::Comparing || progress.compared_sequence != sequence {
        return Err(format!(
            "ROUTER_ATTEMPT_REJECTED status={:?} prefix={}",
            progress.status, progress.compared_sequence
        )
        .into());
    }
    Ok(())
}
fn split(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let prefix: [u8; 4] = bytes.get(at..at + 4).ok_or("framing")?.try_into()?;
        let end = at
            .checked_add(4 + usize::try_from(u32::from_be_bytes(prefix))?)
            .ok_or("framing")?;
        frames.push(bytes.get(at..end).ok_or("framing")?.to_vec());
        at = end;
    }
    Ok(frames)
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    let mut frame = u32::try_from(body.len())?.to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}
fn replay(frames: &[Vec<u8>], scenario: &str) -> Result<()> {
    let mut state = Replay::new();
    for frame in frames {
        state.frame(frame)?;
    }
    state.finish(scenario)
}

// The first successful actual attempt has a valid factor computation and real
// reservation. Change only the final selector ordinal, after both were staged.
fn late_rollback(frames: &[Vec<u8>]) -> Result<()> {
    let mut replay = Replay::new();
    for bytes in frames {
        let body: Value = serde_json::from_slice(&bytes[4..])?;
        if body["payload"]
            .get("router_route")
            .is_some_and(|r| r["backend"] != "0")
        {
            let Frame::RouterRoute(mut route) =
                caller::decode_caller(bytes, replay.origin, replay.state.native_retained_bytes())?
            else {
                return Err("family".into());
            };
            let old_prefix = replay.state.progress(route.epoch).compared_sequence;
            let retained = replay.state.native_retained_bytes();
            let mut view = replay.state.view(route.epoch).ok_or("view")?;
            let generation = replay
                .state
                .router_metadata(route.epoch)
                .ok_or("metadata")?
                .generation();
            route.prefix.next += 1;
            let (progress, derived) = replay.state.observe_router_route(&route, bytes.len());
            view.status = Status::Invalid(InvalidReason::Identity);
            if progress.status != view.status
                || progress.compared_sequence != old_prefix
                || derived.is_some()
                || replay.state.native_retained_bytes() != retained
                || replay.state.view(route.epoch) != Some(view)
                || replay
                    .state
                    .router_metadata(route.epoch)
                    .ok_or("metadata")?
                    .generation()
                    != generation
            {
                return Err("ROUTER_ATTEMPT_LATE_ROLLBACK_FAILED".into());
            }
            println!(
                "ROUTER_ATTEMPT_ATOMIC late-next rejected prefix={old_prefix} retained={retained}"
            );
            return Ok(());
        }
        replay.frame(bytes)?;
    }
    Err("ROUTER_ATTEMPT_NO_SUCCESS_PROBE".into())
}

fn strict_schema(frames: &[Vec<u8>]) -> Result<usize> {
    let first = frames
        .iter()
        .find(|frame| String::from_utf8_lossy(&frame[4..]).contains("\"router_route\""))
        .ok_or("no router frame")?;
    let original: Value = serde_json::from_slice(&first[4..])?;
    // No origin is required by the rejected path; Group paths use the actual
    // origin obtained from the prelude, including native time decoding.
    let mut prelude = Replay::new();
    for frame in frames {
        if std::ptr::eq(frame, first) {
            break;
        }
        prelude.frame(frame)?;
    }
    for key in [
        "generation",
        "observer_error",
        "port_visited",
        "detector_present",
        "listener",
        "reads",
        "path",
    ] {
        let mut value = original.clone();
        value["payload"]["router_route"]
            .as_object_mut()
            .ok_or("object")?
            .remove(key);
        if caller::decode_caller(&encode(&value)?, prelude.origin, 0).is_ok() {
            return Err(format!("ROUTER_ATTEMPT_SCHEMA_MISSING {key}").into());
        }
    }
    let mut unknown = original.clone();
    unknown["payload"]["router_route"]["unknown"] = Value::Bool(true);
    if caller::decode_caller(&encode(&unknown)?, prelude.origin, 0).is_ok()
        || caller::decode(first, 0).is_ok()
    {
        return Err("ROUTER_ATTEMPT_SCHEMA_DOWNGRADE".into());
    }
    println!("ROUTER_ATTEMPT_STRICT rejected=9");
    Ok(9)
}
fn corruptions(frames: &[Vec<u8>], scenario: &str) -> Result<usize> {
    let at = frames
        .iter()
        .position(|frame| String::from_utf8_lossy(&frame[4..]).contains("\"router_route\""))
        .ok_or("router")?;
    for (name, key, value) in [
        ("generation", "generation", Value::String("99999".into())),
        ("late-next", "next", Value::String("99999".into())),
        (
            "rule",
            "rule",
            Value::from(if scenario == "port" { 1 } else { 4 }),
        ),
    ] {
        let mut copy = frames.to_vec();
        let mut body: Value = serde_json::from_slice(&copy[at][4..])?;
        body["payload"]["router_route"][key] = value;
        copy[at] = encode(&body)?;
        match replay(&copy, scenario) {
            Err(e) if e.to_string().starts_with("ROUTER_ATTEMPT_REJECTED") => {
                println!("ROUTER_ATTEMPT_CORRUPTION {name} rejected");
            }
            other => {
                return Err(
                    format!("ROUTER_ATTEMPT_CORRUPTION_UNEXPECTED {name}: {other:?}").into(),
                );
            }
        }
    }
    Ok(3)
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, path, scenario] = args.as_slice() else {
        return Err("usage: router_attempt_check <frames> <all|cidr|proxy|port>".into());
    };
    let frames = split(&fs::read(path)?)?;
    replay(&frames, scenario)?;
    late_rollback(&frames)?;
    let strict = strict_schema(&frames)?;
    let corruptions = corruptions(&frames, scenario)?;
    println!(
        "ROUTER_ATTEMPT_INDEPENDENT scenario={scenario} frames={} strict={strict} corruptions={corruptions}",
        frames.len()
    );
    Ok(())
}
