// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Replay actual Init, first health and complete router/selector calls.
use control_router::shadow::{
    Epoch, InvalidReason, Limits, Progress, Status,
    live::{
        LiveState,
        caller::{metadata::Event, selection::BoundaryEvent},
    },
};
use control_routing::go_time::Origin;
use legacy_router_shadow::caller::{self, Frame};
use serde_json::Value;
use std::{env, fs};
#[path = "support/route_prefix.rs"]
mod prefix;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Replay {
    state: LiveState,
    origin: Option<Origin>,
    owner: Option<Epoch>,
    counts: [usize; 9],
}
impl Replay {
    fn new() -> Self {
        Self {
            state: LiveState::new(Limits::default()),
            origin: None,
            owner: None,
            counts: [0; 9],
        }
    }
    fn frame(&mut self, bytes: &[u8]) -> Result<()> {
        let json: Value = serde_json::from_slice(&bytes[4..])?;
        if json["version"] != 4 {
            return prefix::observe_prefix(
                &mut self.state,
                bytes,
                &mut self.origin,
                &mut self.owner,
            );
        }
        let (progress, sequence) =
            match caller::decode_caller(bytes, self.origin, self.state.native_retained_bytes())? {
                Frame::Metadata(boundary) => {
                    match &boundary.event {
                        Event::Init(_) => self.counts[0] += 1,
                        Event::Begin(_) => self.counts[6] += 1,
                        Event::End(_) => self.counts[7] += 1,
                        _ => (),
                    }
                    (
                        self.state.observe_router_metadata(&boundary, bytes.len()),
                        boundary.sequence,
                    )
                }
                Frame::Selector(boundary) => {
                    let i = match boundary.event {
                        BoundaryEvent::Begin { .. } => 2,
                        BoundaryEvent::End { .. } => 3,
                        BoundaryEvent::Close { .. } => 4,
                    };
                    self.counts[i] += 1;
                    (
                        self.state.observe_selector_boundary(&boundary, bytes.len()),
                        boundary.sequence,
                    )
                }
                Frame::RouterRoute(route) => {
                    self.counts[1] += 1;
                    if route.prefix.generation == 0 {
                        self.counts[8] += 1;
                    }
                    let (p, derived) = self.state.observe_router_route(&route, bytes.len());
                    if p.status == Status::Comparing && derived.is_none() {
                        return Err("STARTUP_NO_DERIVATION".into());
                    }
                    (p, route.sequence + route.span - 1)
                }
                Frame::Finish(finish) => (
                    self.state.observe_selector_finish(&finish, bytes.len()),
                    finish.sequence + finish.span - 1,
                ),
                _ => return Err("STARTUP_WRONG_FAMILY".into()),
            };
        if json["payload"].get("group_finish").is_some() {
            self.counts[5] += 1;
        }
        check(progress, sequence)
    }
    fn finish(&self) -> Result<()> {
        let epoch = self.owner.ok_or("owner")?;
        if self.counts != [1, 7, 7, 7, 6, 1, 5, 5, 2]
            || !self.state.selectors_settled(epoch)
            || self.state.totals(epoch) != Some((0, 0))
            || self
                .state
                .router_metadata(epoch)
                .is_none_or(|m| m.tail().is_err())
        {
            return Err(format!("STARTUP_COUNTS_OR_TAIL {:?}", self.counts).into());
        }
        Ok(())
    }
}
fn check(p: Progress, seq: u64) -> Result<()> {
    if p.status != Status::Comparing || p.compared_sequence != seq {
        return Err(format!(
            "STARTUP_REJECTED status={:?} prefix={}",
            p.status, p.compared_sequence
        )
        .into());
    }
    Ok(())
}
fn split(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let head: [u8; 4] = bytes.get(at..at + 4).ok_or("prefix")?.try_into()?;
        let end = at
            .checked_add(4 + usize::try_from(u32::from_be_bytes(head))?)
            .ok_or("length")?;
        frames.push(bytes.get(at..end).ok_or("frame")?.to_vec());
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
fn replay(frames: &[Vec<u8>]) -> Result<()> {
    let mut r = Replay::new();
    for f in frames {
        r.frame(f)?;
    }
    r.finish()
}
fn strict(frames: &[Vec<u8>]) -> Result<usize> {
    let bytes = frames
        .iter()
        .find(|f| String::from_utf8_lossy(&f[4..]).contains("\"metadata_init\""))
        .ok_or("init")?;
    let original: Value = serde_json::from_slice(&bytes[4..])?;
    for which in 0..8 {
        let mut v = original.clone();
        let init = &mut v["payload"]["metadata_init"];
        match which {
            0 => {
                init.as_object_mut().ok_or("object")?.remove("raw_rule");
            }
            1 => {
                init.as_object_mut().ok_or("object")?.remove("rule");
            }
            2 => init["raw_rule"] = Value::String("x".repeat(513)),
            3 => init["rule"] = Value::from(0),
            4 => init["unexpected"] = Value::Bool(true),
            5 => init["raw_rule"] = Value::Null,
            6 => v["span"] = Value::String("2".into()),
            _ => v["payload"]["metadata_begin"] = serde_json::json!({}),
        }
        if caller::decode_caller(&encode(&v)?, None, 0).is_ok() {
            return Err(format!("STARTUP_STRICT_ACCEPTED {which}").into());
        }
    }
    println!("STARTUP_STRICT rejected=8");
    Ok(8)
}
fn corruptions(frames: &[Vec<u8>]) -> Result<usize> {
    for which in 0..4 {
        let mut changed = frames.to_vec();
        let mut found = false;
        let mut index = 0;
        for (position, bytes) in changed.iter_mut().enumerate() {
            let mut v: Value = serde_json::from_slice(&bytes[4..])?;
            if which == 0 && v["payload"].get("metadata_init").is_some() {
                let value = &mut v["payload"]["metadata_init"]["rule"];
                *value = Value::from(if *value == 1 { 4 } else { 1 });
                found = true;
            }
            if which == 1
                && v["payload"].get("router_route").is_some()
                && v["payload"]["router_route"]["generation"] == "0"
            {
                v["payload"]["router_route"]["observer_error"] = Value::from(2);
                found = true;
            }
            if which == 2
                && v["payload"].get("router_route").is_some()
                && v["payload"]["router_route"]["generation"] == "0"
            {
                let route = &mut v["payload"]["router_route"];
                if route["rule"] == 4 {
                    route["detector_present"] = Value::Bool(true);
                } else {
                    route["port_visited"] = Value::Bool(true);
                }
                found = true;
            }
            if which == 3
                && v["payload"].get("router_route").is_some()
                && v["payload"]["router_route"]["generation"] == "1"
            {
                v["payload"]["router_route"]["generation"] = Value::String("0".into());
                found = true;
            }
            if found {
                *bytes = encode(&v)?;
                index = position;
                break;
            }
        }
        if !found {
            return Err("STARTUP_MISSING_CORRUPTION_SITE".into());
        }
        let mut r = Replay::new();
        for bytes in &changed[..index] {
            r.frame(bytes)?;
        }
        if r.frame(&changed[index]).is_ok() {
            return Err(format!("STARTUP_CORRUPTION_ACCEPTED {which}").into());
        }
        println!("STARTUP_CORRUPTION {which} rejected");
    }
    Ok(4)
}
fn atomic(frames: &[Vec<u8>]) -> Result<()> {
    let mut r = Replay::new();
    for bytes in frames {
        let v: Value = serde_json::from_slice(&bytes[4..])?;
        if v["payload"].get("metadata_init").is_some() {
            let Frame::Metadata(mut boundary) =
                caller::decode_caller(bytes, r.origin, r.state.native_retained_bytes())?
            else {
                return Err("init".into());
            };
            let Event::Init(init) = &mut boundary.event else {
                return Err("init".into());
            };
            init.rule = if init.rule == control_router::shadow::live::caller::metadata::Rule::All {
                control_router::shadow::live::caller::metadata::Rule::Port
            } else {
                control_router::shadow::live::caller::metadata::Rule::All
            };
            let old = r.state.native_retained_bytes();
            let seq = r.state.progress(boundary.epoch).compared_sequence;
            let p = r.state.observe_router_metadata(&boundary, bytes.len());
            if p.status != Status::Invalid(InvalidReason::Witness)
                || p.compared_sequence != seq
                || r.state.native_retained_bytes() != old
                || r.state.router_metadata(boundary.epoch).is_some()
            {
                return Err("STARTUP_ATOMIC_FAILED".into());
            }
            println!("STARTUP_ATOMIC rejected prefix={seq} retained={old}");
            return Ok(());
        }
        r.frame(bytes)?;
    }
    Err("init absent".into())
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    let frames = split(&fs::read(args.get(1).ok_or("path")?)?)?;
    replay(&frames)?;
    let strict = strict(&frames)?;
    let corruptions = corruptions(&frames)?;
    atomic(&frames)?;
    println!(
        "STARTUP_INDEPENDENT frames={} strict={strict} corruptions={corruptions} atomic=1",
        frames.len()
    );
    Ok(())
}
