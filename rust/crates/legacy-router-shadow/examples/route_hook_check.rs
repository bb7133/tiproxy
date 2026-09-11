// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixture-only replay of a complete stream exported by real Go Group.Route.
//! Production v2/v3 dispatch and installed caller capabilities remain unchanged.
use control_router::shadow::{InvalidReason, Limits, Status, live::LiveState};
use legacy_router_shadow::caller;
#[path = "support/route_prefix.rs"]
mod prefix;
use prefix::observe_prefix;
use serde::Deserialize;
use std::{fs, io};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Version {
    version: u32,
}

fn replay(bytes: &[u8], corrupt: bool) -> Result<()> {
    let mut rest = bytes;
    let mut state = LiveState::new(Limits::default());
    let mut origin = None;
    let mut owner = None;
    let mut callers = 0;
    let mut selected = 0;
    let mut zero = 0;
    while !rest.is_empty() {
        let prefix: [u8; 4] = rest.get(..4).ok_or("prefix")?.try_into()?;
        let n = usize::try_from(u32::from_be_bytes(prefix))? + 4;
        let frame = rest.get(..n).ok_or("body")?;
        let version: Version = serde_json::from_slice(&frame[4..])?;
        if version.version == 4 {
            let caller::Frame::GroupRoute(mut e) =
                caller::decode_caller(frame, origin, state.native_retained_bytes())?
            else {
                return Err("unexpected caller family".into());
            };
            callers += 1;
            if e.route.result.account != 0 {
                selected += 1;
            } else {
                zero += 1;
            }
            let mut before = state.view(e.epoch);
            let native_before = state.native_retained_bytes();
            let inject = corrupt && e.route.result.account != 0;
            if inject {
                // Native inputs and every lifecycle child remain correct. Only
                // the final result is wrong, after the staged children execute.
                e.route.result.completed += 1;
            }
            let p = state.observe_group_route(&e, n);
            if inject {
                // Invalidation is intentionally visible; every ledger value,
                // factor lifetime and compared boundary must stay unchanged.
                before.as_mut().ok_or("missing baseline")?.status =
                    Status::Invalid(InvalidReason::Witness);
                if p.status != Status::Invalid(InvalidReason::Witness)
                    || p.compared_sequence != e.sequence - 1
                    || state.view(e.epoch) != before
                    || state.native_retained_bytes() != native_before
                {
                    return Err(io::Error::other(format!(
                        "ROUTE_HOOK_ATOMIC_ROLLBACK progress={p:?} before={before:?} after={:?}",
                        state.view(e.epoch)
                    ))
                    .into());
                }
                println!("ROUTE_HOOK_ATOMIC_ROLLBACK pass=true");
                return Ok(());
            }
            if p.status != Status::Comparing || p.compared_sequence != e.sequence + e.span - 1 {
                return Err(io::Error::other(format!(
                    "ROUTE_HOOK_INDEPENDENT sequence={} status={:?}",
                    e.sequence, p.status
                ))
                .into());
            }
        } else {
            observe_prefix(&mut state, frame, &mut origin, &mut owner)?;
        }
        rest = &rest[n..];
    }
    if corrupt || (callers, selected, zero) != (4, 2, 2) {
        return Err("ROUTE_HOOK_ACTUAL_POPULATION".into());
    }
    if state.totals(owner.ok_or("owner")?) != Some((0, 0)) {
        return Err("ROUTE_HOOK_UNSETTLED_TAIL".into());
    }
    println!(
        "ROUTE_HOOK_INDEPENDENT callers={callers} selected={selected} zero={zero} mismatch=0 settled=true"
    );
    Ok(())
}

fn main() -> Result<()> {
    let bytes = fs::read(std::env::args().nth(1).ok_or("capture path")?)?;
    replay(&bytes, false)?;
    replay(&bytes, true)
}
