// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Validate actual Go capture without manually constructing domain events.
use control_router::shadow::{Limits, Status, live::LiveState};
use legacy_router_shadow::live::{self, Frame};
use std::{collections::BTreeSet, fs, io};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("capture path required")?;
    let data = fs::read(path)?;
    let mut rest = data.as_slice();
    let mut state = LiveState::new(Limits::default());
    let mut owners = BTreeSet::new();
    let (mut batches, mut events) = (0_u64, 0_u64);
    while !rest.is_empty() {
        let prefix: [u8; 4] = rest.get(..4).ok_or("short prefix")?.try_into()?;
        let size = usize::try_from(u32::from_be_bytes(prefix))? + 4;
        let frame = live::decode(rest.get(..size).ok_or("short frame")?)?;
        match frame {
            Frame::Batch(batch) => {
                owners.insert(batch.epoch);
                events += u64::try_from(batch.events.len())?;
                batches += 1;
                let progress = state.observe(&batch);
                if progress.status != Status::Comparing {
                    return Err(io::Error::other(format!("batch {batches}, sequence {}, compared {}, {:?}, events {:?}, witness {:?}",batch.sequence,progress.compared_sequence,progress.status,batch.events,batch.witness)).into());
                }
            }
            Frame::Coverage { .. } => {}
            Frame::Invalid { .. } => {
                return Err("unexpected invalid owner in positive capture".into());
            }
        }
        rest = &rest[size..];
    }
    let mut score = 0_u64;
    let mut physical = 0_u64;
    for epoch in &owners {
        let view = state.view(*epoch).ok_or("missing owner")?;
        for account in view.accounts {
            score += account.counts.score();
            physical += account.counts.active();
        }
    }
    println!(
        "lifecycle_only=true factors=false selection=false scheduler=false owners={} batches={batches} events={events} score={score} physical={physical} invalid=0 mismatch=0",
        owners.len()
    );
    Ok(())
}
