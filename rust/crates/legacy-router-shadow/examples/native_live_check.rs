// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Mixed actual Go factor and lifecycle frames through one contiguous mirror.
use control_router::shadow::{Limits, Status, live::LiveState};
use legacy_router_shadow::{live, native};
use std::{collections::BTreeSet, fs, io};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(std::env::args().nth(1).ok_or("capture path")?)?;
    let mut rest = bytes.as_slice();
    let mut state = LiveState::new(Limits::default());
    let mut evaluations = 0;
    let mut batches = 0;
    let mut epochs = BTreeSet::new();
    while !rest.is_empty() {
        let prefix: [u8; 4] = rest.get(..4).ok_or("prefix")?.try_into()?;
        let n = usize::try_from(u32::from_be_bytes(prefix))? + 4;
        let frame = rest.get(..n).ok_or("body")?;
        if let Some(epoch) = native::envelope(frame)? {
            match native::decode(frame, state.native_coverage(epoch).map(|c| c.origin))? {
                native::Frame::Coverage(c) => state
                    .install_native(c)
                    .map_err(|e| io::Error::other(format!("coverage {e:?}")))?,
                native::Frame::Evaluation(e) => {
                    let p = state.observe_native(&e, n * native::DECODE_MULTIPLIER);
                    evaluations += 1;
                    if p.status != Status::Comparing {
                        return Err(io::Error::other(format!("NATIVE_MIXED_COMPARISON evaluation={} sequence={} prefix={} status={:?}",e.evaluation,e.sequence,p.compared_sequence,p.status)).into());
                    }
                }
            }
        } else {
            match live::decode(frame)? {
                live::Frame::Coverage { .. } => (),
                live::Frame::Invalid { .. } => return Err("producer invalid".into()),
                live::Frame::Batch(batch) => {
                    epochs.insert(batch.epoch);
                    batches += 1;
                    let p = state.observe(&batch);
                    if !matches!(p.status, Status::Comparing | Status::CleanEnded) {
                        return Err(io::Error::other(format!(
                            "NATIVE_MIXED_COMPARISON batch sequence={} prefix={} status={:?}",
                            batch.sequence, p.compared_sequence, p.status
                        ))
                        .into());
                    }
                }
            }
        }
        rest = &rest[n..];
    }
    for epoch in epochs {
        if state.totals(epoch) != Some((0, 0)) {
            return Err("unsettled tail".into());
        }
    }
    println!(
        "NATIVE_MIXED_COMPARISON evaluations={evaluations} batches={batches} retained_bytes={} final_settled=true mismatch=0",
        state.native_retained_bytes()
    );
    Ok(())
}
