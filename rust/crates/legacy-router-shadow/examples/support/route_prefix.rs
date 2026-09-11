// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use control_router::shadow::{Status, live::LiveState};
use legacy_router_shadow::{live, native};
use std::io;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn observe_prefix(
    state: &mut LiveState,
    frame: &[u8],
    origin: &mut Option<control_routing::go_time::Origin>,
    owner: &mut Option<control_router::shadow::Epoch>,
) -> Result<()> {
    let progress = if let Some(epoch) = native::envelope(frame)? {
        match native::decode(frame, state.native_coverage(epoch).map(|c| c.origin))? {
            native::Frame::Coverage(c) => {
                if owner.is_some_and(|old| old != c.epoch) {
                    return Err("fixture expects one owner".into());
                }
                *origin = Some(c.origin);
                *owner = Some(c.epoch);
                state
                    .install_native(c)
                    .map_err(|e| io::Error::other(format!("coverage {e:?}")))?;
                return Ok(());
            }
            native::Frame::Evaluation(e) => state.observe_router_metadata_native(&e, frame.len()),
        }
    } else {
        match live::decode(frame)? {
            live::Frame::Coverage { .. } => return Ok(()),
            live::Frame::Invalid { .. } => return Err("producer invalid".into()),
            live::Frame::Batch(batch) => state.observe_router_metadata_batch(&batch, frame.len()),
        }
    };
    if !matches!(progress.status, Status::Comparing | Status::CleanEnded) {
        return Err(
            io::Error::other(format!("ROUTE_HOOK_ORIGINAL_PREFIX {:?}", progress.status)).into(),
        );
    }
    Ok(())
}
