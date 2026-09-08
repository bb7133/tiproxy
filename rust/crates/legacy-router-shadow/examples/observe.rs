// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Consume a bounded, test-owned Go lifecycle journal and print mirror observations.
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

use control_router::shadow::{Counts, Limits, ShadowState, Status};
use legacy_router_shadow::{MAX_FRAME_BYTES, decode};

fn ids(values: &[u64]) -> String {
    if values.is_empty() {
        "-".into()
    } else {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("expected one owned journal path")?;
    let mut reader = BufReader::new(File::open(path)?);
    let mut shadow = ShadowState::new(Limits::default());
    while !reader.fill_buf()?.is_empty() {
        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix)?;
        let len = usize::try_from(u32::from_be_bytes(prefix))?;
        if len > MAX_FRAME_BYTES {
            return Err("oversized journal frame".into());
        }
        let mut frame = vec![0; len + 4];
        frame[..4].copy_from_slice(&prefix);
        reader.read_exact(&mut frame[4..])?;
        let observation = decode(&frame)?;
        let progress = shadow.observe(&observation);
        if matches!(progress.status, Status::Invalid(_) | Status::Disabled) {
            return Err(format!(
                "SHADOW_GO_LIFECYCLE owner={} seq={} {progress:?}",
                observation.epoch.owner, observation.sequence
            )
            .into());
        }
        let view = shadow
            .view(observation.epoch)
            .ok_or("missing mirror owner")?;
        if !view.lifecycle_only {
            return Err("lifecycle fixture cannot qualify full routing shadow".into());
        }
        print!("{}\t{}", observation.epoch.owner, observation.sequence);
        for id in 1..=2 {
            let account = view.accounts.iter().find(|a| a.id == id);
            let counts = account.map_or(Counts::default(), |a| a.counts);
            let physical = account.map_or_else(|| "-".into(), |a| ids(&a.physical_order));
            print!("\t{}\t{}\t{}", counts.score(), counts.active(), physical);
        }
        println!("\t{}\t{}", ids(&view.pending_redirects), ids(&view.closing));
    }
    let complete = shadow.lifecycle_trace_complete();
    shadow.transport_lost();
    if !complete {
        return Err("SHADOW_UNSEALED_EOF".into());
    }
    Ok(())
}
