// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Actual Go factor frames through the strict codec and independent factor core.
//! This fixture does not qualify lifecycle, selection or scheduler composition.
use control_router::shadow::native::FactorState;
use legacy_router_shadow::native::{self, Frame};
use std::{fs, io};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("capture path required")?;
    let bytes = fs::read(path)?;
    let mut rest = bytes.as_slice();
    let mut origin = None;
    let mut state = None;
    let mut evaluations = 0;
    while !rest.is_empty() {
        let prefix: [u8; 4] = rest.get(..4).ok_or("prefix")?.try_into()?;
        let n = usize::try_from(u32::from_be_bytes(prefix))? + 4;
        match native::decode(rest.get(..n).ok_or("body")?, origin)? {
            Frame::Coverage(c) => {
                if state.is_some() {
                    return Err("duplicate coverage".into());
                }
                origin = Some(c.origin);
                state = Some(FactorState::new(c));
            }
            Frame::Evaluation(e) => {
                evaluations += 1;
                state.as_mut().ok_or("missing coverage")?.apply(&e).map_err(|error|io::Error::other(format!("NATIVE_FACTOR_COMPARISON evaluation={} entry={:?} error={error:?} capture={e:?}",e.evaluation,e.entry)))?;
            }
        }
        rest = &rest[n..];
    }
    println!(
        "NATIVE_FACTOR_COMPARISON evaluations={evaluations} mismatches=0; fixture only, no lifecycle qualification"
    );
    Ok(())
}
