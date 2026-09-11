// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Actual Go Next/Finish oracle for the pure selector component only. Controlled
//! attempt inputs here are not native routing or metadata qualification.
use control_router::shadow::live::caller::selection::{
    Binding, Continue, DerivedResult, ErrorClass, Tracker,
};
use serde::Deserialize;
use std::{fs, io};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    backend: u64,
    error: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    inputs: Vec<Input>,
    before: u64,
    excluded_before: Vec<u64>,
    attempts: Vec<Vec<u64>>,
    backend: u64,
    error: String,
    current: u64,
    excluded: Vec<u64>,
    finish: Vec<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    steps: Vec<Step>,
}
fn classification(value: &str) -> Result<ErrorClass> {
    match value {
        "none" => Ok(ErrorClass::None),
        "sentinel" | "no-group" | "observer-sentinel" => Ok(ErrorClass::NoBackend),
        "other" | "ordinary" | "wrapped" | "conflict" => Ok(ErrorClass::Other),
        _ => Err("unknown fixture error class".into()),
    }
}
fn replay(case: &Case) -> Result<()> {
    let mut tracker = Tracker::default();
    for (index, step) in case.steps.iter().enumerate() {
        let next = u64::try_from(index)? + 1;
        tracker
            .begin(next, step.before, &step.excluded_before)
            .map_err(|r| io::Error::other(format!("begin {r:?}")))?;
        let mut complete = false;
        for (attempt, excluded) in step.attempts.iter().enumerate() {
            let input = step.inputs.get(attempt).ok_or("extra attempt")?;
            let error = classification(&input.error)?;
            // Distinct fixture group/operation tokens detect rewriting Finish
            // to the later attempt. Production integration must use the actual
            // original binding from an independently compared routeOnce.
            let binding = (error == ErrorClass::None).then_some(Binding {
                account: input.backend,
                group: input.backend + 100,
                operation: next * 100 + input.backend,
            });
            let action = tracker
                .attempt(
                    next,
                    u8::try_from(attempt)? + 1,
                    excluded,
                    DerivedResult {
                        backend: input.backend,
                        error,
                        binding,
                    },
                )
                .map_err(|r| io::Error::other(format!("attempt {r:?}")))?;
            complete = action == Continue::Return;
        }
        if !complete {
            return Err("missing attempt".into());
        }
        tracker
            .end(
                next,
                step.backend,
                classification(&step.error)?,
                step.current,
                &step.excluded,
            )
            .map_err(|r| io::Error::other(format!("end {r:?}")))?;
        if step.finish.len() != 1 {
            return Err("Finish callback count".into());
        }
        if tracker.current().is_some() {
            let binding = tracker
                .finish_binding(step.finish[0])
                .map_err(|r| io::Error::other(format!("finish {r:?}")))?;
            if Some(binding) != tracker.current() {
                return Err("original binding".into());
            }
        } else if step.finish[0] != 0 {
            return Err("nil cur".into());
        }
    }
    tracker
        .tail()
        .map_err(|r| io::Error::other(format!("tail {r:?}")))?;
    Ok(())
}
fn main() -> Result<()> {
    let bytes = fs::read(std::env::args().nth(1).ok_or("oracle path")?)?;
    let cases: Vec<Case> = serde_json::from_slice(&bytes)?;
    if cases.len() != 12 {
        return Err("fixture population".into());
    }
    let mut steps = 0;
    for case in &cases {
        if let Err(error) = replay(case) {
            return Err(io::Error::other(format!(
                "SELECTOR_ORACLE_MISMATCH case={} {error}",
                case.name
            ))
            .into());
        }
        steps += case.steps.len();
        println!("SELECTOR_ORACLE case={} pass=true", case.name);
    }
    println!(
        "SELECTOR_ORACLE cases={} steps={steps} mismatch=0 fixed_charge={}",
        cases.len(),
        Tracker::CHARGE
    );
    Ok(())
}
