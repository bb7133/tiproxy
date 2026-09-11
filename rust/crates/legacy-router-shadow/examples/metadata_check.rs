// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixture-only replay of real router metadata refreshes. The tracker derives
//! inventory, membership, the redirection gate and client classification from
//! the Begin inputs and the values each decision actually read; Go's Assign,
//! Refresh and End frames are witnesses only, and every group identity binds to
//! its real `GroupCreated` / native Init / `GroupRemoved` records. The owner
//! tracker lives in `LiveState` and shares the retained budget;
//! production transport dispatch remains uninstalled.
use control_router::shadow::{
    InvalidReason, Limits, Status,
    live::{
        LiveState,
        caller::metadata::{Classification, Event, Tracker},
    },
};
use control_routing::group::ClientInfo;
use legacy_router_shadow::caller;
use serde::Deserialize;
use std::{env, fs, process};
#[path = "support/route_prefix.rs"]
mod prefix;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Version {
    version: u32,
}

#[derive(Default)]
struct Counts {
    begins: usize,
    assigns: usize,
    refreshes: usize,
    ends: usize,
}

struct Replay {
    scenario: String,
    state: LiveState,
    origin: Option<control_routing::go_time::Origin>,
    owner: Option<control_router::shadow::Epoch>,
    generation: u64,
    counts: Counts,
}

fn client(address: &str) -> ClientInfo<'_> {
    ClientInfo {
        client_address: Some(address),
        proxy_address: None,
    }
}

impl Replay {
    fn new(scenario: &str) -> Self {
        Self {
            scenario: scenario.to_string(),
            state: LiveState::new(Limits::default()),
            origin: None,
            owner: None,
            generation: 0,
            counts: Counts::default(),
        }
    }

    fn fail(&self, reason: InvalidReason) -> Box<dyn std::error::Error> {
        format!(
            "METADATA_REPLAY_FAILED scenario={} generation={} reason={reason:?}",
            self.scenario, self.generation
        )
        .into()
    }

    fn frame(&mut self, bytes: &[u8]) -> Result<()> {
        let body = bytes.get(4..).ok_or("framing")?;
        let version: Version = serde_json::from_slice(body)?;
        match version.version {
            4 => self.metadata(bytes),
            2 | 3 => {
                let result = prefix::observe_prefix(
                    &mut self.state,
                    bytes,
                    &mut self.origin,
                    &mut self.owner,
                );
                if result.is_err()
                    && let Some(owner) = self.owner
                    && let Status::Invalid(reason) = self.state.progress(owner).status
                {
                    return Err(self.fail(reason));
                }
                result
            }
            _ => Err("METADATA_UNKNOWN_FRAME_VERSION".into()),
        }
    }

    fn tracker(&self) -> std::result::Result<&Tracker, InvalidReason> {
        self.owner
            .and_then(|owner| self.state.router_metadata(owner))
            .ok_or(InvalidReason::MissingBegin)
    }

    fn metadata(&mut self, bytes: &[u8]) -> Result<()> {
        let caller::Frame::Metadata(boundary) =
            caller::decode_caller(bytes, self.origin, self.state.native_retained_bytes())?
        else {
            return Err("METADATA_FAMILY".into());
        };
        if self.owner.is_some_and(|owner| owner != boundary.epoch) {
            return Err("METADATA_FOREIGN_OWNER".into());
        }
        match &boundary.event {
            Event::Begin(begin) => {
                self.generation = begin.generation;
                self.counts.begins += 1;
            }
            Event::Assign(_) => self.counts.assigns += 1,
            Event::Refresh(_) => self.counts.refreshes += 1,
            Event::End(_) => self.counts.ends += 1,
        }
        let progress = self.state.observe_router_metadata(&boundary, bytes.len());
        if progress.status != Status::Comparing || progress.compared_sequence != boundary.sequence {
            let reason = if let Status::Invalid(reason) = progress.status {
                reason
            } else {
                InvalidReason::Sequence
            };
            return Err(self.fail(reason));
        }
        if matches!(boundary.event, Event::End(_)) {
            self.expect().map_err(|reason| self.fail(reason))?;
        }
        Ok(())
    }

    /// Scenario expectations after each committed generation, computed only
    /// from the tracker's independently derived state.
    fn expect(&self) -> std::result::Result<(), InvalidReason> {
        let t = self.tracker()?;
        let groups = t.known_groups()?;
        let ids = groups.as_slice();
        let classify =
            |address: &str, port: &str| t.classify(self.generation, client(address), port);
        let ok = match (self.scenario.as_str(), self.generation) {
            ("all", 1 | 2) => {
                ids.len() == 1 && classify("1.2.3.4:1", "")? == Classification::Group(ids[0])
            }
            ("all", 3) => ids.is_empty() && classify("1.2.3.4:1", "")? == Classification::NoGroup,
            ("cidr", 1 | 2) => {
                ids.len() == 1
                    && classify("10.1.2.3:1", "")? == Classification::Group(ids[0])
                    && classify("192.168.1.1:1", "")? == Classification::Group(ids[0])
                    && classify("172.16.0.1:1", "")? == Classification::NoGroup
                    && t.matcher(ids[0])?.is_some_and(|m| m.values().len() == 2)
            }
            ("cidr", 3) => {
                classify("10.1.2.3:1", "")?
                    == Classification::ObserverError(
                        control_router::shadow::live::caller::selection::ErrorClass::NoBackend,
                    )
            }
            ("cidr", 4) => {
                classify("10.1.2.3:1", "")?
                    == Classification::ObserverError(
                        control_router::shadow::live::caller::selection::ErrorClass::Other,
                    )
            }
            ("port", 1) => {
                // Go's map iteration decides which backend created which
                // group; the 6001 group is the one whose values say so.
                let beta_6001 = ids.iter().copied().find(|id| {
                    t.matcher(*id)
                        .ok()
                        .flatten()
                        .is_some_and(|m| m.values() == ["beta:6001"])
                });
                ids.len() == 3
                    && classify("1.2.3.4:1", "6000")? == Classification::Conflict
                    && beta_6001.is_some_and(|id| {
                        classify("1.2.3.4:1", "6001").ok() == Some(Classification::Group(id))
                    })
                    && classify("1.2.3.4:1", "6002")? == Classification::NoGroup
            }
            _ => false,
        };
        (ok && t.support_redirection())
            .then_some(())
            .ok_or(InvalidReason::Witness)
    }

    fn finish(&self) -> Result<()> {
        let tracker = self.tracker().map_err(|r| self.fail(r))?;
        tracker.tail().map_err(|r| self.fail(r))?;
        let (generations, expected): (u64, (usize, usize, usize, usize)) =
            match self.scenario.as_str() {
                "all" => (3, (3, 7, 2, 3)),
                "cidr" => (4, (4, 8, 2, 4)),
                "port" => (1, (1, 3, 3, 1)),
                _ => return Err("METADATA_UNKNOWN_SCENARIO".into()),
            };
        let c = &self.counts;
        if (c.begins, c.assigns, c.refreshes, c.ends) != expected
            || tracker.generation() != generations
        {
            return Err(format!(
                "METADATA_POPULATION scenario={} begins={} assigns={} refreshes={} ends={}",
                self.scenario, c.begins, c.assigns, c.refreshes, c.ends
            )
            .into());
        }
        Ok(())
    }
}

fn split(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let prefix: [u8; 4] = bytes.get(at..at + 4).ok_or("framing")?.try_into()?;
        let len = usize::try_from(u32::from_be_bytes(prefix))?;
        let end = at + 4 + len;
        frames.push(bytes.get(at..end).ok_or("framing")?.to_vec());
        at = end;
    }
    Ok(frames)
}

fn replay(scenario: &str, frames: &[Vec<u8>]) -> Result<()> {
    let mut replay = Replay::new(scenario);
    for frame in frames {
        replay.frame(frame)?;
    }
    replay.finish()
}

/// Corrupt one witness field of the first frame containing `needle`; every
/// corruption must be rejected by the tracker, not by the transport.
fn corrupt(frames: &[Vec<u8>], needle: &str, replacement: &str) -> Option<Vec<Vec<u8>>> {
    let mut copy = frames.to_vec();
    let at = copy
        .iter()
        .position(|f| String::from_utf8_lossy(&f[4..]).contains(needle))?;
    let body = String::from_utf8_lossy(&copy[at][4..]).replacen(needle, replacement, 1);
    let mut frame = u32::try_from(body.len()).ok()?.to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    copy[at] = frame;
    Some(copy)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, path, scenario] = args.as_slice() else {
        return Err("usage: metadata_check <frames> <all|cidr|port>".into());
    };
    let frames = split(&fs::read(path)?)?;
    replay(scenario, &frames)?;
    let corruptions: &[(&str, &str, &str)] = match scenario.as_str() {
        "all" => &[
            (
                "wrong-group",
                r#""removed":false,"created":true"#,
                r#""removed":false,"created":false"#,
            ),
            (
                "wrong-removed-count",
                r#""removed":2,"refresh_failed":0"#,
                r#""removed":1,"refresh_failed":0"#,
            ),
        ],
        "cidr" => &[
            (
                "wrong-refresh-parse",
                r#""parsed":false"#,
                r#""parsed":true"#,
            ),
            (
                "wrong-refresh-count",
                r#""refresh_failed":1"#,
                r#""refresh_failed":0"#,
            ),
            // c510c5b5: the stored result grows beyond what the member reads returned.
            (
                "extra-result-cidr",
                r#"],"parsed":true}"#,
                r#","0.0.0.0/0"],"parsed":true}"#,
            ),
            (
                "wrong-no-group",
                r#""group":"0","removed":false,"created":false,"values_read":true,"values":["bad-cidr"]"#,
                r#""group":"0","removed":false,"created":false,"values_read":true,"values":["10.0.0.0/8"]"#,
            ),
        ],
        "port" => &[
            ("wrong-conflicts", r#""conflicts":1"#, r#""conflicts":0"#),
            (
                "wrong-input-health",
                r#""healthy":true,"support_redirection":true,"present":true},{"account""#,
                r#""healthy":false,"support_redirection":true,"present":true},{"account""#,
            ),
        ],
        _ => return Err("METADATA_UNKNOWN_SCENARIO".into()),
    };
    for (name, needle, replacement) in corruptions {
        let corrupted =
            corrupt(&frames, needle, replacement).ok_or("METADATA_CORRUPTION_ANCHOR")?;
        match replay(scenario, &corrupted) {
            Ok(()) => return Err(format!("METADATA_CORRUPTION_SURVIVED {name}").into()),
            Err(e) if e.to_string().starts_with("METADATA_REPLAY_FAILED") => {
                println!("METADATA_CORRUPTION {name} rejected: {e}");
            }
            Err(e) => return Err(format!("METADATA_CORRUPTION_NOT_DOMAIN {name}: {e}").into()),
        }
    }
    println!(
        "METADATA_INDEPENDENT scenario={scenario} frames={} corruptions={}",
        frames.len(),
        corruptions.len()
    );
    Ok(())
}

#[allow(dead_code)]
fn unused() {
    process::exit(0)
}
