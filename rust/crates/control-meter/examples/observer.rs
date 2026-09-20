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

//! Production native consumer/outbox observer for Go parity and state handoff.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use control_meter::{Batch, Consumer, Outbox};
use control_plane::{OwnerScope, OwnershipRegistry};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    reopen: bool,
    batch: Option<Batch>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: observer STATE_DIR EVENTS_JSON".into());
    }
    let dir = PathBuf::from(&args[1]);
    let events: Vec<Event> = serde_json::from_slice(&fs::read(&args[2])?)?;
    let registry = OwnershipRegistry::new();
    let lease = registry.claim(OwnerScope::Process, "meter-parity")?;
    let consumer_path = dir.join("consumer.json");
    let outbox_path = dir.join("run/metering-outbox.json");
    let open = || {
        Consumer::open(
            &consumer_path,
            lease.token(),
            Outbox::open(&outbox_path, lease.token())?,
        )
    };
    let mut consumer = open()?;
    let mut observations = Vec::new();
    for event in events {
        let (applied, error) = if event.reopen {
            consumer = open()?;
            (None, false)
        } else {
            match consumer.apply(&event.batch.ok_or("missing batch")?) {
                Ok(value) => (Some(value), false),
                Err(_) => (Some(false), true),
            }
        };
        let consumer_state: Value = serde_json::from_slice(&fs::read(&consumer_path)?)?;
        let outbox_state: Value = serde_json::from_slice(&fs::read(&outbox_path)?)?;
        observations.push(
            json!({"applied": applied, "error":error, "healthy":consumer.healthy(),
            "consumer":consumer_state, "outbox":outbox_state}),
        );
    }
    println!("{}", serde_json::to_string(&observations)?);
    Ok(())
}
