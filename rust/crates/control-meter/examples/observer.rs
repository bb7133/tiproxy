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

use control_meter::{Batch, Checkpoint, Consumer, Delta, DisabledSink, DurableSink, Outbox};
use control_plane::{OwnerScope, OwnershipRegistry};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    reopen: bool,
    #[serde(default)]
    export: bool,
    batch: Option<Batch>,
}

enum Sink {
    Enabled(Outbox),
    Disabled(DisabledSink),
}

impl DurableSink for Sink {
    fn healthy(&self) -> bool {
        match self {
            Self::Enabled(value) => value.healthy(),
            Self::Disabled(value) => value.healthy(),
        }
    }
    fn checkpoint(&self) -> Option<Checkpoint> {
        match self {
            Self::Enabled(value) => value.checkpoint(),
            Self::Disabled(value) => value.checkpoint(),
        }
    }
    fn apply(
        &mut self,
        producer: &str,
        sequence: u64,
        deltas: &[Delta],
    ) -> Result<(), control_meter::Error> {
        match self {
            Self::Enabled(value) => value.apply(producer, sequence, deltas),
            Self::Disabled(value) => value.apply(producer, sequence, deltas),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 && (args.len() != 4 || args[3] != "disabled") {
        return Err("usage: observer STATE_DIR EVENTS_JSON [disabled]".into());
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
            if args.len() == 4 {
                Sink::Disabled(DisabledSink)
            } else {
                Sink::Enabled(Outbox::open(&outbox_path, lease.token())?)
            },
        )
    };
    let mut consumer = open()?;
    let mut observations = Vec::new();
    for event in events {
        let (applied, error) = if event.export {
            let store = control_meter::LocalStore::new(&dir.join("objects"), "", true, "")?;
            let Sink::Enabled(outbox) = consumer.sink_mut() else {
                return Err("disabled export event".into());
            };
            let result = control_meter::export::flush(
                outbox,
                &store,
                "",
                60,
                std::time::Duration::from_secs(2),
            )
            .await;
            (None, result.is_err())
        } else if event.reopen {
            consumer = open()?;
            (None, false)
        } else {
            match consumer.apply(&event.batch.ok_or("missing batch")?) {
                Ok(value) => (Some(value), false),
                Err(_) => (Some(false), true),
            }
        };
        let consumer_state: Value = serde_json::from_slice(&fs::read(&consumer_path)?)?;
        let outbox_state: Value = match fs::read(&outbox_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if args.len() == 4 && error.kind() == std::io::ErrorKind::NotFound => {
                Value::Null
            }
            Err(error) => return Err(error.into()),
        };
        observations.push(
            json!({"applied": applied, "error":error, "healthy":consumer.healthy(),
            "consumer":consumer_state, "outbox":outbox_state}),
        );
    }
    println!("{}", serde_json::to_string(&observations)?);
    Ok(())
}
