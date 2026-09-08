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

use super::Error;
use control_router::shadow::{Epoch, Event, Observation, Policy};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy)]
struct Decimal(u64);
impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|c| c.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(serde::de::Error::custom(
                "expected canonical u64 decimal string",
            ));
        }
        value
            .parse()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("u64 overflow"))
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WirePolicy {
    Connection,
    Resource,
    Location,
}
impl From<Policy> for WirePolicy {
    fn from(value: Policy) -> Self {
        match value {
            Policy::Connection => Self::Connection,
            Policy::Resource => Self::Resource,
            Policy::Location => Self::Location,
        }
    }
}
impl From<WirePolicy> for Policy {
    fn from(value: WirePolicy) -> Self {
        match value {
            WirePolicy::Connection => Self::Connection,
            WirePolicy::Resource => Self::Resource,
            WirePolicy::Location => Self::Location,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    process: Decimal,
    owner: Decimal,
    nonce: Decimal,
    sequence: Decimal,
    event: WireEvent,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireEvent {
    Begin {},
    Policy {
        value: WirePolicy,
    },
    Account {
        id: Decimal,
        group: Decimal,
    },
    RemoveAccount {
        account: Decimal,
    },
    Open {
        session: Decimal,
    },
    Reserve {
        session: Decimal,
        operation: Decimal,
        account: Decimal,
    },
    Created {
        session: Decimal,
        operation: Decimal,
        success: bool,
    },
    Redirect {
        session: Decimal,
        operation: Decimal,
        target: Decimal,
    },
    Redirected {
        session: Decimal,
        operation: Decimal,
        success: bool,
    },
    Closing {
        session: Decimal,
        operation: Decimal,
    },
    Closed {
        session: Decimal,
    },
    Rehydrate {
        session: Decimal,
        account: Decimal,
    },
    Rejected {
        session: Decimal,
    },
    Retire {},
    End {},
    Watermark {},
}

impl From<&Event> for WireEvent {
    fn from(event: &Event) -> Self {
        match *event {
            Event::Begin => Self::Begin {},
            Event::Policy(value) => Self::Policy {
                value: value.into(),
            },
            Event::Account { id, group } => Self::Account {
                id: Decimal(id),
                group: Decimal(group),
            },
            Event::RemoveAccount(account) => Self::RemoveAccount {
                account: Decimal(account),
            },
            Event::Open(session) => Self::Open {
                session: Decimal(session),
            },
            Event::Reserve {
                session,
                operation,
                account,
            } => Self::Reserve {
                session: Decimal(session),
                operation: Decimal(operation),
                account: Decimal(account),
            },
            Event::Created {
                session,
                operation,
                success,
            } => Self::Created {
                session: Decimal(session),
                operation: Decimal(operation),
                success,
            },
            Event::Redirect {
                session,
                operation,
                target,
            } => Self::Redirect {
                session: Decimal(session),
                operation: Decimal(operation),
                target: Decimal(target),
            },
            Event::Redirected {
                session,
                operation,
                success,
            } => Self::Redirected {
                session: Decimal(session),
                operation: Decimal(operation),
                success,
            },
            Event::Closing { session, operation } => Self::Closing {
                session: Decimal(session),
                operation: Decimal(operation),
            },
            Event::Closed(session) => Self::Closed {
                session: Decimal(session),
            },
            Event::Rehydrate { session, account } => Self::Rehydrate {
                session: Decimal(session),
                account: Decimal(account),
            },
            Event::Rejected { session } => Self::Rejected {
                session: Decimal(session),
            },
            Event::Retire => Self::Retire {},
            Event::End => Self::End {},
            Event::Watermark => Self::Watermark {},
        }
    }
}

impl From<WireEvent> for Event {
    fn from(event: WireEvent) -> Self {
        match event {
            WireEvent::Begin {} => Self::Begin,
            WireEvent::Policy { value } => Self::Policy(value.into()),
            WireEvent::Account { id, group } => Self::Account {
                id: id.0,
                group: group.0,
            },
            WireEvent::RemoveAccount { account } => Self::RemoveAccount(account.0),
            WireEvent::Open { session } => Self::Open(session.0),
            WireEvent::Reserve {
                session,
                operation,
                account,
            } => Self::Reserve {
                session: session.0,
                operation: operation.0,
                account: account.0,
            },
            WireEvent::Created {
                session,
                operation,
                success,
            } => Self::Created {
                session: session.0,
                operation: operation.0,
                success,
            },
            WireEvent::Redirect {
                session,
                operation,
                target,
            } => Self::Redirect {
                session: session.0,
                operation: operation.0,
                target: target.0,
            },
            WireEvent::Redirected {
                session,
                operation,
                success,
            } => Self::Redirected {
                session: session.0,
                operation: operation.0,
                success,
            },
            WireEvent::Closing { session, operation } => Self::Closing {
                session: session.0,
                operation: operation.0,
            },
            WireEvent::Closed { session } => Self::Closed(session.0),
            WireEvent::Rehydrate { session, account } => Self::Rehydrate {
                session: session.0,
                account: account.0,
            },
            WireEvent::Rejected { session } => Self::Rejected { session: session.0 },
            WireEvent::Retire {} => Self::Retire,
            WireEvent::End {} => Self::End,
            WireEvent::Watermark {} => Self::Watermark,
        }
    }
}

pub(super) fn decode(body: &[u8]) -> Result<Observation, Error> {
    let wire: Wire = serde_json::from_slice(body).map_err(|_| Error::Schema)?;
    if wire.version != 1 {
        return Err(Error::Version);
    }
    Ok(Observation {
        epoch: Epoch {
            process: wire.process.0,
            owner: wire.owner.0,
            nonce: wire.nonce.0,
        },
        sequence: wire.sequence.0,
        event: wire.event.into(),
    })
}

pub(super) fn encode(observation: &Observation) -> Result<Vec<u8>, Error> {
    let wire = Wire {
        version: 1,
        process: Decimal(observation.epoch.process),
        owner: Decimal(observation.epoch.owner),
        nonce: Decimal(observation.epoch.nonce),
        sequence: Decimal(observation.sequence),
        event: (&observation.event).into(),
    };
    serde_json::to_vec(&wire).map_err(|_| Error::Schema)
}
