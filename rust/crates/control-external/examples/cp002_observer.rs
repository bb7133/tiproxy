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

//! Emits CP-002 observations from real etcd, HTTP, and DNS dependencies.

use std::fs;
use std::path::Path;
use std::time::Duration;

use control_external::{
    BoundedHttpClient, DnsResolver, EtcdClientConfig, EtcdConnection, EtcdConnector, EtcdTlsConfig,
    HttpClientConfig,
};
use control_plane::{OwnerScope, OwnershipRegistry};
use serde_json::{Value, json};

type AnyError = Box<dyn std::error::Error>;

struct ConnectionInfo {
    etcd_endpoint: String,
    http_url: String,
    http_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let connection_path = std::env::var("CP002_CONNECTION_FILE")?;
    let generation: u64 = std::env::var("CP002_GENERATION")?.parse()?;
    if generation == 0 {
        return Err("CP002_GENERATION must be nonzero".into());
    }
    let connection = read_connection(Path::new(&connection_path))?;

    let registry = OwnershipRegistry::new();
    for retired in 1..generation {
        let lease = registry.claim(OwnerScope::Process, format!("retired-{retired}"))?;
        drop(lease);
    }
    let lease = registry.claim(OwnerScope::Process, format!("external-{generation}"))?;
    if lease.generation() != generation {
        return Err("owner generation did not advance exactly".into());
    }
    let owner = lease.token();
    let (mut etcd, http, body_len) = observe_dependencies(&owner, &connection, generation).await?;
    emit_observation(generation, body_len);

    drop(lease);
    if !matches!(
        etcd.execute(|_| Box::pin(async { Ok(()) })).await,
        Err(control_external::EtcdOperationError::StaleOwner)
    ) {
        return Err("released owner retained etcd access".into());
    }
    if !matches!(
        http.get(&connection.http_url).await,
        Err(control_external::HttpError::StaleOwner)
    ) {
        return Err("released owner retained HTTP access".into());
    }
    Ok(())
}

fn read_connection(path: &Path) -> Result<ConnectionInfo, AnyError> {
    let connection: Value = serde_json::from_slice(&fs::read(path)?)?;
    let etcd_endpoint = connection["etcd_endpoint"]
        .as_str()
        .ok_or("missing etcd_endpoint")?
        .to_owned();
    let http_url = connection["http_url"]
        .as_str()
        .ok_or("missing http_url")?
        .to_owned();
    let http_port = u16::try_from(
        connection["http_port"]
            .as_u64()
            .ok_or("missing http_port")?,
    )?;
    Ok(ConnectionInfo {
        etcd_endpoint,
        http_url,
        http_port,
    })
}

async fn observe_dependencies(
    owner: &control_plane::OwnerToken,
    connection: &ConnectionInfo,
    generation: u64,
) -> Result<(EtcdConnection, BoundedHttpClient, usize), AnyError> {
    let endpoint = if std::env::var_os("CP002_MUTATE_ENDPOINT").is_some() {
        "127.0.0.1:1".to_owned()
    } else {
        connection.etcd_endpoint.clone()
    };
    let tls = if std::env::var_os("CP002_MUTATE_TLS").is_some() {
        Some(EtcdTlsConfig::new(
            b"not-a-valid-ca-certificate".to_vec(),
            None,
            None,
            None,
        )?)
    } else {
        None
    };
    let etcd_config = EtcdClientConfig::new([endpoint], tls)?.with_timeouts(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(3),
        Duration::from_secs(30),
    )?;
    let mut etcd = EtcdConnector::new(owner.clone(), etcd_config)
        .connect()
        .await?;
    let key = format!("/tiproxy/cp002/{generation}/rust");
    let put_key = key.clone();
    etcd.execute(move |client| Box::pin(client.put(put_key, "cp002", None)))
        .await?;
    let get_key = key.clone();
    let get = etcd
        .execute(move |client| Box::pin(client.get(get_key, None)))
        .await?;
    if get.kvs().len() != 1 || get.kvs()[0].value() != b"cp002" {
        return Err("Rust etcd get mismatch".into());
    }
    etcd.execute(move |client| Box::pin(client.delete(key, None)))
        .await?;

    let http = BoundedHttpClient::new(
        owner.clone(),
        HttpClientConfig::new(Duration::from_secs(5), Duration::from_secs(5), 1024, None)?,
    )?;
    let body = http.get(&connection.http_url).await?;
    if body != b"cp002" {
        return Err("Rust HTTP body mismatch".into());
    }
    let addresses = DnsResolver::new(owner.clone(), Duration::from_secs(5))?
        .resolve("localhost", connection.http_port)
        .await?;
    if addresses.is_empty() {
        return Err("Rust DNS result was empty".into());
    }

    Ok((etcd, http, body.len()))
}

fn emit_observation(generation: u64, body_len: usize) {
    let observed_generation = if std::env::var_os("CP002_MUTATE_GENERATION").is_some() {
        generation.saturating_add(1)
    } else {
        generation
    };
    let outcome = if generation == 1 {
        "connected"
    } else {
        "reconnected"
    };
    println!(
        "{}",
        json!({
            "schema_version": 1,
            "producer": "rust",
            "observations": [{
                "scenario_id": "CP-FAULT-EXTERNAL-PROCESS-RESTART",
                "step": generation - 1,
                "contracts": ["CP-EXT-001"],
                "subject": {
                    "namespace": "process",
                    "cluster": "loopback",
                    "generation": observed_generation
                },
                "outcome": outcome,
                "effects": [
                    "dns_resolution_succeeded",
                    "etcd_kv_round_trip",
                    "http_bounded_body"
                ],
                "state": [
                    {"key": "cancellation_state", "value": "owner_current"},
                    {"key": "dependency", "value": "dns,etcd,http"},
                    {"key": "endpoint_address", "value": "loopback"}
                ],
                "counters": [
                    {"key": "deadline_millis", "value": 5000},
                    {"key": "http_body_bytes", "value": i64::try_from(body_len).unwrap_or(i64::MAX)},
                    {"key": "retry_count", "value": 0}
                ]
            }]
        })
    );
}
