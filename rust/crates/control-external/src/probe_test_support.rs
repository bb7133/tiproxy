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

//! Shared loopback fixtures for the cluster probe modules' tests: a process
//! owner lease, cluster configs, and a fake explicit nameserver.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};
use tokio::net::UdpSocket;

use crate::etcd::{EtcdClientConfig, EtcdTlsConfig};

/// A claimed process owner lease and the registry that keeps it alive.
pub(crate) fn owner_lease() -> (OwnershipRegistry, OwnerLease) {
    let registry = OwnershipRegistry::new();
    let lease = registry
        .claim(OwnerScope::Process, "cluster-probe-test")
        .unwrap_or_else(|error| unreachable!("claim: {error}"));
    (registry, lease)
}

/// A plaintext cluster config with no explicit nameservers (system resolver).
pub(crate) fn plaintext_config() -> EtcdClientConfig {
    EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], None)
        .unwrap_or_else(|error| unreachable!("config: {error}"))
}

/// Spawns a loopback UDP nameserver answering `A`/`AAAA` for ANY name with the
/// given addresses, after `delay` (zero for an immediate answer), returning
/// its port.
pub(crate) async fn spawn_dns_with_delay(
    a: Vec<Ipv4Addr>,
    aaaa: Vec<Ipv6Addr>,
    delay: Duration,
) -> u16 {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType};

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap_or_else(|error| unreachable!("bind dns: {error}"));
    let port = socket
        .local_addr()
        .unwrap_or_else(|error| unreachable!("dns addr: {error}"))
        .port();
    let socket = Arc::new(socket);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(message) = Message::from_vec(&buffer[..len]) else {
                continue;
            };
            let Some(query) = message.queries.first() else {
                continue;
            };
            let qname = query.name().clone();
            let qtype = query.query_type();
            let mut response = Message::new(message.id, MessageType::Response, OpCode::Query);
            response.metadata.authoritative = true;
            response.metadata.response_code = ResponseCode::NoError;
            response.add_query(Query::query(qname.clone(), qtype));
            if qtype == RecordType::A {
                for ip in &a {
                    let octets = ip.octets();
                    response.add_answer(Record::from_rdata(
                        qname.clone(),
                        30,
                        RData::A(A::new(octets[0], octets[1], octets[2], octets[3])),
                    ));
                }
            } else if qtype == RecordType::AAAA {
                for ip in &aaaa {
                    response.add_answer(Record::from_rdata(
                        qname.clone(),
                        30,
                        RData::AAAA(AAAA(*ip)),
                    ));
                }
            }
            let Ok(bytes) = response.to_vec() else {
                continue;
            };
            // Answer each query on its own task so a delayed answer never
            // serializes the resolver's parallel A/AAAA queries.
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let _ = socket.send_to(&bytes, src).await;
            });
        }
    });
    port
}

/// Spawns an immediately-answering loopback nameserver (see
/// [`spawn_dns_with_delay`]).
pub(crate) async fn spawn_dns(a: Vec<Ipv4Addr>, aaaa: Vec<Ipv6Addr>) -> u16 {
    spawn_dns_with_delay(a, aaaa, Duration::ZERO).await
}

/// A plaintext (or TLS) cluster config whose only nameserver is the loopback
/// fake at `dns_port`.
pub(crate) fn ns_config(dns_port: u16, tls: Option<EtcdTlsConfig>) -> EtcdClientConfig {
    let ns: Arc<[Arc<str>]> =
        Arc::from([Arc::<str>::from(format!("127.0.0.1:{dns_port}").as_str())]);
    EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], tls)
        .and_then(|config| config.with_ns_servers(ns))
        .unwrap_or_else(|error| unreachable!("config: {error}"))
}
