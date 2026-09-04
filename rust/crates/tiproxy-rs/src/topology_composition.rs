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

//! Composition-root wiring for CP-TOPO self-registration.
//!
//! The [`TopologyCandidateValidator`] reads the backend-cluster TLS PEM material
//! once, at validation time, and binds it into a [`PreparedClusterSet`] carried
//! by the published snapshot's opaque `PreparedArtifact`. The
//! [`ArtifactClusterFactory`] then downcasts that artifact and hands the module
//! the already-built clients without re-reading any file, so a swap or delete of
//! the PEM between validation and application cannot change the material a
//! generation registers with (closing the validate->apply TOCTOU).

use std::net::IpAddr;
use std::sync::Arc;

use control_config::{
    CandidateValidator, ClientTlsConfig, ConfigNamespaceSnapshot, EffectiveConfig, NamespaceConfig,
    PreparedArtifact, TopologyConfig,
};
use control_external::{EtcdClientConfig, EtcdTlsConfig, EtcdTlsPolicy, EtcdTlsVersion};
use control_topology::{TopologyClientFactory, TopologyClusterClient};

use crate::tls_material::{TlsRoots, read_tls_material};

/// The concrete artifact a [`TopologyCandidateValidator`] prepares: the exact
/// normalized topology projection it validated, plus one built etcd client per
/// backend cluster with its TLS material already loaded.
///
/// The bound [`TopologyConfig`] lets [`ArtifactClusterFactory`] confirm the
/// artifact belongs to the exact snapshot it is handed (a typed exact compare,
/// not a fingerprint), so a drifted or mismatched artifact fails closed rather
/// than registering stale clients. It is carried opaquely by the snapshot and
/// has no `Debug`, so the endpoints and material it holds never render.
pub struct PreparedClusterSet {
    topology: TopologyConfig,
    clusters: Vec<TopologyClusterClient>,
}

impl PreparedClusterSet {
    /// The name-sorted built clients.
    #[must_use]
    pub fn clusters(&self) -> &[TopologyClusterClient] {
        &self.clusters
    }
}

/// Reads backend-cluster TLS material and prepares the per-cluster etcd clients
/// for the candidate generation. TLS files are read through the safe seam,
/// confined to the process's allowed TLS roots.
#[derive(Clone)]
pub struct TopologyCandidateValidator {
    allowed_tls_roots: Arc<TlsRoots>,
}

impl TopologyCandidateValidator {
    /// Creates a validator that reads TLS material only from within
    /// `allowed_tls_roots`.
    #[must_use]
    pub fn new(allowed_tls_roots: Arc<TlsRoots>) -> Self {
        Self { allowed_tls_roots }
    }
}

impl CandidateValidator for TopologyCandidateValidator {
    fn validate(
        &self,
        effective: &EffectiveConfig,
        _namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str> {
        let topology = effective.topology().map_err(|_| "topology_projection")?;
        // Read the shared cluster TLS material once for this generation.
        let tls = cluster_tls_material(&topology.cluster_tls, &self.allowed_tls_roots)?;
        let mut clusters = Vec::with_capacity(topology.backend_clusters.len());
        for cluster in topology.backend_clusters.iter() {
            let endpoints = cluster.pd_addrs.iter().map(ToString::to_string);
            let client = EtcdClientConfig::new(endpoints, tls.clone())
                .and_then(|config| config.with_ns_servers(Arc::clone(&cluster.ns_servers)))
                .map_err(|_| "cluster_client_build")?;
            clusters.push(TopologyClusterClient {
                cluster_name: Arc::clone(&cluster.name),
                client,
            });
        }
        clusters.sort_by(|left, right| left.cluster_name.cmp(&right.cluster_name));
        Ok(PreparedArtifact::new(Arc::new(PreparedClusterSet {
            topology,
            clusters,
        })))
    }
}

/// Loads the optional client mTLS material referenced by a normalized
/// [`ClientTlsConfig`], reading each PEM once through the safe seam.
///
/// Returns payload-free failure classes: no path or material ever appears in the
/// error.
///
/// The advanced policy (`minimum_version` / `allowed_common_names` /
/// `skip_ca_verification`) is threaded into the returned [`EtcdTlsConfig`], which
/// the owner-fenced custom TLS transport consumes; `skip_ca_verification` is
/// honored (the CA is then optional), not rejected. A cluster-tls whose only
/// non-default is `minimum_version` stays plaintext — only a CA, a client
/// certificate, a key, or skip-CA upgrades the endpoints to HTTPS. Returning
/// `Some` is what upgrades the endpoints via `normalize_endpoints`, so a
/// skip-only configuration deliberately returns `Some`, never `None`.
fn cluster_tls_material(
    config: &ClientTlsConfig,
    allowed_tls_roots: &TlsRoots,
) -> Result<Option<EtcdTlsConfig>, &'static str> {
    let configured = config.skip_ca_verification
        || config.ca_path.is_some()
        || config.certificate_path.is_some()
        || config.private_key_path.is_some();
    if !configured {
        return Ok(None);
    }
    let policy = EtcdTlsPolicy {
        minimum_version: EtcdTlsVersion::parse(&config.minimum_version)
            .map_err(|_| "cluster_tls_min_version")?,
        allowed_common_names: config
            .allowed_common_names
            .iter()
            .map(ToString::to_string)
            .collect(),
        skip_ca_verification: config.skip_ca_verification,
    };
    let ca = config
        .ca_path
        .as_deref()
        .map(|path| read_tls_material(path, allowed_tls_roots))
        .transpose()
        .map_err(|_| "cluster_tls_read_ca")?;
    let certificate = config
        .certificate_path
        .as_deref()
        .map(|path| read_tls_material(path, allowed_tls_roots))
        .transpose()
        .map_err(|_| "cluster_tls_read_certificate")?;
    let key = config
        .private_key_path
        .as_deref()
        .map(|path| read_tls_material(path, allowed_tls_roots))
        .transpose()
        .map_err(|_| "cluster_tls_read_key")?;
    EtcdTlsConfig::new(ca, certificate, key, None, policy)
        .map(Some)
        .map_err(|_| "cluster_tls_invalid")
}

/// Runs two candidate validators in a fixed order and publishes a single
/// artifact.
///
/// The serving validator runs first so a serving-TLS or protocol rejection fails
/// the candidate before topology material is prepared; the topology validator
/// then prepares the [`PreparedClusterSet`] that becomes the generation's
/// published artifact. Only the topology stage prepares an artifact today, so
/// exactly one artifact is published per accepted generation.
pub struct CompositeCandidateValidator {
    serving: Arc<dyn CandidateValidator>,
    topology: Arc<dyn CandidateValidator>,
}

impl CompositeCandidateValidator {
    /// Composes the serving and topology validators in that deterministic order.
    #[must_use]
    pub fn new(
        serving: Arc<dyn CandidateValidator>,
        topology: Arc<dyn CandidateValidator>,
    ) -> Self {
        Self { serving, topology }
    }
}

impl CandidateValidator for CompositeCandidateValidator {
    fn validate(
        &self,
        effective: &EffectiveConfig,
        namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str> {
        // Serving validates first and prepares nothing today; its artifact is
        // intentionally discarded. Topology prepares the published artifact.
        let _ = self.serving.validate(effective, namespaces)?;
        self.topology.validate(effective, namespaces)
    }
}

/// Builds a generation's cluster clients by downcasting the snapshot's opaque
/// artifact to the [`PreparedClusterSet`] the [`TopologyCandidateValidator`]
/// prepared — with no PEM re-read.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactClusterFactory;

/// Enumerates local interface IP addresses for the advertise resolver's
/// fallback candidate list.
///
/// The OS-reported order of `if_addrs::get_if_addrs` is preserved — no sort or
/// dedup — because the resolver picks the first global-unicast address, matching
/// Go's `net.InterfaceAddrs()` selection; reordering would change which address
/// is advertised. On any enumeration error the list is empty, so the resolver
/// fails closed rather than falling back to a wildcard host. The interface list
/// is never logged.
#[must_use]
pub fn interface_advertise_candidates() -> Vec<IpAddr> {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces
            .into_iter()
            .map(|interface| interface.ip())
            .collect(),
        Err(_) => Vec::new(),
    }
}

impl TopologyClientFactory for ArtifactClusterFactory {
    fn build(
        &self,
        snapshot: &ConfigNamespaceSnapshot,
    ) -> Result<Vec<TopologyClusterClient>, String> {
        // Fail closed: a generation whose published artifact is not a prepared
        // cluster set (for example an empty artifact) is rejected rather than
        // registered with re-read or missing material.
        let set = snapshot
            .prepared()
            .downcast_ref::<PreparedClusterSet>()
            .ok_or_else(|| "prepared topology cluster set missing".to_owned())?;
        // Closed loop: the artifact must belong to exactly this snapshot. A
        // same-type artifact bound to a different normalized projection (a
        // drifted or mismatched generation) is rejected rather than registered
        // with stale clients. This is a typed exact compare of the whole
        // normalized projection — no fingerprint, so no field is missed and no
        // collision or diagnostic leak is possible.
        let projected = snapshot
            .topology()
            .map_err(|_| "topology projection".to_owned())?;
        if projected != set.topology {
            return Err("prepared cluster set does not match the snapshot topology".to_owned());
        }
        Ok(set.clusters().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactClusterFactory, TopologyCandidateValidator, interface_advertise_candidates,
    };
    use std::sync::Arc;

    use control_config::{ConfigNamespaceSource, ConfigNamespaceStore};
    use control_topology::TopologyClientFactory;

    fn config_toml(max_connections: u64, ca_path: &str) -> Vec<u8> {
        config_toml_named(max_connections, ca_path, "cluster-a")
    }

    fn config_toml_named(max_connections: u64, ca_path: &str, cluster: &str) -> Vec<u8> {
        format!(
            r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = {max_connections}

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "{cluster}"
pd-addrs = "pd-a:2379"
ns-servers = ["dns-a:53"]

[security.cluster-tls]
ca = "{ca_path}"
"#
        )
        .into_bytes()
    }

    #[test]
    fn a_pem_swap_or_delete_after_prepare_never_changes_the_prepared_generation() {
        let dir = std::env::temp_dir();
        let ca_path = dir.join(format!("cptopo-toctou-{}.pem", std::process::id()));
        std::fs::write(&ca_path, b"ca-bytes-a")
            .unwrap_or_else(|error| unreachable!("write ca: {error}"));
        let ca_str = ca_path
            .to_str()
            .unwrap_or_else(|| unreachable!("temp path is not utf-8"));

        let store = ConfigNamespaceStore::from_toml_with_validator(
            &config_toml(100, ca_str),
            None,
            &dir,
            Arc::new(TopologyCandidateValidator::new(Arc::new(
                crate::tls_material::open_tls_roots(std::slice::from_ref(&dir)),
            ))),
        )
        .unwrap_or_else(|error| unreachable!("generation 1: {error}"));
        let factory = ArtifactClusterFactory;

        // Generation 1 bound the CA bytes "a" into its prepared artifact.
        let generation_one = store.current();
        let clients_a = factory
            .build(&generation_one)
            .unwrap_or_else(|error| unreachable!("build generation 1: {error}"));
        assert_eq!(clients_a.len(), 1);

        // Swap the SAME path to new bytes. The already-prepared generation is
        // untouched: the factory still yields the bytes bound at validation,
        // never re-reading the file.
        std::fs::write(&ca_path, b"ca-bytes-b")
            .unwrap_or_else(|error| unreachable!("swap ca: {error}"));
        let clients_a_again = factory
            .build(&generation_one)
            .unwrap_or_else(|error| unreachable!("rebuild generation 1: {error}"));
        assert_eq!(clients_a[0].client, clients_a_again[0].client);

        // Only a new candidate re-validates and observes "b": its artifact
        // differs from generation 1's, proving the swap is seen at the next
        // validation rather than retroactively.
        let generation_two = store
            .apply_toml(&config_toml(200, ca_str), None, 2, &dir)
            .unwrap_or_else(|error| unreachable!("generation 2: {error}"))
            .unwrap_or_else(|| unreachable!("a changed candidate publishes"));
        let clients_b = factory
            .build(&generation_two)
            .unwrap_or_else(|error| unreachable!("build generation 2: {error}"));
        assert_ne!(clients_a[0].client, clients_b[0].client);

        // Delete the same path. The next candidate cannot prepare and is
        // rejected; the store retains generation 2, whose already-prepared
        // artifact still builds the "b" clients.
        std::fs::remove_file(&ca_path).unwrap_or_else(|error| unreachable!("delete ca: {error}"));
        let rejected = store.apply_toml(&config_toml(300, ca_str), None, 3, &dir);
        assert!(rejected.is_err());
        let retained = store.current();
        assert_eq!(retained.generation(), generation_two.generation());
        let clients_retained = factory
            .build(&retained)
            .unwrap_or_else(|error| unreachable!("rebuild generation 2: {error}"));
        assert_eq!(clients_b[0].client, clients_retained[0].client);
    }

    #[test]
    fn a_same_root_symlink_ca_is_rejected_through_the_topology_validator() {
        // Proves the topology production path uses the safe read: a symlink CA is
        // rejected. Reverting cluster_tls_material to a bare read would follow the
        // link and this would pass validation instead.
        let dir = std::env::temp_dir();
        let real = dir.join(format!("cptopo-prod-real-{}.pem", std::process::id()));
        std::fs::write(&real, b"ca-bytes").unwrap_or_else(|error| unreachable!("write: {error}"));
        let link = dir.join(format!("cptopo-prod-link-{}.pem", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link)
            .unwrap_or_else(|error| unreachable!("symlink: {error}"));
        let link_str = link
            .to_str()
            .unwrap_or_else(|| unreachable!("temp path is not utf-8"));
        let roots = crate::tls_material::open_tls_roots(std::slice::from_ref(&dir));
        let result = ConfigNamespaceStore::from_toml_with_validator(
            &config_toml(100, link_str),
            None,
            &dir,
            Arc::new(TopologyCandidateValidator::new(Arc::new(roots))),
        );
        assert!(
            result.is_err(),
            "a symlink CA must be rejected by the topology validator"
        );
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&real);
    }

    #[test]
    fn an_empty_artifact_is_rejected_by_the_factory() {
        // A generation whose published artifact is not a prepared cluster set
        // (here the accept-everything default) must fail closed, never register
        // with re-read or missing material.
        let dir = std::env::temp_dir();
        let store = ConfigNamespaceStore::from_toml(&config_toml(100, ""), None, &dir)
            .unwrap_or_else(|error| unreachable!("generation 1: {error}"));
        let factory = ArtifactClusterFactory;
        let result = factory.build(&store.current());
        assert!(result.is_err());
    }

    #[test]
    fn a_same_type_artifact_bound_to_a_different_projection_is_rejected() {
        use control_config::{
            CandidateValidator, EffectiveConfig, NamespaceConfig, PreparedArtifact, TopologyConfig,
        };

        // A validator that prepares a well-typed cluster set bound to a foreign
        // projection, to prove the factory rejects a same-type artifact that
        // does not belong to the snapshot it is attached to.
        struct MismatchValidator {
            topology: TopologyConfig,
        }
        impl CandidateValidator for MismatchValidator {
            fn validate(
                &self,
                _effective: &EffectiveConfig,
                _namespaces: &[NamespaceConfig],
            ) -> Result<PreparedArtifact, &'static str> {
                Ok(PreparedArtifact::new(Arc::new(super::PreparedClusterSet {
                    topology: self.topology.clone(),
                    clusters: Vec::new(),
                })))
            }
        }

        let dir = std::env::temp_dir();
        // Projection A comes from a config with a distinct cluster name.
        let store_a = ConfigNamespaceStore::from_toml_with_validator(
            &config_toml_named(100, "", "cluster-x"),
            None,
            &dir,
            Arc::new(TopologyCandidateValidator::new(Arc::new(
                crate::tls_material::open_tls_roots(std::slice::from_ref(&dir)),
            ))),
        )
        .unwrap_or_else(|error| unreachable!("store a: {error}"));
        let topology_a = store_a
            .current()
            .topology()
            .unwrap_or_else(|error| unreachable!("topology a: {error}"));

        // Store B publishes projection B, but its artifact carries projection A.
        let store_b = ConfigNamespaceStore::from_toml_with_validator(
            &config_toml_named(100, "", "cluster-a"),
            None,
            &dir,
            Arc::new(MismatchValidator {
                topology: topology_a,
            }),
        )
        .unwrap_or_else(|error| unreachable!("store b: {error}"));

        let factory = ArtifactClusterFactory;
        assert!(factory.build(&store_b.current()).is_err());
    }

    #[test]
    fn the_interface_provider_extracts_addresses_safely() {
        // A focused seam check: enumeration and IP extraction must not panic,
        // whatever interfaces this host has. There is no fixed count to assert
        // (it is host-dependent); the deterministic candidate-selection rules are
        // asserted against the resolver's injectable fake in control-topology.
        for candidate in interface_advertise_candidates() {
            let _ = candidate.is_loopback();
        }
    }
}

/// End-to-end wiring tests for the advanced-TLS topology gate (slice 2b-2).
///
/// Each advanced row obtains its [`EtcdClientConfig`] only through the real
/// composition pipeline (`TopologyCandidateValidator::validate` →
/// `ArtifactClusterFactory::build` → `TopologyClusterClient` →
/// [`EtcdConnector`]) and then drives a semantic `Range` over the owner-fenced
/// custom transport against an in-process etcd v3 gRPC fixture.
///
/// The fixture is a hand-rolled single-route tonic adapter (no `build-server`,
/// no raw h2): [`tonic::server::Grpc::unary`] with a [`tonic_prost::ProstCodec`]
/// owns the `application/grpc` content type, 5-byte length framing, single-unary
/// message, and `grpc-status: 0` trailers for the `Range` route. Plaintext, TLS,
/// and mTLS differ only in the accepted IO fed into that one service. The wire
/// messages are hand-defined to etcd 0.20.0's exact field tags so the real
/// pinned client interoperates.
#[cfg(test)]
mod advanced_tls_wiring {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use control_config::{ConfigNamespaceSource, ConfigNamespaceStore};
    use control_external::{
        EtcdClientConfig, EtcdConnection, EtcdConnector, EtcdOperationError, EtcdTlsPolicy,
        EtcdTlsVersion,
    };
    use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};
    use control_topology::{TopologyClientFactory, TopologyClusterClient};
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    use rustls::ServerConfig;
    use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
    use rustls::sign::CertifiedKey;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tonic::codegen::{BoxFuture, Context, Poll, Service, http};
    use tonic::server::{Grpc, NamedService, UnaryService};
    use tonic_prost::ProstCodec;

    use super::{ArtifactClusterFactory, TopologyCandidateValidator};
    use crate::tls_material::open_tls_roots;

    /// A non-zero response header so a client assertion on `revision()` is
    /// meaningful (a downgraded-to-plaintext path would never return it).
    const FIXTURE_REVISION: i64 = 42;
    /// The etcd v3 `Range` unary gRPC method path the pinned client calls.
    const RANGE_PATH: &str = "/etcdserverpb.KV/Range";
    /// The gRPC service name the pinned client routes against.
    const KV_SERVICE_NAME: &str = "etcdserverpb.KV";

    // ----- Wire-compatible etcd v3 messages (etcd 0.20.0 field tags) --------

    /// `etcdserverpb.RangeRequest` (only the `key` the fixture asserts).
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct RangeRequest {
        #[prost(bytes = "vec", tag = "1")]
        key: Vec<u8>,
    }

    /// `etcdserverpb.ResponseHeader`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct ResponseHeader {
        #[prost(uint64, tag = "1")]
        cluster_id: u64,
        #[prost(uint64, tag = "2")]
        member_id: u64,
        #[prost(int64, tag = "3")]
        revision: i64,
        #[prost(uint64, tag = "4")]
        raft_term: u64,
    }

    /// `mvccpb.KeyValue`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct KeyValue {
        #[prost(bytes = "vec", tag = "1")]
        key: Vec<u8>,
        #[prost(int64, tag = "2")]
        create_revision: i64,
        #[prost(int64, tag = "3")]
        mod_revision: i64,
        #[prost(int64, tag = "4")]
        version: i64,
        #[prost(bytes = "vec", tag = "5")]
        value: Vec<u8>,
        #[prost(int64, tag = "6")]
        lease: i64,
    }

    /// `etcdserverpb.RangeResponse`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct RangeResponse {
        #[prost(message, optional, tag = "1")]
        header: Option<ResponseHeader>,
        #[prost(message, repeated, tag = "2")]
        kvs: Vec<KeyValue>,
        #[prost(bool, tag = "3")]
        more: bool,
        #[prost(int64, tag = "4")]
        count: i64,
    }

    // ----- The single-route etcd v3 KV fixture (conditions 2, 3 & 4) --------

    /// Shared fixture state: the key it asserts, the value it returns, and the
    /// `Range` request counter.
    #[derive(Clone)]
    struct KvFixture {
        expected_key: Vec<u8>,
        response_value: Vec<u8>,
        range_calls: Arc<AtomicUsize>,
        /// The first request's HTTP/2 `:authority`, recorded for the logical-host
        /// identity row; other rows leave it unread.
        authority: Arc<Mutex<Option<String>>>,
    }

    /// The `Range` unary handler: it decodes the request, asserts the key,
    /// counts the call, and answers a known pair with a non-zero header.
    struct RangeHandler {
        fixture: KvFixture,
    }

    impl UnaryService<RangeRequest> for RangeHandler {
        type Response = RangeResponse;
        type Future = BoxFuture<tonic::Response<RangeResponse>, tonic::Status>;

        fn call(&mut self, request: tonic::Request<RangeRequest>) -> Self::Future {
            let fixture = self.fixture.clone();
            Box::pin(async move {
                let message = request.into_inner();
                assert_eq!(
                    message.key, fixture.expected_key,
                    "the fixture received exactly the key the client sent"
                );
                fixture.range_calls.fetch_add(1, Ordering::SeqCst);
                let header = ResponseHeader {
                    cluster_id: 7,
                    member_id: 11,
                    revision: FIXTURE_REVISION,
                    raft_term: 3,
                };
                let kv = KeyValue {
                    key: fixture.expected_key.clone(),
                    value: fixture.response_value.clone(),
                    ..KeyValue::default()
                };
                Ok(tonic::Response::new(RangeResponse {
                    header: Some(header),
                    kvs: vec![kv],
                    more: false,
                    count: 1,
                }))
            })
        }
    }

    /// The `Range` route uses a prost codec so tonic frames the response; any
    /// other path returns the same `unimplemented` gRPC reply tonic's generated
    /// server sends (status 200 + `grpc-status: 12`).
    impl Service<http::Request<Incoming>> for KvFixture {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Infallible>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
            if let Some(authority) = request.uri().authority() {
                let mut slot = self
                    .authority
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if slot.is_none() {
                    *slot = Some(authority.to_string());
                }
            }
            let fixture = self.clone();
            Box::pin(async move {
                let response = if request.uri().path() == RANGE_PATH {
                    let mut grpc = Grpc::new(ProstCodec::<RangeResponse, RangeRequest>::default());
                    grpc.unary(RangeHandler { fixture }, request).await
                } else {
                    unimplemented_reply()
                };
                Ok(response)
            })
        }
    }

    impl NamedService for KvFixture {
        const NAME: &'static str = KV_SERVICE_NAME;
    }

    /// The `unimplemented` gRPC reply for an unrouted path: HTTP 200 with a
    /// `grpc-status: 12` header and the gRPC content type, matching tonic's
    /// generated fallback.
    fn unimplemented_reply() -> http::Response<tonic::body::Body> {
        let mut response = http::Response::new(tonic::body::Body::default());
        let headers = response.headers_mut();
        headers.insert(
            tonic::Status::GRPC_STATUS,
            http::HeaderValue::from_static("12"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            tonic::metadata::GRPC_CONTENT_TYPE,
        );
        response
    }

    /// A running fixture: its bound address, the shared `Range` counter, and the
    /// captured `:authority` of the first request.
    struct Fixture {
        addr: SocketAddr,
        range_calls: Arc<AtomicUsize>,
        authority: Arc<Mutex<Option<String>>>,
    }

    /// Binds a loopback listener and serves the single-route KV adapter over each
    /// accepted connection, optionally wrapping the IO in a TLS acceptor. The
    /// accept loop is detached; the test process bounds its lifetime.
    fn spawn_fixture(
        acceptor: Option<TlsAcceptor>,
        expected_key: &[u8],
        response_value: &[u8],
    ) -> Fixture {
        let range_calls = Arc::new(AtomicUsize::new(0));
        let authority = Arc::new(Mutex::new(None));
        let fixture = KvFixture {
            expected_key: expected_key.to_vec(),
            response_value: response_value.to_vec(),
            range_calls: Arc::clone(&range_calls),
            authority: Arc::clone(&authority),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        tokio::spawn(async move {
            let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
                return;
            };
            let Ok(addr) = listener.local_addr() else {
                return;
            };
            if tx.send(addr).is_err() {
                return;
            }
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let fixture = fixture.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(serve_connection(stream, acceptor, fixture));
            }
        });
        let addr = rx
            .recv()
            .unwrap_or_else(|error| unreachable!("fixture bind: {error}"));
        Fixture {
            addr,
            range_calls,
            authority,
        }
    }

    /// Feeds one accepted connection (plain or after a TLS handshake) into the
    /// single-route KV adapter via hyper's HTTP/2 server, so tonic owns the gRPC
    /// framing and trailers.
    async fn serve_connection(
        stream: TcpStream,
        acceptor: Option<TlsAcceptor>,
        fixture: KvFixture,
    ) {
        let service = TowerToHyperService::new(fixture);
        let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        match acceptor {
            Some(acceptor) => {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = builder.serve_connection(TokioIo::new(tls), service).await;
            }
            None => {
                let _ = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        }
    }

    // ----- Certificate + rustls server helpers (condition 4) ----------------

    /// A self-signed CA PEM plus a reusable issuer for signing leaves.
    fn make_ca(common_name: &str) -> (String, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|error| unreachable!("ca params: {error}"));
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let key =
            rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("ca key: {error}"));
        let certificate = params
            .self_signed(&key)
            .unwrap_or_else(|error| unreachable!("ca self-signed: {error}"));
        let pem = certificate.pem();
        (pem, rcgen::Issuer::new(params, key))
    }

    /// Signs a leaf for `subject_alt` with `common_name`, as a server or client
    /// certificate. Returns the leaf and key PEM.
    fn make_leaf(
        issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
        common_name: &str,
        subject_alt: &str,
        server_auth: bool,
    ) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![subject_alt.to_owned()])
            .unwrap_or_else(|error| unreachable!("leaf params: {error}"));
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.extended_key_usages = vec![if server_auth {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        }];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let key =
            rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("leaf key: {error}"));
        let certificate = params
            .signed_by(&key, issuer)
            .unwrap_or_else(|error| unreachable!("leaf signed: {error}"));
        (certificate.pem(), key.serialize_pem())
    }

    fn parse_chain(pem: &str) -> Vec<CertificateDer<'static>> {
        let mut chain = Vec::new();
        for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            chain.push(
                certificate
                    .unwrap_or_else(|error| unreachable!("leaf cert: {error}"))
                    .into_owned(),
            );
        }
        chain
    }

    fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("leaf key: {error}"))
    }

    fn root_store(ca_pem: &str) -> Arc<rustls::RootCertStore> {
        let mut store = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            let certificate = certificate.unwrap_or_else(|error| unreachable!("ca cert: {error}"));
            store
                .add(certificate)
                .unwrap_or_else(|error| unreachable!("add root: {error}"));
        }
        Arc::new(store)
    }

    /// Builds a rustls-backed TLS acceptor for the fixture, optionally requiring
    /// a client certificate from `client_ca_pem` via `WebPkiClientVerifier`.
    fn tls_acceptor(cert_pem: &str, key_pem: &str, client_ca_pem: Option<&str>) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .unwrap_or_else(|error| unreachable!("server versions: {error}"));
        let builder = match client_ca_pem {
            Some(ca) => {
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(root_store(ca), provider)
                        .build()
                        .unwrap_or_else(|error| unreachable!("client verifier: {error}"));
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(parse_chain(cert_pem), parse_key(key_pem))
            .unwrap_or_else(|error| unreachable!("server cert: {error}"));
        TlsAcceptor::from(Arc::new(config))
    }

    // ----- Temp material + pipeline helpers ---------------------------------

    /// A fresh, unique temp directory used as both the TLS root and the config
    /// current directory.
    fn material_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cptopo-2b2-{tag}-{}-{}",
            std::process::id(),
            next_id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| unreachable!("mkdir: {error}"));
        dir
    }

    fn next_id() -> u64 {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        COUNTER.fetch_add(1, Ordering::SeqCst) as u64
    }

    /// Writes a PEM file into `dir`, returning its absolute path string.
    fn write_pem(dir: &Path, name: &str, pem: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("write pem: {error}"));
        path.to_str()
            .unwrap_or_else(|| unreachable!("temp path is not utf-8"))
            .to_owned()
    }

    /// Assembles a backend-cluster TOML with the given pd-addrs and an optional
    /// `security.cluster-tls` block.
    fn topology_toml(pd_addrs: &str, cluster_tls: &str) -> Vec<u8> {
        format!(
            r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = 100

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "cluster-a"
pd-addrs = "{pd_addrs}"
ns-servers = []
{cluster_tls}
"#
        )
        .into_bytes()
    }

    /// Runs the real validation pipeline over `toml` and returns the built,
    /// name-sorted cluster clients (each an [`EtcdClientConfig`]).
    fn build_clients(toml: &[u8], dir: &Path) -> Vec<TopologyClusterClient> {
        let roots = open_tls_roots(std::slice::from_ref(&dir.to_path_buf()));
        let store = ConfigNamespaceStore::from_toml_with_validator(
            toml,
            None,
            dir,
            Arc::new(TopologyCandidateValidator::new(Arc::new(roots))),
        )
        .unwrap_or_else(|error| unreachable!("pipeline validation: {error}"));
        ArtifactClusterFactory
            .build(&store.current())
            .unwrap_or_else(|error| unreachable!("cluster build: {error}"))
    }

    /// The single client the pipeline built, moved out of the cluster set.
    fn single_client(toml: &[u8], dir: &Path) -> EtcdClientConfig {
        let mut clusters = build_clients(toml, dir);
        assert_eq!(clusters.len(), 1, "exactly one backend cluster is built");
        clusters
            .pop()
            .unwrap_or_else(|| unreachable!("one cluster client"))
            .client
    }

    fn owner() -> (OwnershipRegistry, OwnerLease) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "wiring-owner")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        (registry, lease)
    }

    /// The owned projection of a `get` response the wiring tests assert on. The
    /// raw client response is decoded inside the fenced closure so no
    /// `etcd-client` type is named outside the transport crate.
    struct GetOutcome {
        kvs: Vec<(Vec<u8>, Vec<u8>)>,
        revision: Option<i64>,
    }

    /// Runs one owner-fenced `get` and decodes it into an owned [`GetOutcome`].
    async fn run_get(
        connection: &mut EtcdConnection,
        key: &[u8],
    ) -> Result<GetOutcome, EtcdOperationError> {
        let key = key.to_vec();
        connection
            .execute(move |client| {
                Box::pin(async move {
                    let response = client.get(key, None).await?;
                    let kvs = response
                        .kvs()
                        .iter()
                        .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                        .collect();
                    let mut revision = None;
                    if let Some(header) = response.header() {
                        revision = Some(header.revision());
                    }
                    Ok(GetOutcome { kvs, revision })
                })
            })
            .await
    }

    /// Connects for the exact owner and runs one fenced `get`, each await bounded
    /// so a wedged CI cannot hang.
    async fn connect_and_get(
        config: EtcdClientConfig,
        lease: &OwnerLease,
        key: &[u8],
    ) -> Result<GetOutcome, ConnectGetError> {
        let connector = EtcdConnector::new(lease.token(), config);
        let Ok(connected) =
            tokio::time::timeout(Duration::from_secs(10), connector.connect()).await
        else {
            unreachable!("connect must resolve within the deadline");
        };
        let mut connection = connected.map_err(|_| ConnectGetError::Connect)?;
        let Ok(result) =
            tokio::time::timeout(Duration::from_secs(10), run_get(&mut connection, key)).await
        else {
            unreachable!("get must resolve within the deadline");
        };
        result.map_err(|_| ConnectGetError::Operation)
    }

    /// A payload-free connect-or-get failure class for the wiring tests, which
    /// assert only success versus failure (D-(4) inspects the typed operation
    /// error directly instead).
    enum ConnectGetError {
        Connect,
        Operation,
    }

    /// Asserts a successful `get` decoded the fixture's known pair and non-zero
    /// header revision.
    fn assert_known_pair(outcome: &GetOutcome, key: &[u8], value: &[u8]) {
        assert_eq!(outcome.kvs.len(), 1, "one key-value is returned");
        let (decoded_key, decoded_value) = &outcome.kvs[0];
        assert_eq!(decoded_key.as_slice(), key, "the decoded key matches");
        assert_eq!(decoded_value.as_slice(), value, "the decoded value matches");
        let revision = outcome
            .revision
            .unwrap_or_else(|| unreachable!("a response header is present"));
        assert_eq!(
            revision, FIXTURE_REVISION,
            "the decoded header carries the fixture revision"
        );
    }

    const KEY: &[u8] = b"/topology/cluster-a/registry";
    const VALUE: &[u8] = b"member-registered";

    // ----- D-(1): typed-equality of the topology -> transport policy map ----

    #[test]
    fn d1_topology_maps_skip_common_name_and_minimum_version_into_the_policy() {
        // skip-CA + common-name pin + a 1.3 floor, all through the real pipeline.
        // Deleting any single mapping line changes the produced policy (or fails
        // the build), so this asserts each line is threaded.
        let dir = material_dir("d1-skip");
        let toml = topology_toml(
            "127.0.0.1:2379",
            "[security.cluster-tls]\nskip-ca = true\ncert-allowed-cn = [\"etcd-server\"]\nmin-tls-version = \"1.3\"",
        );
        let client = single_client(&toml, &dir);
        assert_eq!(
            client.tls_policy(),
            Some(&EtcdTlsPolicy {
                minimum_version: Some(EtcdTlsVersion::V1_3),
                allowed_common_names: vec!["etcd-server".to_owned()],
                skip_ca_verification: true,
            }),
            "skip-CA, the CN pin, and the 1.3 floor all reach the transport policy"
        );

        // A CA-verified variant proves the skip=false mapping as well.
        let ca_dir = material_dir("d1-ca");
        let (ca_pem, _issuer) = make_ca("wiring-ca");
        let ca_path = write_pem(&ca_dir, "ca.pem", &ca_pem);
        let ca_toml = topology_toml(
            "127.0.0.1:2379",
            &format!(
                "[security.cluster-tls]\nca = \"{ca_path}\"\ncert-allowed-cn = [\"etcd-server\"]\nmin-tls-version = \"1.2\""
            ),
        );
        let ca_client = single_client(&ca_toml, &ca_dir);
        assert_eq!(
            ca_client.tls_policy(),
            Some(&EtcdTlsPolicy {
                minimum_version: Some(EtcdTlsVersion::V1_2),
                allowed_common_names: vec!["etcd-server".to_owned()],
                skip_ca_verification: false,
            }),
            "a CA-verified policy maps skip=false with the CN pin and 1.2 floor"
        );
    }

    // ----- D-(2a): plaintext production wiring ------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d2a_plaintext_row_gets_through_the_real_pipeline() {
        let fixture = spawn_fixture(None, KEY, VALUE);
        let dir = material_dir("d2a");
        let toml = topology_toml(&format!("127.0.0.1:{}", fixture.addr.port()), "");
        let config = single_client(&toml, &dir);
        assert!(
            config.tls_policy().is_none(),
            "an empty cluster-tls stays plaintext"
        );

        let (_registry, lease) = owner();
        let Ok(response) = connect_and_get(config, &lease, KEY).await else {
            unreachable!("the plaintext get must succeed");
        };
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(fixture.range_calls.load(Ordering::SeqCst), 1);
    }

    // ----- D-(2b): advanced TLS = skip-CA + matching CN + TLS1.3 ------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d2b_advanced_tls_row_gets_and_wrong_cn_never_reaches_the_server() {
        let (_ca, issuer) = make_ca("wiring-ca");
        let (server_cert, server_key) = make_leaf(&issuer, "etcd-server", "127.0.0.1", true);
        let acceptor = tls_acceptor(&server_cert, &server_key, None);
        let fixture = spawn_fixture(Some(acceptor), KEY, VALUE);
        let endpoint = format!("127.0.0.1:{}", fixture.addr.port());

        // Matching CN over skip-CA at a 1.3 floor: the get succeeds.
        let ok_dir = material_dir("d2b-ok");
        let ok_toml = topology_toml(
            &endpoint,
            "[security.cluster-tls]\nskip-ca = true\ncert-allowed-cn = [\"etcd-server\"]\nmin-tls-version = \"1.3\"",
        );
        let ok_config = single_client(&ok_toml, &ok_dir);
        assert!(
            ok_config
                .tls_policy()
                .is_some_and(|policy| policy.skip_ca_verification),
            "skip-only still upgrades to TLS"
        );
        let (_registry, lease) = owner();
        let Ok(response) = connect_and_get(ok_config, &lease, KEY).await else {
            unreachable!("the matching-CN TLS get must succeed");
        };
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(fixture.range_calls.load(Ordering::SeqCst), 1);

        // A wrong CN pin fails the handshake, so no request reaches the server.
        let bad_dir = material_dir("d2b-bad");
        let bad_toml = topology_toml(
            &endpoint,
            "[security.cluster-tls]\nskip-ca = true\ncert-allowed-cn = [\"not-the-server\"]\nmin-tls-version = \"1.3\"",
        );
        let bad_config = single_client(&bad_toml, &bad_dir);
        let (_registry_bad, lease_bad) = owner();
        let result = connect_and_get(bad_config, &lease_bad, KEY).await;
        assert!(
            result.is_err(),
            "a non-matching CN pin fails the get at the TLS handshake"
        );
        assert_eq!(
            fixture.range_calls.load(Ordering::SeqCst),
            1,
            "the wrong-CN row never reached the server (still just the one earlier Range)"
        );
    }

    // ----- D-(2c): mTLS, server requires a client certificate ---------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d2c_mtls_row_presents_the_client_identity_from_config() {
        let (ca_pem, issuer) = make_ca("wiring-ca");
        let (server_cert, server_key) = make_leaf(&issuer, "etcd-server", "127.0.0.1", true);
        let (client_cert, client_key) = make_leaf(&issuer, "etcd-client", "127.0.0.1", false);
        let acceptor = tls_acceptor(&server_cert, &server_key, Some(&ca_pem));
        let fixture = spawn_fixture(Some(acceptor), KEY, VALUE);

        let dir = material_dir("d2c");
        let ca_path = write_pem(&dir, "ca.pem", &ca_pem);
        let cert_path = write_pem(&dir, "client-cert.pem", &client_cert);
        let key_path = write_pem(&dir, "client-key.pem", &client_key);
        let toml = topology_toml(
            &format!("127.0.0.1:{}", fixture.addr.port()),
            &format!(
                "[security.cluster-tls]\nca = \"{ca_path}\"\ncert = \"{cert_path}\"\nkey = \"{key_path}\""
            ),
        );
        let config = single_client(&toml, &dir);

        let (_registry, lease) = owner();
        let Ok(response) = connect_and_get(config, &lease, KEY).await else {
            unreachable!("the mTLS get must succeed with a client identity");
        };
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(fixture.range_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d2c_mtls_rejects_a_client_without_an_identity() {
        // The SAME require-client-cert server as the positive row, but the client
        // config carries only the CA — no client identity. The handshake must fail
        // and no Range must reach the server. Deleting the server's
        // with_client_cert_verifier (accepting no client auth) makes this row red.
        let (ca_pem, issuer) = make_ca("wiring-ca");
        let (server_cert, server_key) = make_leaf(&issuer, "etcd-server", "127.0.0.1", true);
        let acceptor = tls_acceptor(&server_cert, &server_key, Some(&ca_pem));
        let fixture = spawn_fixture(Some(acceptor), KEY, VALUE);

        let dir = material_dir("d2c-neg");
        let ca_path = write_pem(&dir, "ca.pem", &ca_pem);
        let toml = topology_toml(
            &format!("127.0.0.1:{}", fixture.addr.port()),
            &format!("[security.cluster-tls]\nca = \"{ca_path}\""),
        );
        let config = single_client(&toml, &dir);

        let (_registry, lease) = owner();
        // The rejected client may fail fast or its reconnect attempts may not
        // converge; either way it must never complete a get, and no Range may
        // reach the server. Bound it so a reconnecting client can't wedge CI.
        let outcome =
            tokio::time::timeout(Duration::from_secs(5), connect_and_get(config, &lease, KEY))
                .await;
        assert!(
            !matches!(outcome, Ok(Ok(_))),
            "a server requiring a client certificate never lets a no-identity client complete a get"
        );
        assert_eq!(
            fixture.range_calls.load(Ordering::SeqCst),
            0,
            "the mTLS-rejected client never reaches the Range handler"
        );
    }

    // ----- D-(3): multi-endpoint + caller retry -----------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d3_multi_endpoint_caller_retry_reaches_live_server_once() {
        let fixture = spawn_fixture(None, KEY, VALUE);
        let dead = dead_addr().await;
        let dir = material_dir("d3");
        // One endpoint refuses and one is live; normalization may reorder them.
        let toml = topology_toml(
            &format!(
                "127.0.0.1:{},127.0.0.1:{}",
                dead.port(),
                fixture.addr.port()
            ),
            "",
        );
        let config = single_client(&toml, &dir);
        assert_eq!(config.endpoints().len(), 2, "two endpoints are configured");

        let (_registry, lease) = owner();
        let connector = EtcdConnector::new(lease.token(), config);
        let Ok(Ok(mut connection)) =
            tokio::time::timeout(Duration::from_secs(10), connector.connect()).await
        else {
            unreachable!("connect must resolve within the deadline");
        };

        // Caller-retry failover, not single-RPC transparent failover: a dispatched
        // call is never replayed to another endpoint. At most two gets converge —
        // p2c may pick the live endpoint first (immediate success), or the dead one
        // first (that call fails, and failure-load backoff then de-prefers it so the
        // second get is steered to the healthy live endpoint). The structural seam
        // test (build_endpoint_services) separately locks that both endpoints enter
        // the stack; this row asserts the composed semantic outcome.
        let mut response = None;
        for _ in 0..2 {
            let Ok(attempt) =
                tokio::time::timeout(Duration::from_secs(5), run_get(&mut connection, KEY)).await
            else {
                unreachable!("each get attempt must resolve within the deadline");
            };
            if let Ok(ok) = attempt {
                response = Some(ok);
                break;
            }
        }
        let response = response.unwrap_or_else(|| unreachable!("the live endpoint must answer"));
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(
            fixture.range_calls.load(Ordering::SeqCst),
            1,
            "the live server received exactly one Range"
        );
    }

    /// A bound-then-dropped loopback port that reliably refuses connections.
    async fn dead_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        drop(listener);
        addr
    }

    // ----- D-(4): owner retired after connect, before execute ---------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d4_owner_retired_before_execute_never_reaches_the_server() {
        let fixture = spawn_fixture(None, KEY, VALUE);
        let dir = material_dir("d4");
        let toml = topology_toml(&format!("127.0.0.1:{}", fixture.addr.port()), "");
        let config = single_client(&toml, &dir);

        let (_registry, lease) = owner();
        let connector = EtcdConnector::new(lease.token(), config);
        let Ok(Ok(mut connection)) =
            tokio::time::timeout(Duration::from_secs(10), connector.connect()).await
        else {
            unreachable!("connect must resolve while the owner is current");
        };

        // Retire the owner after connect() returned but before the operation.
        lease.release();
        let Ok(result) =
            tokio::time::timeout(Duration::from_secs(10), run_get(&mut connection, KEY)).await
        else {
            unreachable!("execute must resolve promptly for a retired owner");
        };
        assert!(
            matches!(result, Err(EtcdOperationError::StaleOwner)),
            "a retired owner fails execute closed before any RPC"
        );
        assert_eq!(
            fixture.range_calls.load(Ordering::SeqCst),
            0,
            "no request ever reached the server"
        );
    }

    // ----- Rows 7 & 8: explicit-nameserver resolution in the KV pipeline -----

    /// A running loopback UDP nameserver. tiproxy-rs carries no DNS dependency, so
    /// the wire codec is hand-rolled: every `A` query is answered `127.0.0.1` and
    /// every other qtype (the concurrent `AAAA`) is NODATA. Observed `A` queries
    /// are counted so a row can prove the target went through this nameserver.
    struct LoopbackDns {
        /// The read-back UDP port the cluster's `ns-servers` point at.
        port: u16,
        /// Observed `A` queries.
        a_queries: Arc<AtomicUsize>,
    }

    /// Parses a query into `(id, qtype, question_bytes)`; the question section
    /// begins at offset 12 and is echoed verbatim into the response.
    fn parse_dns_query(buffer: &[u8]) -> Option<(u16, u16, &[u8])> {
        if buffer.len() < 12 {
            return None;
        }
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let mut cursor = 12;
        loop {
            let label_len = usize::from(*buffer.get(cursor)?);
            if label_len == 0 {
                break;
            }
            cursor += 1 + label_len;
        }
        // `cursor` indexes the zero-length root label; QTYPE/QCLASS follow it.
        let qtype = u16::from_be_bytes([*buffer.get(cursor + 1)?, *buffer.get(cursor + 2)?]);
        let question_end = cursor + 5;
        if question_end > buffer.len() {
            return None;
        }
        Some((id, qtype, &buffer[12..question_end]))
    }

    /// Builds an authoritative response echoing the question. An `A` query
    /// (qtype 1) carries one `127.0.0.1` answer; anything else is NODATA.
    fn build_dns_response(id: u16, qtype: u16, question: &[u8]) -> Vec<u8> {
        const QTYPE_A: u16 = 1;
        let mut out = Vec::with_capacity(28 + question.len());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&[0x84, 0x00]); // QR=1, AA=1, RCODE=NoError
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&u16::from(qtype == QTYPE_A).to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out.extend_from_slice(question);
        if qtype == QTYPE_A {
            out.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to the question
            out.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE A
            out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            out.extend_from_slice(&30u32.to_be_bytes()); // TTL
            out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            out.extend_from_slice(&[127, 0, 0, 1]); // RDATA 127.0.0.1
        }
        out
    }

    /// Binds the loopback nameserver on `127.0.0.1:0` and detaches its loop.
    async fn spawn_loopback_dns() -> LoopbackDns {
        use std::net::Ipv4Addr;
        use tokio::net::UdpSocket;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind dns: {error}"));
        let port = socket
            .local_addr()
            .unwrap_or_else(|error| unreachable!("dns addr: {error}"))
            .port();
        let a_queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&a_queries);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let Some((id, qtype, question)) = parse_dns_query(&buffer[..len]) else {
                    continue;
                };
                if qtype == 1 {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let response = build_dns_response(id, qtype, question);
                let _ = socket.send_to(&response, src).await;
            }
        });
        LoopbackDns { port, a_queries }
    }

    /// Like [`topology_toml`] but with explicit `ns-servers` on the cluster.
    fn topology_toml_ns(pd_addrs: &str, ns_servers: &str, cluster_tls: &str) -> Vec<u8> {
        format!(
            r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = 100

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "cluster-a"
pd-addrs = "{pd_addrs}"
ns-servers = [{ns_servers}]
{cluster_tls}
"#
        )
        .into_bytes()
    }

    /// A self-signed server certificate (PEM chain + key) with `hostname` in SAN.
    fn self_signed_server_cert(hostname: &str) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![hostname.to_owned()])
            .unwrap_or_else(|error| unreachable!("cert params: {error}"));
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("key: {error}"));
        let certificate = params
            .self_signed(&key)
            .unwrap_or_else(|error| unreachable!("self-signed: {error}"));
        (certificate.pem(), key.serialize_pem())
    }

    /// A server certificate resolver that records the observed `ClientHello` SNI.
    struct SniRecorder {
        observed: Arc<Mutex<Option<String>>>,
        certified: Arc<CertifiedKey>,
    }

    impl std::fmt::Debug for SniRecorder {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("SniRecorder")
                .finish_non_exhaustive()
        }
    }

    impl ResolvesServerCert for SniRecorder {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            *self
                .observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                client_hello.server_name().map(str::to_owned);
            Some(Arc::clone(&self.certified))
        }
    }

    /// Builds a TLS acceptor whose resolver records the negotiated SNI.
    fn sni_recording_acceptor(
        cert_pem: &str,
        key_pem: &str,
        observed: Arc<Mutex<Option<String>>>,
    ) -> TlsAcceptor {
        let certificate = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("cert: {error}"))
            .into_owned();
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("key: {error}"));
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
            .unwrap_or_else(|error| unreachable!("signing key: {error}"));
        let certified = Arc::new(CertifiedKey::new(vec![certificate], signing));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .unwrap_or_else(|error| unreachable!("server versions: {error}"))
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniRecorder {
                observed,
                certified,
            }));
        TlsAcceptor::from(Arc::new(config))
    }

    // ----- Row 7: system-DNS-unresolvable target reached via explicit NS -----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row7_target_resolves_through_the_explicit_nameserver() {
        let fixture = spawn_fixture(None, KEY, VALUE);
        let dns = spawn_loopback_dns().await;
        let dir = material_dir("row7");
        // `etcd.invalid` never resolves through the system resolver (RFC 6761), so
        // the only path to the fixture is the explicit loopback nameserver.
        let toml = topology_toml_ns(
            &format!("etcd.invalid:{}", fixture.addr.port()),
            &format!("\"127.0.0.1:{}\"", dns.port),
            "",
        );
        let config = single_client(&toml, &dir);

        let (_registry, lease) = owner();
        let Ok(response) = connect_and_get(config, &lease, KEY).await else {
            unreachable!("the get must succeed via the explicit nameserver");
        };
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(fixture.range_calls.load(Ordering::SeqCst), 1);
        assert!(
            dns.a_queries.load(Ordering::SeqCst) >= 1,
            "the explicit nameserver received the target's A query"
        );
    }

    // ----- Row 8: logical host drives SNI + :authority, never the resolved IP -

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row8_logical_host_drives_sni_and_authority_not_the_resolved_ip() {
        let (cert_pem, key_pem) = self_signed_server_cert("etcd.internal");
        let observed_sni = Arc::new(Mutex::new(None));
        let acceptor = sni_recording_acceptor(&cert_pem, &key_pem, Arc::clone(&observed_sni));
        let fixture = spawn_fixture(Some(acceptor), KEY, VALUE);
        let dns = spawn_loopback_dns().await;
        let dir = material_dir("row8");
        // The explicit nameserver maps the logical host `etcd.internal` to
        // 127.0.0.1, but the logical host must remain the SNI and :authority.
        let toml = topology_toml_ns(
            &format!("etcd.internal:{}", fixture.addr.port()),
            &format!("\"127.0.0.1:{}\"", dns.port),
            "[security.cluster-tls]\nskip-ca = true",
        );
        let config = single_client(&toml, &dir);
        assert!(
            config
                .tls_policy()
                .is_some_and(|policy| policy.skip_ca_verification),
            "skip-ca upgrades this cluster to TLS"
        );

        let (_registry, lease) = owner();
        let Ok(response) = connect_and_get(config, &lease, KEY).await else {
            unreachable!("the TLS get must succeed via the explicit nameserver");
        };
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(fixture.range_calls.load(Ordering::SeqCst), 1);
        assert!(
            dns.a_queries.load(Ordering::SeqCst) >= 1,
            "the explicit nameserver resolved etcd.internal"
        );

        let sni = observed_sni
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            sni.as_deref(),
            Some("etcd.internal"),
            "the ClientHello SNI is the logical host, not the resolved IP"
        );

        let authority = fixture
            .authority
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let authority =
            authority.unwrap_or_else(|| unreachable!("the server recorded an :authority"));
        assert!(
            authority.contains("etcd.internal"),
            "the HTTP/2 :authority is the logical host: {authority}"
        );
        assert!(
            !authority.contains("127.0.0.1"),
            "the HTTP/2 :authority is never the resolved IP: {authority}"
        );
    }
}
