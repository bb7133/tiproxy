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

    /// The responder loop for one bound socket, shared by the v4 and v6 listeners.
    async fn dns_responder(socket: tokio::net::UdpSocket, counter: Arc<AtomicUsize>) {
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
    }

    /// Binds the loopback nameserver on `127.0.0.1:0`, learns the port, then also
    /// binds `[::1]:P` best-effort so a hostname nameserver (`localhost` resolves
    /// to both `127.0.0.1` and `::1`) is answered promptly on either family.
    async fn spawn_loopback_dns() -> LoopbackDns {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use tokio::net::UdpSocket;
        let v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind dns: {error}"));
        let port = v4
            .local_addr()
            .unwrap_or_else(|error| unreachable!("dns addr: {error}"))
            .port();
        let a_queries = Arc::new(AtomicUsize::new(0));
        tokio::spawn(dns_responder(v4, Arc::clone(&a_queries)));
        if let Ok(v6) = UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).await {
            tokio::spawn(dns_responder(v6, Arc::clone(&a_queries)));
        }
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

    // ----- Row 9: a HOSTNAME nameserver is bootstrapped in the KV pipeline ---

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row9_hostname_nameserver_is_bootstrapped_in_the_pipeline() {
        let fixture = spawn_fixture(None, KEY, VALUE);
        let dns = spawn_loopback_dns().await;
        let dir = material_dir("row9");
        // The nameserver is a HOSTNAME ("localhost"), so the production dialer must
        // run the real system bootstrap ("localhost" -> 127.0.0.1/::1) before it
        // can reach the loopback DNS server; the target `etcd.invalid` is itself
        // system-unresolvable and reachable only through that explicit nameserver.
        let toml = topology_toml_ns(
            &format!("etcd.invalid:{}", fixture.addr.port()),
            &format!("\"localhost:{}\"", dns.port),
            "",
        );
        let config = single_client(&toml, &dir);

        let (_registry, lease) = owner();
        let Ok(response) = connect_and_get(config, &lease, KEY).await else {
            unreachable!("the get must succeed via the bootstrapped hostname nameserver");
        };
        assert_known_pair(&response, KEY, VALUE);
        assert_eq!(fixture.range_calls.load(Ordering::SeqCst), 1);
        assert!(
            dns.a_queries.load(Ordering::SeqCst) >= 1,
            "the target's A query reached the bootstrapped localhost nameserver"
        );
    }
}

/// Same-epoch discovery wiring: the real pipeline
/// `TopologyCandidateValidator -> ArtifactClusterFactory -> TopologyModule ->
/// DiscoveryHandle` must surface a discovered `TiDB` backend AND the seeded
/// Prometheus endpoint at the SAME source client epoch.
///
/// The fixture is the same hand-rolled single-route tonic etcd v3 `KV.Range`
/// adapter used elsewhere, but with real prefix-range semantics (mirroring
/// `control-topology/tests/prometheus_etcd.rs`): an empty `range_end` is an
/// exact get, otherwise a half-open `key <= k < range_end`, sorted ascending.
/// It serves the `/topology/tidb/` + `/keyspaces/tidb/` topology reads and the
/// `/topology/prometheus` read from one seeded key space, so both discovery
/// polls resolve against the exact same published epoch's connection.
///
/// The module is driven through its real self-registration path: the registrar
/// child retries harmlessly against a Range-only fixture (its lease `Grant`/`Put`
/// are `unimplemented`), and because that child only exits on owner loss, its
/// failing writes never fail the module — it stays ready and its discovery
/// publication is live.
#[cfg(test)]
mod discovery_same_epoch {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use control_config::{ConfigNamespaceSource, ConfigNamespaceStore, TopologyRuntimeIdentity};
    use control_plane::{
        ControlConfig, ControlModule, ControlRuntime, EventSink, LogLevel, MetricsPolicy,
        OwnershipRegistry, RuntimeEvent, TlsPolicy,
    };
    use control_topology::{StaticAdvertiseResolver, TopologyModule};
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    use tokio::net::{TcpListener, TcpStream};
    use tonic::codegen::{BoxFuture, Context, Poll, Service, http};
    use tonic::server::{Grpc, NamedService, UnaryService};
    use tonic_prost::ProstCodec;

    use super::{ArtifactClusterFactory, TopologyCandidateValidator};
    use crate::tls_material::open_tls_roots;

    /// The etcd v3 `Range` unary gRPC method path the pinned client calls.
    const RANGE_PATH: &str = "/etcdserverpb.KV/Range";
    /// The gRPC service name the pinned client routes against.
    const KV_SERVICE_NAME: &str = "etcdserverpb.KV";
    /// The backend cluster name shared by the config, the discovery poll, and the
    /// Prometheus poll.
    const CLUSTER_NAME: &str = "cluster-a";
    /// The seeded `TiDB` backend's SQL address (its `/topology/tidb/<addr>` key).
    const TIDB_ADDR: &str = "10.0.0.9:4000";

    // ----- Wire-compatible etcd v3 messages (etcd 0.20.0 field tags) --------

    /// `etcdserverpb.RangeRequest`: both `key` (tag 1) and `range_end` (tag 2)
    /// are read so the fixture evaluates real range semantics.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct RangeRequest {
        #[prost(bytes = "vec", tag = "1")]
        key: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        range_end: Vec<u8>,
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

    // ----- The single-route etcd v3 KV fixture with real range semantics ----

    /// Shared fixture state: the seeded key/value pairs the `Range` handler
    /// filters with real prefix-range semantics.
    #[derive(Clone)]
    struct KvFixture {
        seeded: Arc<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    /// Evaluates enough etcd `Range` semantics for the pipeline: an empty
    /// `range_end` is an exact get (`k == key`), otherwise a half-open range
    /// (`key <= k < range_end`). Matches are returned ascending by key.
    fn range_scan(
        seeded: &[(Vec<u8>, Vec<u8>)],
        key: &[u8],
        range_end: &[u8],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut hits: Vec<(Vec<u8>, Vec<u8>)> = seeded
            .iter()
            .filter(|(k, _)| {
                if range_end.is_empty() {
                    k.as_slice() == key
                } else {
                    k.as_slice() >= key && k.as_slice() < range_end
                }
            })
            .cloned()
            .collect();
        hits.sort_by(|(a, _), (b, _)| a.cmp(b));
        hits
    }

    /// The `Range` unary handler: it answers the seeded key/values selected by
    /// real range semantics, ascending by key.
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
                let matches = range_scan(&fixture.seeded, &message.key, &message.range_end);
                let count = i64::try_from(matches.len()).unwrap_or(i64::MAX);
                let kvs = matches
                    .into_iter()
                    .map(|(key, value)| KeyValue {
                        key,
                        value,
                        ..KeyValue::default()
                    })
                    .collect();
                let header = ResponseHeader {
                    cluster_id: 7,
                    member_id: 11,
                    revision: 42,
                    raft_term: 3,
                };
                Ok(tonic::Response::new(RangeResponse {
                    header: Some(header),
                    kvs,
                    more: false,
                    count,
                }))
            })
        }
    }

    /// The `Range` route uses a prost codec; any other path (the registrar's
    /// lease `Grant`/`Put`) returns tonic's `unimplemented` reply, so the child
    /// retries harmlessly without ever fixing a write.
    impl Service<http::Request<Incoming>> for KvFixture {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Infallible>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
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
    /// `grpc-status: 12` header and the gRPC content type.
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

    /// Binds a loopback listener and serves the single-route KV adapter over each
    /// accepted plaintext connection. The accept loop is detached; the test
    /// process bounds its lifetime.
    async fn spawn_fixture(seeded: Vec<(Vec<u8>, Vec<u8>)>) -> Option<SocketAddr> {
        let fixture = KvFixture {
            seeded: Arc::new(seeded),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve_connection(stream, fixture.clone()));
            }
        });
        Some(addr)
    }

    /// Feeds one accepted plaintext connection into the single-route KV adapter
    /// via hyper's HTTP/2 server, so tonic owns the gRPC framing and trailers.
    async fn serve_connection(stream: TcpStream, fixture: KvFixture) {
        let service = TowerToHyperService::new(fixture);
        let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        let _ = builder
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    fn kv(key: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
        (key.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    /// An `EventSink` that drops every event, keeping test output clean.
    struct NullSink;
    impl EventSink for NullSink {
        fn record(&self, _event: &RuntimeEvent) {}
    }

    fn identity() -> TopologyRuntimeIdentity {
        TopologyRuntimeIdentity {
            version: Arc::from("v-test"),
            git_hash: Arc::from("hash-test"),
            deploy_path: PathBuf::from("/deploy/test"),
            start_timestamp: 1_700_000_000,
        }
    }

    /// A fresh, unique temp directory used as both the TLS root and the config
    /// current directory.
    fn material_dir() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cptopo-same-epoch-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| unreachable!("mkdir: {error}"));
        dir
    }

    /// A one-backend-cluster topology TOML whose PD points at the fixture,
    /// plaintext (no `security.cluster-tls`).
    fn topology_toml(pd_addrs: &str) -> Vec<u8> {
        format!(
            r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = 100

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "{CLUSTER_NAME}"
pd-addrs = "{pd_addrs}"
ns-servers = []
"#
        )
        .into_bytes()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tidb_and_prometheus_discovery_share_the_source_epoch() {
        let body = async {
            // One key space serves both the TiDB topology (info + a live ttl
            // sibling) and the Prometheus endpoint, so both polls read the same
            // published epoch's connection.
            let seeded = vec![
                kv(
                    &format!("/topology/tidb/{TIDB_ADDR}/info"),
                    r#"{"ip":"10.0.0.9","status_port":10080,"version":"v8","git_hash":"abc","deploy_path":"/d","start_timestamp":42,"labels":{"zone":"z1"}}"#,
                ),
                kv(&format!("/topology/tidb/{TIDB_ADDR}/ttl"), "173000000000"),
                kv("/topology/prometheus/x", r#"{"ip":"1.2.3.4","port":9090}"#),
            ];
            let Some(addr) = spawn_fixture(seeded).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };

            // The REAL pipeline: validator -> factory -> module. The config's PD
            // points at the fixture; validation prepares the plaintext client set,
            // the factory downcasts it, and the module publishes epoch 0.
            let dir = material_dir();
            let toml = topology_toml(&format!("127.0.0.1:{}", addr.port()));
            let roots = open_tls_roots(std::slice::from_ref(&dir));
            let store = ConfigNamespaceStore::from_toml_with_validator(
                &toml,
                None,
                &dir,
                Arc::new(TopologyCandidateValidator::new(Arc::new(roots))),
            )
            .unwrap_or_else(|error| unreachable!("pipeline validation: {error}"));

            let registry = Box::leak(Box::new(OwnershipRegistry::new()));
            let config = ControlConfig::new(
                1,
                Duration::from_secs(30),
                0,
                TlsPolicy::default(),
                LogLevel::Info,
                MetricsPolicy::default(),
            )
            .unwrap_or_else(|error| unreachable!("control config: {error}"));
            let runtime = ControlRuntime::claim_process(
                registry,
                "cptopo-same-epoch",
                config,
                Arc::new(NullSink),
            )
            .unwrap_or_else(|error| unreachable!("claim process: {error}"));

            let source: Arc<dyn ConfigNamespaceSource> = Arc::new(store);
            let (module, mut handle) = TopologyModule::new(
                source,
                Box::new(ArtifactClusterFactory),
                Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
                identity(),
                control_config::HealthCheckConfig::default(),
            )
            .unwrap_or_else(|error| unreachable!("pinned health config is valid: {error}"));
            let context = runtime.handle().module_context();
            runtime
                .mark_ready()
                .unwrap_or_else(|error| unreachable!("mark ready: {error}"));
            let task = tokio::spawn(Box::new(module).run(context));

            // The registrar child cannot write to a Range-only fixture, but that
            // never fails the module: readiness means the plan's children are
            // installed and the discovery epoch is published.
            handle
                .wait_ready()
                .await
                .unwrap_or_else(|error| unreachable!("module ready: {error}"));
            assert!(
                !task.is_finished(),
                "the module stays ready despite the registrar retrying its writes"
            );

            let discovery = handle.discovery_handle();

            // TiDB discovery: the real merged-topology poll finds the seeded,
            // liveness-gated backend under this cluster.
            let merged = discovery
                .poll_merged_topology()
                .await
                .unwrap_or_else(|error| unreachable!("merged topology poll: {error:?}"));
            assert_eq!(merged.value.backends.len(), 1, "one backend is discovered");
            let backend = &merged.value.backends[0];
            assert_eq!(backend.cluster_name.as_ref(), CLUSTER_NAME);
            assert_eq!(backend.backend.addr, TIDB_ADDR);
            assert_eq!(backend.backend.ip, "10.0.0.9");
            assert_eq!(backend.backend.status_port, 10080);

            // Prometheus discovery: the real prometheus poll on the SAME cluster
            // finds the seeded endpoint.
            let prom = discovery
                .poll_prometheus(CLUSTER_NAME)
                .await
                .unwrap_or_else(|error| unreachable!("prometheus poll: {error:?}"));
            assert_eq!(prom.value.ip, "1.2.3.4");
            assert_eq!(prom.value.port, 9090);

            // The load-bearing assertion: both reads came from the same source
            // client epoch, so a consumer can never mix two epochs' data.
            assert_eq!(
                merged.client_epoch, prom.client_epoch,
                "the TiDB and Prometheus discovery reads share one source epoch"
            );

            task.abort();
        };
        if tokio::time::timeout(Duration::from_secs(5), body)
            .await
            .is_err()
        {
            unreachable!("the same-epoch discovery pipeline completes within the deadline");
        }
    }
}

/// Real-composition proof of the #214 routing-generation semantics.
///
/// Drives the FULL public path only — `TopologyCandidateValidator` →
/// `ConfigNamespaceStore` → `ControlRuntime` → `TopologyModule::new` (real
/// `ArtifactClusterFactory` + real connector + registrar + the 214-2 refresh
/// loop) → `ControlModule::run` → `TopologyModuleHandle` — and observes the
/// routing source ONLY through `handle.routing_handle()`. The initial snapshot
/// comes from the refresh loop's own `wait_first`, never a hand poll.
///
/// The KV fixture is mutable (its served `/topology/tidb/...` keys are swappable
/// at runtime) and counts + signals each `TiDB`-prefix Range, so the paused-clock
/// drain is structured (waits on a real Range event and the observed routing
/// generation), never a sleep or yield count.
#[cfg(test)]
mod routing_generation_semantics {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use control_config::{ConfigNamespaceSource, ConfigNamespaceStore, TopologyRuntimeIdentity};
    use control_plane::{
        ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
        MetricsPolicy, ModuleError, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
    };
    use control_topology::{
        RoutingSnapshot, RoutingSnapshotHandle, StaticAdvertiseResolver, TopologyModule,
        TopologyModuleHandle, TopologyStatus,
    };
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Notify, oneshot, watch};
    use tonic::codegen::{BoxFuture, Context, Poll, Service, http};
    use tonic::server::{Grpc, NamedService, UnaryService};
    use tonic_prost::ProstCodec;

    use super::{ArtifactClusterFactory, TopologyCandidateValidator};
    use crate::tls_material::open_tls_roots;

    const RANGE_PATH: &str = "/etcdserverpb.KV/Range";
    const KV_SERVICE_NAME: &str = "etcdserverpb.KV";
    const CLUSTER_NAME: &str = "cluster-a";
    const ADDR_A: &str = "10.0.0.1:4000";
    const ADDR_B: &str = "10.0.0.2:4000";
    /// The classic `TiDB` topology prefix a merged poll reads first.
    const TIDB_PREFIX: &[u8] = b"/topology/tidb/";
    /// Mirrors the private production `ROUTING_REFRESH_INTERVAL` (3s); advancing
    /// the paused clock by it fires the refresh loop's next tick.
    const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

    // ----- Wire-compatible etcd v3 messages (etcd 0.20.0 field tags) --------

    #[derive(Clone, PartialEq, ::prost::Message)]
    struct RangeRequest {
        #[prost(bytes = "vec", tag = "1")]
        key: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        range_end: Vec<u8>,
    }

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

    // ----- The mutable, per-prefix-counting KV fixture ----------------------

    /// A seeded etcd key space (raw key/value bytes).
    type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

    /// A KV fixture whose served keys are swappable at runtime; each `TiDB`-prefix
    /// Range bumps a counter and fires `served`, so a structured drain can wait on
    /// a real refresh poll.
    #[derive(Clone)]
    struct KvFixture {
        seeded: Arc<Mutex<KvPairs>>,
        /// Bumped, and `served` fired, the moment a `TiDB`-prefix Range handler is
        /// ENTERED — i.e. before the response exists or the client can publish.
        tidb_ranges: Arc<AtomicUsize>,
        served: Arc<Notify>,
        /// A test-controlled response gate: a `TiDB` Range handler parks on it after
        /// entry until it is open. Open by default; the paused-vs-real discriminator
        /// closes it to hold a poll in flight deterministically (no wall sleep, no
        /// thread scheduling).
        gate: Arc<watch::Sender<bool>>,
    }

    impl KvFixture {
        fn swap(&self, new: KvPairs) {
            *self.seeded.lock().unwrap_or_else(PoisonError::into_inner) = new;
        }

        fn tidb_range_count(&self) -> usize {
            self.tidb_ranges.load(Ordering::SeqCst)
        }

        fn close_gate(&self) {
            self.gate.send_replace(false);
        }

        fn open_gate(&self) {
            self.gate.send_replace(true);
        }
    }

    fn range_scan(
        seeded: &[(Vec<u8>, Vec<u8>)],
        key: &[u8],
        range_end: &[u8],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut hits: Vec<(Vec<u8>, Vec<u8>)> = seeded
            .iter()
            .filter(|(k, _)| {
                if range_end.is_empty() {
                    k.as_slice() == key
                } else {
                    k.as_slice() >= key && k.as_slice() < range_end
                }
            })
            .cloned()
            .collect();
        hits.sort_by(|(a, _), (b, _)| a.cmp(b));
        hits
    }

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
                // Snapshot the (mutable) seeded set under the lock, then release it
                // before any further work — the lock is never held across an await.
                let snapshot = {
                    fixture
                        .seeded
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone()
                };
                if message.key.as_slice() == TIDB_PREFIX {
                    fixture.tidb_ranges.fetch_add(1, Ordering::SeqCst);
                    fixture.served.notify_one();
                    // Hold the response until the gate is open (open by default).
                    let mut gate = fixture.gate.subscribe();
                    while !*gate.borrow_and_update() {
                        if gate.changed().await.is_err() {
                            break;
                        }
                    }
                }
                let matches = range_scan(&snapshot, &message.key, &message.range_end);
                let count = i64::try_from(matches.len()).unwrap_or(i64::MAX);
                let kvs = matches
                    .into_iter()
                    .map(|(key, value)| KeyValue {
                        key,
                        value,
                        ..KeyValue::default()
                    })
                    .collect();
                let header = ResponseHeader {
                    cluster_id: 7,
                    member_id: 11,
                    revision: 42,
                    raft_term: 3,
                };
                Ok(tonic::Response::new(RangeResponse {
                    header: Some(header),
                    kvs,
                    more: false,
                    count,
                }))
            })
        }
    }

    impl Service<http::Request<Incoming>> for KvFixture {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Infallible>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
            let fixture = self.clone();
            Box::pin(async move {
                let response = if request.uri().path() == RANGE_PATH {
                    let mut grpc = Grpc::new(ProstCodec::<RangeResponse, RangeRequest>::default());
                    grpc.unary(RangeHandler { fixture }, request).await
                } else {
                    // The registrar's lease Grant/Put land here and retry harmlessly.
                    unimplemented_reply()
                };
                Ok(response)
            })
        }
    }

    impl NamedService for KvFixture {
        const NAME: &'static str = KV_SERVICE_NAME;
    }

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

    /// Binds a loopback listener and serves the mutable fixture over each accepted
    /// plaintext connection. Returns the fixture handle (for runtime swaps) and the
    /// bound address.
    async fn spawn_fixture(seeded: Vec<(Vec<u8>, Vec<u8>)>) -> Option<(KvFixture, SocketAddr)> {
        let fixture = KvFixture {
            seeded: Arc::new(Mutex::new(seeded)),
            tidb_ranges: Arc::new(AtomicUsize::new(0)),
            served: Arc::new(Notify::new()),
            gate: Arc::new(watch::channel(true).0),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        let serving = fixture.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve_connection(stream, serving.clone()));
            }
        });
        Some((fixture, addr))
    }

    async fn serve_connection(stream: TcpStream, fixture: KvFixture) {
        let service = TowerToHyperService::new(fixture);
        let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        let _ = builder
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    fn kv(key: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
        (key.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    /// The `info` + live `ttl` pair for one backend at `addr` advertising `ip`.
    fn backend_kvs(addr: &str, ip: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            kv(
                &format!("/topology/tidb/{addr}/info"),
                &format!(r#"{{"ip":"{ip}","status_port":10080,"version":"v8"}}"#),
            ),
            kv(&format!("/topology/tidb/{addr}/ttl"), "173000000000"),
        ]
    }

    /// The seeded key space for the given backends (`(addr, ip)` pairs).
    fn seed(backends: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        backends
            .iter()
            .flat_map(|(addr, ip)| backend_kvs(addr, ip))
            .collect()
    }

    /// The discovered backend addresses of a routing snapshot, in published order.
    fn addrs(snapshot: &RoutingSnapshot) -> Vec<String> {
        snapshot
            .backends
            .backends
            .iter()
            .map(|b| b.backend.addr.clone())
            .collect()
    }

    struct NullSink;
    impl EventSink for NullSink {
        fn record(&self, _event: &RuntimeEvent) {}
    }

    fn identity() -> TopologyRuntimeIdentity {
        TopologyRuntimeIdentity {
            version: Arc::from("v-test"),
            git_hash: Arc::from("hash-test"),
            deploy_path: PathBuf::from("/deploy/test"),
            start_timestamp: 1_700_000_000,
        }
    }

    fn material_dir() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cptopo-routing-gen-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| unreachable!("mkdir: {error}"));
        dir
    }

    /// A one-cluster topology TOML with the given PD address and `ns-servers`
    /// literal list (empty string for none).
    fn topology_toml(pd_addrs: &str, ns_servers: &str) -> Vec<u8> {
        format!(
            r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = 100

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "{CLUSTER_NAME}"
pd-addrs = "{pd_addrs}"
ns-servers = [{ns_servers}]
"#
        )
        .into_bytes()
    }

    /// A live composition, driven ONLY through the real public path.
    struct Composition {
        handle: TopologyModuleHandle,
        routing: RoutingSnapshotHandle,
        store: ConfigNamespaceStore,
        dir: PathBuf,
        task: tokio::task::JoinHandle<Result<(), ModuleError>>,
        runtime: ControlRuntime,
    }

    /// Builds the real pipeline against `addr` and waits for module readiness.
    async fn build_composition(addr: SocketAddr, ns_servers: &str) -> Composition {
        let dir = material_dir();
        let toml = topology_toml(&format!("127.0.0.1:{}", addr.port()), ns_servers);
        let roots = open_tls_roots(std::slice::from_ref(&dir));
        let store = ConfigNamespaceStore::from_toml_with_validator(
            &toml,
            None,
            &dir,
            Arc::new(TopologyCandidateValidator::new(Arc::new(roots))),
        )
        .unwrap_or_else(|error| unreachable!("pipeline validation: {error}"));

        let registry = Box::leak(Box::new(OwnershipRegistry::new()));
        let config = ControlConfig::new(
            1,
            Duration::from_secs(30),
            0,
            TlsPolicy::default(),
            LogLevel::Info,
            MetricsPolicy::default(),
        )
        .unwrap_or_else(|error| unreachable!("control config: {error}"));
        let runtime = ControlRuntime::claim_process(
            registry,
            "cptopo-routing-gen",
            config,
            Arc::new(NullSink),
        )
        .unwrap_or_else(|error| unreachable!("claim process: {error}"));

        let source: Arc<dyn ConfigNamespaceSource> = Arc::new(store.clone());
        let (module, mut handle) = TopologyModule::new(
            source,
            Box::new(ArtifactClusterFactory),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            control_config::HealthCheckConfig::default(),
        )
        .unwrap_or_else(|error| unreachable!("pinned health config is valid: {error}"));
        let context = runtime.handle().module_context();
        runtime
            .mark_ready()
            .unwrap_or_else(|error| unreachable!("mark ready: {error}"));
        let task = tokio::spawn(Box::new(module).run(context));
        handle
            .wait_ready()
            .await
            .unwrap_or_else(|error| unreachable!("module ready: {error}"));
        let routing = handle.routing_handle();
        Composition {
            handle,
            routing,
            store,
            dir,
            task,
            runtime,
        }
    }

    /// Drives the refresh loop to the next published routing generation satisfying
    /// `done`, deterministically, without `sleep`/`yield` and without a spin budget.
    ///
    /// The paused clock is used for exactly one thing: `advance` wakes the parked
    /// refresh ticker so the target poll starts. The poll's real loopback I/O then
    /// runs under REAL time (`resume`) until the drain exits — with the clock
    /// resumed the runtime never auto-advances, so the production per-cluster
    /// timeout inside `merge_tidb_topology` cannot beat the fixture's response (the
    /// race CI hit). The clock is paused again only on exit.
    ///
    /// Observation is structured on real Range events. The handler's `served` fires
    /// at ENTRY, before the response or the client's publication, so the target may
    /// not be visible after Range #1. Range #2 is the previous round's completion
    /// fence: `run_refresh` is serial, so poll #2 can only be entered once poll #1
    /// has fully completed and published — the target must be visible then, and if
    /// it is not, that poll genuinely failed and the drain fails outright rather
    /// than looping. The successor poll entered at Range #2 is itself still in
    /// flight when the drain exits; every row tears its composition down
    /// immediately afterward, which cancels it.
    async fn drain_until<F>(
        routing: &RoutingSnapshotHandle,
        fixture: &KvFixture,
        mut done: F,
    ) -> Arc<RoutingSnapshot>
    where
        F: FnMut(&RoutingSnapshot) -> bool,
    {
        if let Some(snapshot) = routing.current()
            && done(&snapshot)
        {
            return snapshot;
        }
        let before = fixture.tidb_range_count();
        tokio::time::advance(REFRESH_INTERVAL).await;
        tokio::time::resume();
        let snapshot = drain_in_real_time(routing, fixture, before, &mut done).await;
        tokio::time::pause();
        snapshot
    }

    /// The real-time half of [`drain_until`]: Range #1 (the target poll entered),
    /// then, if the target is not yet visible, Range #2 (the completion fence: the
    /// target poll has completed + published; its successor is now in flight).
    async fn drain_in_real_time<F>(
        routing: &RoutingSnapshotHandle,
        fixture: &KvFixture,
        before: usize,
        done: &mut F,
    ) -> Arc<RoutingSnapshot>
    where
        F: FnMut(&RoutingSnapshot) -> bool,
    {
        wait_range_past(fixture, before).await;
        if let Some(snapshot) = routing.current()
            && done(&snapshot)
        {
            return snapshot;
        }
        wait_range_past(fixture, before + 1).await;
        if let Some(snapshot) = routing.current()
            && done(&snapshot)
        {
            return snapshot;
        }
        unreachable!(
            "the routing generation is not at the target after a COMPLETE refresh poll: \
             that poll failed, so the target can never arrive"
        );
    }

    /// Resolves once the fixture has served more than `count` `TiDB` Ranges. The
    /// waiter is registered (`enable`d) BEFORE the counter is read, so a Range landing
    /// between the read and the await cannot be lost.
    async fn wait_range_past(fixture: &KvFixture, count: usize) {
        loop {
            let notified = fixture.served.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if fixture.tidb_range_count() > count {
                return;
            }
            notified.await;
        }
    }

    /// The refresh loop's very FIRST poll runs the same real loopback I/O as every
    /// later one, so it gets real time for the same reason as [`drain_until`].
    async fn wait_first_real(routing: &RoutingSnapshotHandle) -> Arc<RoutingSnapshot> {
        tokio::time::resume();
        let first = routing
            .wait_first()
            .await
            .unwrap_or_else(|_| unreachable!("the refresh loop publishes a first snapshot"));
        tokio::time::pause();
        first
    }

    /// Waits until the module's observable status reaches `applied` — an
    /// event-driven wait on the real status watch.
    async fn wait_applied(status: &mut watch::Receiver<TopologyStatus>, applied: u64) {
        while status.borrow_and_update().applied_generation < applied {
            if status.changed().await.is_err() {
                unreachable!("the status source must not close before the generation applies");
            }
        }
    }

    /// Cancels and joins the wall-clock watchdog thread on EVERY exit — the
    /// success path, the deadline `panic!`, or a `body` unwind — so a failing test
    /// never leaves a thread still counting toward 120s. Dropping the cancel sender
    /// disconnects the thread's `recv_timeout`, which it treats as a cancel and
    /// returns at once, so the `join` is immediate.
    struct WatchdogGuard {
        cancel: Option<std::sync::mpsc::Sender<()>>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            drop(self.cancel.take());
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// Runs `body` under a REAL wall-clock deadlock watchdog, immune to the test's
    /// paused virtual clock.
    ///
    /// A `tokio::time::timeout` cannot be used here: it runs on the paused clock,
    /// so the instant `body` parks on real loopback I/O the runtime auto-advances
    /// virtual time to the deadline and the "120s" timeout trips at once — a false
    /// deadlock (see the discriminator below). Instead a std thread counts REAL
    /// time via `recv_timeout`; only a genuine wall-clock hang fires the oneshot.
    /// The `select!` resolves to an outcome first; the guard then cancels + joins
    /// the thread on every path before we act on that outcome.
    async fn with_real_wall_clock_watchdog<F>(body: F)
    where
        F: Future<Output = ()>,
    {
        enum Outcome {
            Body,
            Deadline,
        }
        let (deadline_tx, deadline_rx) = oneshot::channel::<()>();
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            match cancel_rx.recv_timeout(Duration::from_secs(120)) {
                // A real wall-clock hang: fire the deadline.
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let _ = deadline_tx.send(());
                }
                // Cancelled (sender dropped/disconnected) — return without firing.
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
            }
        });
        let guard = WatchdogGuard {
            cancel: Some(cancel_tx),
            handle: Some(handle),
        };
        let outcome = tokio::select! {
            () = body => Outcome::Body,
            _ = deadline_rx => Outcome::Deadline,
        };
        // Cancel + join the watchdog thread BEFORE acting on the outcome, so the
        // deadline `panic!` never skips the join. (A `body` unwind reaches the same
        // cancel + join through `guard`'s `Drop`.)
        drop(guard);
        if matches!(outcome, Outcome::Deadline) {
            unreachable!(
                "real wall-clock watchdog: the composition test exceeded 120s of REAL time"
            );
        }
    }

    /// The determinism fix's own oracle: a `tokio::time::timeout` under a paused
    /// clock FALSELY reports a deadlock, while [`with_real_wall_clock_watchdog`]
    /// does not — even though the paused virtual clock keeps auto-advancing.
    #[tokio::test(start_paused = true)]
    async fn a_paused_clock_timeout_falsely_trips_while_the_real_watchdog_does_not() {
        // Old pattern: a virtual-clock `timeout` over a never-ready future
        // auto-advances the paused clock to the deadline and trips immediately.
        let tripped =
            tokio::time::timeout(Duration::from_secs(120), std::future::pending::<()>()).await;
        assert!(
            tripped.is_err(),
            "a paused-clock `timeout` falsely reports a deadlock on a pending future"
        );
        // New pattern: a body that only completes after a real std-thread schedule
        // (a cross-thread oneshot handshake) is NOT tripped by the real wall-clock
        // watchdog, though the paused virtual clock still auto-advances underneath.
        with_real_wall_clock_watchdog(async {
            let (tx, rx) = oneshot::channel::<()>();
            std::thread::spawn(move || {
                let _ = tx.send(());
            });
            let _ = rx.await;
        })
        .await;
    }

    /// The mechanism oracle for the determinism fix, deterministic on every
    /// platform (no wall sleep, no thread scheduling). Each half stands up its OWN
    /// fixture + composition and tears it down at the end, so the two conclusions
    /// share no connection, stream, or successor-poll state. A `TiDB` Range handler
    /// parks on a test-controlled gate after ENTRY (after it is counted and `served`
    /// fires), holding one poll in flight with its response withheld.
    ///
    /// Real time (the fix): with the clock resumed there is no auto-advance, so
    /// opening the gate after entry lets the in-flight poll complete and publish.
    /// Paused clock (the bug): holding the gate closed leaves the runtime nothing
    /// runnable, so it auto-advances straight to the production per-cluster timeout
    /// inside the poll — Ranges are served, yet nothing is published.
    #[tokio::test(start_paused = true)]
    async fn a_paused_clock_lets_the_inner_timeout_beat_a_served_range_but_real_time_does_not() {
        let body = async {
            // Real time (the fix), on a fresh fixture + composition.
            {
                let Some((fixture, addr)) = spawn_fixture(seed(&[(ADDR_A, "10.0.0.1")])).await
                else {
                    unreachable!("the fixture binds an ephemeral loopback port");
                };
                let comp = build_composition(addr, "").await;
                let s1 = wait_first_real(&comp.routing).await;
                assert_eq!(s1.generation, 1, "the first snapshot is generation 1");
                // A content change makes the next successful poll publish generation
                // 2. Gate that poll after entry, resume, then open the gate: it
                // completes and publishes; Range #2 (its completion fence) proves it.
                fixture.swap(seed(&[(ADDR_A, "10.0.0.1"), (ADDR_B, "10.0.0.2")]));
                fixture.close_gate();
                let before = fixture.tidb_range_count();
                tokio::time::advance(REFRESH_INTERVAL).await;
                wait_range_past(&fixture, before).await;
                tokio::time::resume();
                fixture.open_gate();
                wait_range_past(&fixture, before + 1).await;
                let published = comp
                    .routing
                    .current()
                    .unwrap_or_else(|| unreachable!("a routing source is published"));
                assert_eq!(
                    published.generation, 2,
                    "under real time the gate-released poll completes and publishes"
                );
                tokio::time::pause();
                comp.task.abort();
                drop(comp.runtime);
            }

            // Paused clock (the bug), on another fresh fixture + composition.
            {
                let Some((fixture, addr)) = spawn_fixture(seed(&[(ADDR_A, "10.0.0.1")])).await
                else {
                    unreachable!("the fixture binds an ephemeral loopback port");
                };
                let comp = build_composition(addr, "").await;
                let s1 = wait_first_real(&comp.routing).await;
                assert_eq!(s1.generation, 1, "the first snapshot is generation 1");
                // The same content change; hold the gate closed across the poll. It is
                // entered (Range served), then the only pending work is timers, so the
                // paused runtime auto-advances: the poll's inner timeout fires (the
                // poll fails), the ticker fires, the next poll is entered — and
                // NOTHING is published.
                fixture.swap(seed(&[(ADDR_A, "10.0.0.1"), (ADDR_B, "10.0.0.2")]));
                fixture.close_gate();
                let before = fixture.tidb_range_count();
                tokio::time::advance(REFRESH_INTERVAL).await;
                wait_range_past(&fixture, before).await;
                wait_range_past(&fixture, before + 1).await;
                let stuck = comp
                    .routing
                    .current()
                    .unwrap_or_else(|| unreachable!("a routing source is published"));
                assert_eq!(
                    stuck.generation, 1,
                    "Ranges were served, but the paused clock let the inner timeout beat \
                     the response: nothing was published"
                );
                assert!(
                    fixture.tidb_range_count() >= before + 2,
                    "at least two Ranges were served while nothing published"
                );
                fixture.open_gate();
                comp.task.abort();
                drop(comp.runtime);
            }
        };
        with_real_wall_clock_watchdog(body).await;
    }

    // ----- Row 1: same client_epoch, content change -> generation +1 --------

    #[tokio::test(start_paused = true)]
    async fn a_content_change_at_the_same_epoch_advances_the_routing_generation() {
        let body = async {
            let Some((fixture, addr)) = spawn_fixture(seed(&[(ADDR_A, "10.0.0.1")])).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };
            let comp = build_composition(addr, "").await;

            // The refresh loop's OWN first publication.
            let s1 = wait_first_real(&comp.routing).await;
            assert_eq!(s1.generation, 1, "the first snapshot is generation 1");
            assert_eq!(
                addrs(&s1),
                vec![ADDR_A.to_owned()],
                "it discovers backend A"
            );
            let e0 = s1.client_epoch;

            // Swap the served backends to [A, B] with the CONFIG COMPLETELY
            // UNCHANGED: the client epoch cannot move, only the content.
            fixture.swap(seed(&[(ADDR_A, "10.0.0.1"), (ADDR_B, "10.0.0.2")]));
            let s2 = drain_until(&comp.routing, &fixture, |s| s.generation >= 2).await;

            assert_eq!(
                s2.client_epoch, e0,
                "a content-only change keeps the SAME discovery client epoch"
            );
            assert_eq!(
                s2.generation, 2,
                "the routing generation advances EXACTLY by one"
            );
            assert_eq!(
                addrs(&s2),
                vec![ADDR_A.to_owned(), ADDR_B.to_owned()],
                "the content changed to exactly [A, B]"
            );
            assert!(
                !Arc::ptr_eq(&s1, &s2),
                "a real change swaps in a new snapshot Arc"
            );
            assert!(
                !comp.routing.still_current(&s1),
                "the superseded snapshot is no longer current via the real handle"
            );

            comp.task.abort();
            drop(comp.runtime);
        };
        with_real_wall_clock_watchdog(body).await;
    }

    // ----- Row 2: equal-content epoch rotation -> generation +1 -------------

    #[tokio::test(start_paused = true)]
    async fn an_epoch_rotation_at_equal_content_advances_the_routing_generation() {
        let body = async {
            let Some((fixture, addr)) = spawn_fixture(seed(&[(ADDR_A, "10.0.0.1")])).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };
            let comp = build_composition(addr, "").await;

            let s1 = wait_first_real(&comp.routing).await;
            assert_eq!(addrs(&s1), vec![ADDR_A.to_owned()]);
            let e0 = s1.client_epoch;
            let g1 = s1.generation;

            // Rotate the cluster MATERIAL through a real next TOML revision: add a
            // literal nameserver. The PD endpoint stays a literal IP, so the
            // resolver bypasses DNS and the fixture stays reachable — only the
            // discovery client material (and thus the client epoch) changes.
            let mut status = comp.handle.status();
            comp.store
                .apply_toml(
                    &topology_toml(&format!("127.0.0.1:{}", addr.port()), "\"203.0.113.9:53\""),
                    None,
                    2,
                    &comp.dir,
                )
                .unwrap_or_else(|error| unreachable!("apply revision 2: {error}"));
            // FIRST confirm the config applied (so the discovery epoch is committed)
            // through the real status watch.
            wait_applied(&mut status, 2).await;

            // THEN drain the next refresh tick and observe the new publication.
            let s2 = drain_until(&comp.routing, &fixture, |s| s.generation > g1).await;

            assert_eq!(
                s2.backends, s1.backends,
                "the backends are byte-identical across an equal-content epoch rotation"
            );
            assert_eq!(
                s2.client_epoch,
                e0 + 1,
                "the discovery client epoch rotated E0 -> E1"
            );
            assert_eq!(
                s2.generation,
                g1 + 1,
                "the routing generation advances EXACTLY by one on the epoch rotation"
            );
            assert!(
                !Arc::ptr_eq(&s1, &s2),
                "the provenance swap installs a new snapshot Arc"
            );
            assert!(
                !comp.routing.still_current(&s1),
                "the superseded provenance is no longer current"
            );

            comp.task.abort();
            drop(comp.runtime);
        };
        with_real_wall_clock_watchdog(body).await;
    }

    // ----- Row 3: old Arc fail-closed at BOTH the swap seam and teardown ----

    #[tokio::test(start_paused = true)]
    async fn a_superseded_and_the_final_snapshot_both_fail_closed() {
        let body = async {
            let Some((fixture, addr)) = spawn_fixture(seed(&[(ADDR_A, "10.0.0.1")])).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };
            let comp = build_composition(addr, "").await;

            let s1 = wait_first_real(&comp.routing).await;

            // (a) A replacement (content change) supersedes s1 at the swap seam: the
            // old Arc must be reported not-current via the SAME public handle.
            fixture.swap(seed(&[(ADDR_A, "10.0.0.1"), (ADDR_B, "10.0.0.2")]));
            let s2 = drain_until(&comp.routing, &fixture, |s| s.generation >= 2).await;
            assert!(
                !comp.routing.still_current(&s1),
                "the superseded snapshot is fail-closed at the swap-time revoke"
            );
            assert!(
                comp.routing.still_current(&s2),
                "the live snapshot is still current before teardown"
            );

            // (b) A legal lifecycle teardown (Ready -> Quiescing -> Draining ->
            // Stopping) must withdraw the routing source: the LATEST Arc is also
            // fail-closed AND the handle publishes nothing.
            comp.runtime
                .begin_shutdown(ShutdownReason::Requested)
                .unwrap_or_else(|error| unreachable!("begin shutdown: {error}"));
            comp.runtime
                .advance_shutdown(LifecyclePhase::Draining)
                .unwrap_or_else(|error| unreachable!("advance draining: {error}"));
            comp.runtime
                .advance_shutdown(LifecyclePhase::Stopping)
                .unwrap_or_else(|error| unreachable!("advance stopping: {error}"));
            let result = comp
                .task
                .await
                .unwrap_or_else(|error| unreachable!("module task join: {error}"));
            assert!(
                matches!(result, Ok(())),
                "the module retires cleanly at Stopping"
            );

            assert!(
                !comp.routing.still_current(&s2),
                "the final snapshot is fail-closed after the terminal withdraw"
            );
            assert!(
                comp.routing.current().is_none(),
                "the routing handle publishes nothing after teardown"
            );

            comp.runtime
                .finish()
                .unwrap_or_else(|error| unreachable!("finish: {error}"));
        };
        with_real_wall_clock_watchdog(body).await;
    }

    // ===================================================================
    // CP-TOPO #213-3b: real-composition proof of the backend-health seam.
    //
    // These rows drive the REAL TopologyModule + REAL #213-2 health loop
    // (composed by #213-3a) against a REAL loopback HTTP/1.1 `/status`
    // server, observing verdicts ONLY through the public source-paired
    // protocol `routing_handle().current()` -> `health_overlay_handle()
    // .current_for(&R)` -> `still_current_for` -> `HealthSnapshot::get`.
    //
    // NOTE on the `/status` server transport: the frozen design names a
    // "hyper HTTP/1.1" loopback server, but tiproxy-rs's `hyper` dev-dep
    // enables only `["http2","server"]` (http2 is required by the etcd gRPC
    // `KvFixture` above) — NOT `http1`. Adding the `http1` feature would edit
    // `Cargo.toml`, a production/build surface this task forbids. So this is
    // the behaviourally-equivalent raw-TCP HTTP/1.1 `/status` server the
    // design itself points to as "the MODEL" (control-topology's cfg(test)
    // `serve_counting` is likewise raw TCP, exercised against the SAME
    // `get_once` probe). No production is touched and Cargo.lock is unchanged.
    // ===================================================================

    use control_topology::{HealthOverlayHandle, HealthSnapshot};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The default health round cadence (`HealthCheckConfig::default().interval`),
    /// which the paused-clock structured wait advances by to fire the next round.
    const HEALTH_INTERVAL: Duration = Duration::from_secs(3);
    /// The merged backend id for `ADDR_A` under `CLUSTER_NAME` (`{cluster}/{addr}`).
    const BACKEND_ID: &str = "cluster-a/10.0.0.1:4000";

    // ----- The controllable loopback HTTP/1.1 `/status` server --------------

    /// The scripted per-request behavior of the loopback `/status` server,
    /// snapshotted synchronously at the START of each request.
    #[derive(Clone)]
    enum StatusBehavior {
        /// Answer `200 OK` with a valid `{"version": ...}` body.
        Ok200(String),
        /// Answer `500` whose body is a VALID version JSON, so a mutant deleting
        /// the production non-200 rejection would wrongly decode it as healthy.
        Status500,
        /// Never respond: hold the connection open so the probe's own attempt
        /// deadline fires, across the whole retry budget.
        Hang,
    }

    /// A loopback HTTP/1.1 `/status` server. It records BOTH every accepted
    /// connection AND — separately — every request parsed as an exact `GET
    /// /status` (incremented + signalled only after the method/path are
    /// confirmed), so a structured wait can key on a real post-switch probe and a
    /// disabled row can assert zero I/O.
    #[derive(Clone)]
    struct StatusServer {
        behavior: Arc<Mutex<StatusBehavior>>,
        accepted: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
        notify: Arc<Notify>,
        port: u16,
    }

    impl StatusServer {
        /// Swaps the controllable behavior; snapshotted at the start of each later
        /// request (never held across an await).
        fn set(&self, behavior: StatusBehavior) {
            *self.behavior.lock().unwrap_or_else(PoisonError::into_inner) = behavior;
        }

        /// The count of exact `GET /status` requests parsed so far.
        fn request_count(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }

        /// The count of accepted TCP connections so far.
        fn accepted_count(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    /// Binds a loopback `/status` server and serves each accepted connection.
    async fn spawn_status_server(behavior: StatusBehavior) -> StatusServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("status bind: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("status addr: {error}"))
            .port();
        let server = StatusServer {
            behavior: Arc::new(Mutex::new(behavior)),
            accepted: Arc::new(AtomicUsize::new(0)),
            requests: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
            port,
        };
        let serving = server.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                serving.accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_status_connection(stream, serving.clone()));
            }
        });
        server
    }

    /// Serves one `/status` connection: reads the request head, snapshots the
    /// behavior synchronously, counts + signals ONLY an exact `GET /status`, then
    /// answers per the snapshotted behavior (or hangs).
    async fn serve_status_connection(mut stream: TcpStream, server: StatusServer) {
        let Some(head) = read_request_head(&mut stream).await else {
            return;
        };
        // Snapshot the controllable behavior at the START of the request; the lock
        // is released before any await.
        let behavior = server
            .behavior
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        // An unknown method/path is a non-200 that does NOT count as a `/status`
        // request.
        if !is_get_status(&head) {
            let _ = stream.write_all(HTTP_404).await;
            let _ = stream.flush().await;
            return;
        }
        // Exactly `GET /status`: count and signal AFTER confirming method + path.
        server.requests.fetch_add(1, Ordering::SeqCst);
        server.notify.notify_one();
        match behavior {
            StatusBehavior::Ok200(version) => {
                let response = http_response(200, "OK", &format!(r#"{{"version":"{version}"}}"#));
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
            StatusBehavior::Status500 => {
                // A 500 with a VALID version body: a mutant that drops the non-200
                // rejection would decode this as healthy (making R1 phase-500 red).
                let response = http_response(
                    500,
                    "Internal Server Error",
                    r#"{"version":"v-should-not-matter"}"#,
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
            StatusBehavior::Hang => {
                // Never respond; hold the connection open so the probe's 2s attempt
                // deadline fires (across the whole retry budget). Keep the stream
                // alive by never dropping it.
                let _keep = stream;
                std::future::pending::<()>().await;
            }
        }
    }

    /// A `404` head that is never counted as a `/status` request.
    const HTTP_404: &[u8] =
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    /// Builds an HTTP/1.1 response with `Connection: close` and a `Content-Length`.
    fn http_response(code: u16, reason: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Reads a request head up to (and including) the terminating `\r\n\r\n`,
    /// returning the raw head or `None` on EOF/error.
    async fn read_request_head(stream: &mut TcpStream) -> Option<String> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if buffer.len() > 8192 {
                break;
            }
        }
        Some(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Whether the request head's start line is exactly `GET /status ...`.
    fn is_get_status(head: &str) -> bool {
        let Some(line) = head.lines().next() else {
            return false;
        };
        let mut parts = line.split_whitespace();
        parts.next() == Some("GET") && parts.next() == Some("/status")
    }

    // ----- The port-templated backend seed ----------------------------------

    /// The `info` + live `ttl` pair for one backend at `addr` whose `/status`
    /// probe target is the loopback server: `ip = 127.0.0.1`, `status_port =
    /// port`. The info `version` is irrelevant — the probe reads the version from
    /// the HTTP `/status` body, not this etcd record.
    fn backend_kvs_at(addr: &str, port: u16) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            kv(
                &format!("/topology/tidb/{addr}/info"),
                &format!(r#"{{"ip":"127.0.0.1","status_port":{port},"version":"v8"}}"#),
            ),
            kv(&format!("/topology/tidb/{addr}/ttl"), "173000000000"),
        ]
    }

    /// The seeded key space for one backend at `addr` templating the loopback
    /// `/status` port.
    fn seed_at(addr: &str, port: u16) -> Vec<(Vec<u8>, Vec<u8>)> {
        backend_kvs_at(addr, port)
    }

    /// Builds the real pipeline against `addr` with an explicit (checked) health
    /// config, so a row can pass `enabled = false` through the SAME public
    /// `TopologyModule::new`. Mirrors [`build_composition`], which pins the enabled
    /// default.
    async fn build_composition_with_health(
        addr: SocketAddr,
        ns_servers: &str,
        health: control_config::HealthCheckConfig,
    ) -> Composition {
        let dir = material_dir();
        let toml = topology_toml(&format!("127.0.0.1:{}", addr.port()), ns_servers);
        let roots = open_tls_roots(std::slice::from_ref(&dir));
        let store = ConfigNamespaceStore::from_toml_with_validator(
            &toml,
            None,
            &dir,
            Arc::new(TopologyCandidateValidator::new(Arc::new(roots))),
        )
        .unwrap_or_else(|error| unreachable!("pipeline validation: {error}"));

        let registry = Box::leak(Box::new(OwnershipRegistry::new()));
        let config = ControlConfig::new(
            1,
            Duration::from_secs(30),
            0,
            TlsPolicy::default(),
            LogLevel::Info,
            MetricsPolicy::default(),
        )
        .unwrap_or_else(|error| unreachable!("control config: {error}"));
        let runtime = ControlRuntime::claim_process(
            registry,
            "cptopo-health-comp",
            config,
            Arc::new(NullSink),
        )
        .unwrap_or_else(|error| unreachable!("claim process: {error}"));

        let source: Arc<dyn ConfigNamespaceSource> = Arc::new(store.clone());
        let (module, mut handle) = TopologyModule::new(
            source,
            Box::new(ArtifactClusterFactory),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            health,
        )
        .unwrap_or_else(|error| unreachable!("checked health config is valid: {error}"));
        let context = runtime.handle().module_context();
        runtime
            .mark_ready()
            .unwrap_or_else(|error| unreachable!("mark ready: {error}"));
        let task = tokio::spawn(Box::new(module).run(context));
        handle
            .wait_ready()
            .await
            .unwrap_or_else(|error| unreachable!("module ready: {error}"));
        let routing = handle.routing_handle();
        Composition {
            handle,
            routing,
            store,
            dir,
            task,
            runtime,
        }
    }

    // ----- The anti-false-pass structured health wait -----------------------

    /// A structured wait for the health overlay to carry `expected_healthy` /
    /// `expected_version` for `backend_id` under the EXACT routing source `r`,
    /// deterministically, without `sleep`/`yield` and without a spin budget.
    ///
    /// The paused clock is used for exactly one thing: `advance(health_interval)`
    /// wakes the parked health loop into its next round. When a real `/status`
    /// RESPONSE must arrive (`real_time`: the 200 / 500 phases), the clock is then
    /// `resume`d for the rest of the wait — with the clock resumed the runtime never
    /// auto-advances, so the production probe's attempt timeout cannot beat the
    /// loopback response (the same race the routing drain had) — and paused again
    /// on exit. When the attempt timeout firing IS the expected event (not
    /// `real_time`: the Hang phase), the wait stays on the paused clock, whose
    /// auto-advance drives the initial attempt and each retry deterministically.
    ///
    /// Observation is structured on the server's exact `GET /status` events: the
    /// handler's notify fires when the request is parsed — before the response and
    /// the loop's publication — so the verdict is re-checked after each event and
    /// the wait returns only when ALL hold: (1) the request count advanced past
    /// `baseline + min_request_delta` (a real post-switch probe; `>= 4` for Hang
    /// covers the full retry budget); (2) `current_for(&r)` is `Some(h)`; (3)
    /// `still_current_for(&h, &r, routing)`; (4) `h` is not `prev_h` (a genuinely
    /// NEW overlay, never a stale prior verdict); (5) the verdict matches. The
    /// waiter is registered before each check, so an event landing between the
    /// check and the await cannot be lost. A genuine hang is bounded only by the
    /// real wall-clock watchdog.
    #[allow(clippy::too_many_arguments)]
    async fn wait_health(
        overlay: &HealthOverlayHandle,
        routing: &RoutingSnapshotHandle,
        r: &Arc<RoutingSnapshot>,
        backend_id: &str,
        expected_healthy: bool,
        expected_version: Option<&str>,
        baseline: usize,
        min_request_delta: usize,
        server: &StatusServer,
        prev_h: Option<&Arc<HealthSnapshot>>,
        real_time: bool,
        health_interval: Duration,
    ) -> Arc<HealthSnapshot> {
        tokio::time::advance(health_interval).await;
        if real_time {
            tokio::time::resume();
        }
        let h = loop {
            let notified = server.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if server.request_count() >= baseline + min_request_delta
                && let Some(h) = overlay.current_for(r)
                && prev_h.is_none_or(|prev| !Arc::ptr_eq(&h, prev))
                && overlay.still_current_for(&h, r, routing)
            {
                let verdict = h.get(backend_id);
                if verdict.healthy == expected_healthy
                    && verdict.server_version.as_deref() == expected_version
                {
                    break h;
                }
            }
            notified.await;
        };
        if real_time {
            tokio::time::pause();
        }
        h
    }

    /// A structured wait for a DISABLED runtime's published overlay.
    ///
    /// A disabled runtime does no probe I/O, so there is no `/status` request
    /// signal to key on; this advances one further cadence and then bounded-yields
    /// the (change-future-less) public overlay handle until a live all-healthy
    /// overlay is published for `r`. The cap is a pure deadlock guard.
    ///
    /// The cadence advance also fires the routing refresh ticker (the two intervals
    /// coincide), starting a real loopback poll. That poll runs under REAL time
    /// (`resume` across the wait, `pause` on exit) for the same reason as
    /// [`drain_until`]: a paused clock would let the runtime auto-advance past the
    /// production per-cluster timeout while the poll's I/O is in flight and leave a
    /// failed, half-finished refresh round behind for the next drain.
    async fn drain_disabled_health(
        overlay: &HealthOverlayHandle,
        routing: &RoutingSnapshotHandle,
        r: &Arc<RoutingSnapshot>,
        health_interval: Duration,
    ) -> Arc<HealthSnapshot> {
        tokio::time::advance(health_interval).await;
        tokio::time::resume();
        for _ in 0..20_000 {
            tokio::task::yield_now().await;
            if let Some(h) = overlay.current_for(r)
                && overlay.still_current_for(&h, r, routing)
            {
                tokio::time::pause();
                return h;
            }
        }
        unreachable!("the disabled health overlay was not published within the budget");
    }

    /// Asserts every backend of `r` reads healthy with no version through `h`.
    fn assert_all_healthy(h: &Arc<HealthSnapshot>, r: &Arc<RoutingSnapshot>) {
        for backend in &r.backends.backends {
            let verdict = h.get(backend.backend_id.as_ref());
            assert!(
                verdict.healthy,
                "a disabled runtime reads {} healthy",
                backend.backend_id
            );
            assert!(
                verdict.server_version.is_none(),
                "a disabled runtime carries no version for {}",
                backend.backend_id
            );
        }
    }

    // ----- Row R1: a backend flips healthy -> 500 -> Hang on one source ------

    #[tokio::test(start_paused = true)]
    async fn a_backend_health_flips_through_the_real_status_probe() {
        let body = async {
            let server =
                spawn_status_server(StatusBehavior::Ok200("v-health-200".to_owned())).await;
            let Some((_fixture, addr)) = spawn_fixture(seed_at(ADDR_A, server.port)).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };
            let comp = build_composition(addr, "").await;
            let overlay = comp.handle.health_overlay_handle();

            // The epoch-0 routing source R, observed only through the public handle.
            let r =
                comp.routing.wait_first().await.unwrap_or_else(|_| {
                    unreachable!("the refresh loop publishes a first snapshot")
                });
            let r_epoch = r.client_epoch;
            let r_gen = r.generation;

            // Phase 200: a real `GET /status` -> 200 decodes a healthy version.
            let h200 = wait_health(
                &overlay,
                &comp.routing,
                &r,
                BACKEND_ID,
                true,
                Some("v-health-200"),
                0,
                1,
                &server,
                None,
                true,
                HEALTH_INTERVAL,
            )
            .await;
            assert!(h200.get(BACKEND_ID).healthy, "the 200 verdict is healthy");
            assert_eq!(
                h200.get(BACKEND_ID).server_version.as_deref(),
                Some("v-health-200"),
                "the healthy version came from the HTTP /status body"
            );
            assert_unchanged_routing(&comp.routing, &r, r_epoch, r_gen);

            // Phase 500: a valid-body 500 is a terminal non-200 -> unhealthy.
            server.set(StatusBehavior::Status500);
            let baseline_500 = server.request_count();
            let h500 = wait_health(
                &overlay,
                &comp.routing,
                &r,
                BACKEND_ID,
                false,
                None,
                baseline_500,
                1,
                &server,
                Some(&h200),
                true,
                HEALTH_INTERVAL,
            )
            .await;
            assert!(
                !h500.get(BACKEND_ID).healthy,
                "the 500 verdict is unhealthy"
            );
            assert!(
                !overlay.still_current_for(&h200, &r, &comp.routing),
                "the healthy overlay is de-authorized once the unhealthy round publishes"
            );
            assert_unchanged_routing(&comp.routing, &r, r_epoch, r_gen);

            // Phase Hang: a hung backend times out every attempt across the FULL
            // retry budget (initial + 3 retries) -> unhealthy with no version.
            server.set(StatusBehavior::Hang);
            let baseline_hang = server.request_count();
            let h_timeout = wait_health(
                &overlay,
                &comp.routing,
                &r,
                BACKEND_ID,
                false,
                None,
                baseline_hang,
                4,
                &server,
                Some(&h500),
                false,
                HEALTH_INTERVAL,
            )
            .await;
            assert!(
                server.request_count() - baseline_hang >= 4,
                "the hung phase exercised the full 4-attempt retry budget"
            );
            let verdict = h_timeout.get(BACKEND_ID);
            assert!(!verdict.healthy, "the hung verdict is unhealthy");
            assert!(
                verdict.server_version.is_none(),
                "a hung probe yields no version"
            );
            assert!(
                !overlay.still_current_for(&h500, &r, &comp.routing),
                "the 500 overlay is de-authorized once the timeout round publishes"
            );
            // Throughout R1 a health flip never rotated the routing source.
            assert_unchanged_routing(&comp.routing, &r, r_epoch, r_gen);

            comp.task.abort();
            drop(comp.runtime);
        };
        with_real_wall_clock_watchdog(body).await;
    }

    /// Asserts the routing source is still the exact live `Arc` at its published
    /// epoch and generation — a health flip must not rotate routing.
    fn assert_unchanged_routing(
        routing: &RoutingSnapshotHandle,
        r: &Arc<RoutingSnapshot>,
        epoch: u64,
        generation: u64,
    ) {
        let live = routing
            .current()
            .unwrap_or_else(|| unreachable!("the routing source stays live across a health flip"));
        assert!(
            Arc::ptr_eq(&live, r),
            "the routing source Arc is unchanged across the health flip"
        );
        assert_eq!(live.client_epoch, epoch, "the routing epoch is unchanged");
        assert_eq!(
            live.generation, generation,
            "the routing generation is unchanged"
        );
    }

    // ----- Row R2: an epoch rotation realigns health provenance -------------

    #[tokio::test(start_paused = true)]
    async fn an_epoch_rotation_realigns_health_provenance_and_fails_the_old_source_closed() {
        let body = async {
            let server = spawn_status_server(StatusBehavior::Ok200("v-rot".to_owned())).await;
            let Some((fixture, addr)) = spawn_fixture(seed_at(ADDR_A, server.port)).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };
            let comp = build_composition(addr, "").await;
            let overlay = comp.handle.health_overlay_handle();

            let r0 =
                comp.routing.wait_first().await.unwrap_or_else(|_| {
                    unreachable!("the refresh loop publishes a first snapshot")
                });
            let e0 = r0.client_epoch;
            let h0 = wait_health(
                &overlay,
                &comp.routing,
                &r0,
                BACKEND_ID,
                true,
                Some("v-rot"),
                0,
                1,
                &server,
                None,
                true,
                HEALTH_INTERVAL,
            )
            .await;
            assert!(h0.get(BACKEND_ID).healthy, "the E0 source is healthy");

            // Rotate the exact cluster MATERIAL (add a literal nameserver), keeping
            // the backend KV content identical; the PD/backend endpoints stay
            // literal IPs so the fixture stays reachable — only the client epoch
            // rotates.
            let mut status = comp.handle.status();
            // The rotation runs under REAL time: `reconfigure` awaits inside the module
            // (child stop/spawn, lazy connects) can leave the runtime idle, and an idle
            // PAUSED clock would auto-advance the routing ticker, firing a post-commit
            // poll whose budget then trips — a reset stream that poisons the new epoch's
            // connection for the drain that follows.
            tokio::time::resume();
            comp.store
                .apply_toml(
                    &topology_toml(&format!("127.0.0.1:{}", addr.port()), "\"203.0.113.9:53\""),
                    None,
                    2,
                    &comp.dir,
                )
                .unwrap_or_else(|error| unreachable!("apply revision 2: {error}"));
            wait_applied(&mut status, 2).await;
            tokio::time::pause();

            // The material/feed fence de-authorizes H0 synchronously at apply, while
            // the routing source R0 is still the live `current()` (routing has not
            // rotated yet) — isolating the health-feed fence from routing rotation.
            assert!(
                overlay.current_for(&r0).is_none(),
                "H0 fails closed at the material/feed fence, before routing rotates"
            );
            let live = comp
                .routing
                .current()
                .unwrap_or_else(|| unreachable!("R0 stays live until the next refresh tick"));
            assert!(
                Arc::ptr_eq(&live, &r0),
                "the routing source R0 is still current at the feed fence"
            );

            // Drain the new routing generation R1: E0 -> E1, a fresh Arc, identical
            // backend content.
            let r1 = drain_until(&comp.routing, &fixture, |s| s.client_epoch == e0 + 1).await;
            assert_eq!(
                r1.client_epoch,
                e0 + 1,
                "the discovery client epoch rotated"
            );
            assert!(!Arc::ptr_eq(&r0, &r1), "the rotation installs a new Arc");
            assert_eq!(
                r1.backends, r0.backends,
                "the backend content is identical across the epoch rotation"
            );

            // H1 healthy under R1 IS the provenance proof: a network still stamped
            // E0 would be epoch-fenced unhealthy under the E1 source.
            let baseline = server.request_count();
            let h1 = wait_health(
                &overlay,
                &comp.routing,
                &r1,
                BACKEND_ID,
                true,
                Some("v-rot"),
                baseline,
                1,
                &server,
                None,
                true,
                HEALTH_INTERVAL,
            )
            .await;
            assert!(
                h1.get(BACKEND_ID).healthy,
                "the E1 source is healthy through an E1-stamped network"
            );
            assert!(
                overlay.current_for(&r0).is_none(),
                "the old provenance stays fail-closed after the rotation"
            );
            assert!(
                !overlay.still_current_for(&h0, &r0, &comp.routing),
                "the old overlay is not current for the old source"
            );

            comp.task.abort();
            drop(comp.runtime);
        };
        with_real_wall_clock_watchdog(body).await;
    }

    // ----- Row R3: a disabled composition does no health I/O ----------------

    #[tokio::test(start_paused = true)]
    async fn a_disabled_composition_does_no_health_io_and_reads_all_healthy() {
        let body = async {
            // Ok200 that must NEVER be hit: a disabled runtime opens no socket.
            let server = spawn_status_server(StatusBehavior::Ok200("never".to_owned())).await;
            let Some((fixture, addr)) = spawn_fixture(seed_at(ADDR_A, server.port)).await else {
                unreachable!("the fixture binds an ephemeral loopback port");
            };
            // The SAME public constructor, with a checked disabled health config.
            let health = control_config::HealthCheckConfig {
                enabled: false,
                ..control_config::HealthCheckConfig::default()
            };
            let comp = build_composition_with_health(addr, "", health).await;
            let overlay = comp.handle.health_overlay_handle();

            // Initial source: the disabled seam publishes an all-healthy, no-version
            // overlay with zero probe I/O.
            let r0 =
                comp.routing.wait_first().await.unwrap_or_else(|_| {
                    unreachable!("the refresh loop publishes a first snapshot")
                });
            assert_eq!(r0.backends.backends.len(), 1, "one backend is discovered");
            let h0 = drain_disabled_health(&overlay, &comp.routing, &r0, HEALTH_INTERVAL).await;
            assert_all_healthy(&h0, &r0);

            // A real material rotation, then the rotated source is ALSO all-healthy.
            let mut status = comp.handle.status();
            // The rotation runs under REAL time: `reconfigure` awaits inside the module
            // (child stop/spawn, lazy connects) can leave the runtime idle, and an idle
            // PAUSED clock would auto-advance the routing ticker, firing a post-commit
            // poll whose budget then trips — a reset stream that poisons the new epoch's
            // connection for the drain that follows.
            tokio::time::resume();
            comp.store
                .apply_toml(
                    &topology_toml(&format!("127.0.0.1:{}", addr.port()), "\"203.0.113.9:53\""),
                    None,
                    2,
                    &comp.dir,
                )
                .unwrap_or_else(|error| unreachable!("apply revision 2: {error}"));
            wait_applied(&mut status, 2).await;
            tokio::time::pause();
            let r1 = drain_until(&comp.routing, &fixture, |s| {
                s.client_epoch == r0.client_epoch + 1
            })
            .await;
            assert!(!Arc::ptr_eq(&r0, &r1), "the rotation installs a new Arc");
            assert!(
                !comp.routing.still_current(&r0),
                "the old routing source is de-authorized across the rotation"
            );
            assert!(
                overlay.current_for(&r0).is_none(),
                "the old overlay is de-authorized across the rotation"
            );
            let h1 = drain_disabled_health(&overlay, &comp.routing, &r1, HEALTH_INTERVAL).await;
            assert_all_healthy(&h1, &r1);

            // Zero `/status` I/O ever: a disabled runtime built no client, opened no
            // socket, and sent no probe. (Together with 3a's unbuildable-material
            // row this closes zero-construction; this row alone proves the real-seam
            // disabled all-healthy + zero-I/O, not that no client was constructed.)
            assert_eq!(
                server.accepted_count(),
                0,
                "a disabled runtime accepts no /status connection"
            );
            assert_eq!(
                server.request_count(),
                0,
                "a disabled runtime sends no /status request"
            );

            comp.task.abort();
            drop(comp.runtime);
        };
        with_real_wall_clock_watchdog(body).await;
    }
}
