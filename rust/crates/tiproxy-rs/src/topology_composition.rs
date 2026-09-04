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
    PreparedArtifact,
};
use control_external::{EtcdClientConfig, EtcdTlsConfig};
use control_topology::{TopologyClientFactory, TopologyClusterClient};

/// The concrete artifact a [`TopologyCandidateValidator`] prepares: one built
/// etcd client per backend cluster, each with its TLS material already loaded.
///
/// It is carried opaquely by the snapshot and recovered by
/// [`ArtifactClusterFactory`]. It has no `Debug`, so the endpoints and material
/// it holds never render.
pub struct PreparedClusterSet {
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
/// for the candidate generation.
#[derive(Clone, Copy, Debug, Default)]
pub struct TopologyCandidateValidator;

impl CandidateValidator for TopologyCandidateValidator {
    fn validate(
        &self,
        effective: &EffectiveConfig,
        _namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str> {
        let topology = effective.topology().map_err(|_| "topology_projection")?;
        // Read the shared cluster TLS material once for this generation.
        let tls = cluster_tls_material(&topology.cluster_tls)?;
        let mut clusters = Vec::with_capacity(topology.backend_clusters.len());
        for cluster in topology.backend_clusters.iter() {
            let endpoints = cluster.pd_addrs.iter().map(ToString::to_string);
            let client = EtcdClientConfig::new(endpoints, tls.clone())
                .map_err(|_| "cluster_client_build")?;
            clusters.push(TopologyClusterClient {
                cluster_name: Arc::clone(&cluster.name),
                client,
            });
        }
        clusters.sort_by(|left, right| left.cluster_name.cmp(&right.cluster_name));
        Ok(PreparedArtifact::new(Arc::new(PreparedClusterSet {
            clusters,
        })))
    }
}

/// Loads the optional client mTLS material referenced by a normalized
/// [`ClientTlsConfig`], reading each PEM exactly once.
///
/// Returns payload-free failure classes: no path or material ever appears in the
/// error.
fn cluster_tls_material(config: &ClientTlsConfig) -> Result<Option<EtcdTlsConfig>, &'static str> {
    if config.skip_ca_verification {
        return Err("cluster_tls_skip_ca_unsupported");
    }
    let configured = config.ca_path.is_some()
        || config.certificate_path.is_some()
        || config.private_key_path.is_some();
    if !configured {
        return Ok(None);
    }
    let ca_path = config.ca_path.as_deref().ok_or("cluster_tls_requires_ca")?;
    let ca = std::fs::read(ca_path).map_err(|_| "cluster_tls_read_ca")?;
    let certificate = config
        .certificate_path
        .as_deref()
        .map(std::fs::read)
        .transpose()
        .map_err(|_| "cluster_tls_read_certificate")?;
    let key = config
        .private_key_path
        .as_deref()
        .map(std::fs::read)
        .transpose()
        .map_err(|_| "cluster_tls_read_key")?;
    EtcdTlsConfig::new(ca, certificate, key, None)
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
        format!(
            r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = {max_connections}

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "cluster-a"
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
            Arc::new(TopologyCandidateValidator),
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
    fn the_interface_provider_extracts_addresses_safely() {
        // A focused seam check: enumeration must return a bounded address list
        // without panicking, whatever interfaces this host happens to have. The
        // candidate-selection rules are asserted deterministically against the
        // resolver's injectable fake in control-topology, not here.
        let candidates = interface_advertise_candidates();
        assert!(candidates.len() < 4096);
    }
}
