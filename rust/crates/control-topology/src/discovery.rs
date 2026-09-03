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

//! The discovery poll (the I/O half of topology discovery).
//!
//! [`poll_tidb_topology`] reads the live `TiDB` topology from a backend
//! cluster's etcd and returns the liveness-filtered snapshot, mirroring Go
//! `infosync.InfoSyncer::GetTiDBTopology` (`pkg/manager/infosync/info.go`): it
//! prefix-reads `/topology/tidb/` and `/keyspaces/tidb/`, concatenates the
//! key/value pairs, and feeds the shared pure parser [`parse_tidb_topology`].
//!
//! The read goes through [`control_external::EtcdConnection`], so it is fenced
//! by the process [`control_plane::OwnerToken`]. The parsing itself is unit
//! tested in [`crate::model`]; the live range read is covered by the same
//! embedded-etcd integration test that exercises registration.

use control_external::{EtcdConnection, EtcdOperationError};
use etcd_client::GetOptions;

use crate::model::{TopologySnapshot, parse_tidb_topology};

/// Classic (non-keyspace) `TiDB` topology prefix. Matches Go
/// `tidbTopologyInformationPath`.
const TIDB_TOPOLOGY_PREFIX: &str = "/topology/tidb/";
/// Keyspace-scoped `TiDB` topology prefix. Matches Go
/// `tidbKeyspaceTopologyInformationPath`.
const TIDB_KEYSPACE_TOPOLOGY_PREFIX: &str = "/keyspaces/tidb/";

/// Reads the live `TiDB` topology and returns a liveness-filtered snapshot.
///
/// Both prefixes are read with a single ranged get each; a backend appears only
/// when its `info` record still has a live `ttl` sibling, exactly as the shared
/// parser enforces.
///
/// # Errors
///
/// Returns [`EtcdOperationError::StaleOwner`] if the owner generation is
/// released around either read, or [`EtcdOperationError::Dependency`] for a
/// transport or server failure.
pub async fn poll_tidb_topology(
    connection: &mut EtcdConnection,
) -> Result<TopologySnapshot, EtcdOperationError> {
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for prefix in [TIDB_TOPOLOGY_PREFIX, TIDB_KEYSPACE_TOPOLOGY_PREFIX] {
        let key = prefix.to_owned();
        let response = connection
            .execute(move |client| Box::pin(client.get(key, Some(GetOptions::new().with_prefix()))))
            .await?;
        entries.reserve(response.kvs().len());
        for kv in response.kvs() {
            entries.push((kv.key().to_vec(), kv.value().to_vec()));
        }
    }
    Ok(parse_tidb_topology(&entries))
}
