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

use thiserror::Error;

/// Maximum byte length of an election or session key.
pub const MAX_ETCD_KEY_BYTES: usize = 2_048;
/// Maximum election namespace length after reserving `/<signed-lease-hex>`.
pub const MAX_ELECTION_NAME_BYTES: usize = MAX_ETCD_KEY_BYTES - 18;
/// Maximum byte length of the stable election member identity.
pub const MAX_MEMBER_ID_BYTES: usize = 256;
/// Maximum supported session TTL.
pub const MAX_SESSION_TTL_SECONDS: i64 = 300;

/// Validated configuration for one etcd-backed control owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectionConfig {
    election_name: Vec<u8>,
    member_id: Vec<u8>,
    session_key: Vec<u8>,
    session_ttl_seconds: i64,
}

impl ElectionConfig {
    /// Creates a bounded election/session policy.
    ///
    /// `session_key` is an additional ephemeral presence key.  It is written
    /// by a transaction fenced on both the elected key's creation revision and
    /// lease, so later modules can safely attach owner-only state to the same
    /// session.
    ///
    /// # Errors
    ///
    /// Rejects empty, over-bound, NUL-containing keys and TTLs outside
    /// `1..=300` seconds.
    pub fn new(
        election_name: impl Into<Vec<u8>>,
        member_id: impl Into<Vec<u8>>,
        session_key: impl Into<Vec<u8>>,
        session_ttl_seconds: i64,
    ) -> Result<Self, ElectionConfigError> {
        let election_name = validate(
            "election_name",
            election_name.into(),
            MAX_ELECTION_NAME_BYTES,
        )?;
        let member_id = validate("member_id", member_id.into(), MAX_MEMBER_ID_BYTES)?;
        let session_key = validate("session_key", session_key.into(), MAX_ETCD_KEY_BYTES)?;
        let mut election_prefix = election_name.clone();
        election_prefix.push(b'/');
        if session_key.starts_with(&election_prefix) {
            return Err(ElectionConfigError::SessionKeyOverlapsElection);
        }
        if !(1..=MAX_SESSION_TTL_SECONDS).contains(&session_ttl_seconds) {
            return Err(ElectionConfigError::InvalidSessionTtl(session_ttl_seconds));
        }
        Ok(Self {
            election_name,
            member_id,
            session_key,
            session_ttl_seconds,
        })
    }

    /// Returns the election namespace.
    #[must_use]
    pub fn election_name(&self) -> &[u8] {
        &self.election_name
    }

    /// Returns the stable member identity.
    #[must_use]
    pub fn member_id(&self) -> &[u8] {
        &self.member_id
    }

    /// Returns the lease-attached presence key.
    #[must_use]
    pub fn session_key(&self) -> &[u8] {
        &self.session_key
    }

    /// Returns the requested lease TTL in seconds.
    #[must_use]
    pub const fn session_ttl_seconds(&self) -> i64 {
        self.session_ttl_seconds
    }
}

/// Invalid election/session configuration.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ElectionConfigError {
    /// A bounded identifier was empty, too long, or contained NUL.
    #[error("invalid {kind}: value must be nonempty, bounded, and contain no NUL")]
    InvalidIdentifier {
        /// Stable identifier role.
        kind: &'static str,
    },
    /// The requested lease TTL was outside the supported range.
    #[error("invalid etcd session TTL {0}; expected 1..=300 seconds")]
    InvalidSessionTtl(i64),
    /// A presence key inside the election prefix would become a contender.
    #[error("session key must not overlap the election candidate prefix")]
    SessionKeyOverlapsElection,
}

fn validate(
    kind: &'static str,
    value: Vec<u8>,
    maximum: usize,
) -> Result<Vec<u8>, ElectionConfigError> {
    if value.is_empty() || value.len() > maximum || value.contains(&0) {
        return Err(ElectionConfigError::InvalidIdentifier { kind });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{ElectionConfig, ElectionConfigError};

    #[test]
    fn identifiers_and_ttl_are_bounded() {
        assert!(ElectionConfig::new("/election", "member-A", "/session/A", 30).is_ok());
        assert_eq!(
            ElectionConfig::new("", "member-A", "/session/A", 30),
            Err(ElectionConfigError::InvalidIdentifier {
                kind: "election_name"
            })
        );
        assert_eq!(
            ElectionConfig::new("/election", "member-A", "/session/A", 0),
            Err(ElectionConfigError::InvalidSessionTtl(0))
        );
        assert_eq!(
            ElectionConfig::new("/election", b"member\0A".to_vec(), "/session/A", 30),
            Err(ElectionConfigError::InvalidIdentifier { kind: "member_id" })
        );
        assert_eq!(
            ElectionConfig::new("/election", "member-A", "/election/presence", 30),
            Err(ElectionConfigError::SessionKeyOverlapsElection)
        );
    }
}
