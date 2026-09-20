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

//! `/api/admin/namespace/*` and `/api/admin/config/` (CP-ADMIN slice 2).
//!
//! The handlers keep the Go status codes and bounded bodies
//! (`pkg/server/api/namespace.go`, `config.go`) while the storage behind
//! them is the [`ConfigAdmin`] seam: the executable binds it to the
//! owner-fenced `ConfigModuleHandle`, so namespaces persist below `/config`
//! in etcd instead of Go's in-process B-tree, and a configuration `PUT` is
//! Go's `SetTOMLConfig` through the config owner.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use control_config::{ConfigMutationError, NamespaceConfig};
use serde_json::Value;

/// Boxed future returned by the storage seam.
pub type AdminFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a namespace commit failed, mapped to the Go handler's bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitError {
    /// A named namespace does not exist (`500 "failed to get namespace"`).
    Missing,
    /// The serving view did not pick up the namespaces in time
    /// (`500 "failed to reload namespaces"`).
    Reload,
}

/// Storage behind the namespace and configuration endpoints.
pub trait ConfigAdmin: Send + Sync {
    /// Name-sorted namespaces from the current accepted generation.
    fn list_namespaces(&self) -> Vec<NamespaceConfig>;
    /// One namespace by exact name.
    fn get_namespace(&self, name: &str) -> Option<NamespaceConfig>;
    /// Persists one namespace under its name.
    fn set_namespace(
        &self,
        value: NamespaceConfig,
    ) -> AdminFuture<'_, Result<(), ConfigMutationError>>;
    /// Deletes one namespace; deleting an absent name succeeds like Go's
    /// B-tree delete.
    fn delete_namespace(&self, name: String) -> AdminFuture<'_, Result<(), ConfigMutationError>>;
    /// Makes the named namespaces (all when empty) serving.
    fn commit_namespaces(&self, names: Vec<String>) -> AdminFuture<'_, Result<(), CommitError>>;
    /// Current effective configuration as TOML.
    fn config_toml(&self) -> Option<String>;
    /// Current effective configuration as JSON.
    fn config_json(&self) -> Option<String>;
    /// Go `SetTOMLConfig`: partial document merged onto the current
    /// configuration, validated as a whole.
    fn put_config_toml(&self, data: Vec<u8>) -> AdminFuture<'_, Result<(), ConfigMutationError>>;
}

/// In-memory [`ConfigAdmin`] with Go's per-process semantics, for tests and
/// the differential replay.
#[derive(Debug, Default)]
pub struct MemoryConfigAdmin {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    namespaces: std::collections::BTreeMap<String, NamespaceConfig>,
    config: control_config::EffectiveConfig,
    current_dir: std::path::PathBuf,
    committed: Vec<String>,
}

impl MemoryConfigAdmin {
    /// Starts from `config` validated against `current_dir`.
    #[must_use]
    pub fn new(config: control_config::EffectiveConfig, current_dir: std::path::PathBuf) -> Self {
        Self {
            state: Mutex::new(MemoryState {
                namespaces: std::collections::BTreeMap::new(),
                config,
                current_dir,
                committed: Vec::new(),
            }),
        }
    }

    /// CRC32 of the current configuration, as Go reports it in the health body.
    #[must_use]
    pub fn go_checksum(&self) -> u32 {
        self.state
            .lock()
            .map(|state| state.config.go_checksum())
            .unwrap_or_default()
    }

    /// Names passed to the last successful commit.
    #[must_use]
    pub fn committed(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|state| state.committed.clone())
            .unwrap_or_default()
    }
}

impl ConfigAdmin for MemoryConfigAdmin {
    fn list_namespaces(&self) -> Vec<NamespaceConfig> {
        self.state
            .lock()
            .map(|state| state.namespaces.values().cloned().collect())
            .unwrap_or_default()
    }

    fn get_namespace(&self, name: &str) -> Option<NamespaceConfig> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.namespaces.get(name).cloned())
    }

    fn set_namespace(
        &self,
        value: NamespaceConfig,
    ) -> AdminFuture<'_, Result<(), ConfigMutationError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ConfigMutationError::Stopped)?;
            state.namespaces.insert(value.namespace.clone(), value);
            Ok(())
        })
    }

    fn delete_namespace(&self, name: String) -> AdminFuture<'_, Result<(), ConfigMutationError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ConfigMutationError::Stopped)?;
            state.namespaces.remove(&name);
            Ok(())
        })
    }

    fn commit_namespaces(&self, names: Vec<String>) -> AdminFuture<'_, Result<(), CommitError>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| CommitError::Reload)?;
            if names
                .iter()
                .any(|name| !state.namespaces.contains_key(name))
            {
                return Err(CommitError::Missing);
            }
            state.committed = names;
            Ok(())
        })
    }

    fn config_toml(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.config.to_toml_string().ok())
    }

    fn config_json(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.config.to_json_string().ok())
    }

    fn put_config_toml(&self, data: Vec<u8>) -> AdminFuture<'_, Result<(), ConfigMutationError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ConfigMutationError::Stopped)?;
            let current_dir = state.current_dir.clone();
            let candidate = state
                .config
                .patched_with_toml(&data, &current_dir)
                .map_err(|_| ConfigMutationError::Invalid)?;
            candidate
                .check_reload_from(&state.config)
                .map_err(|_| ConfigMutationError::RestartRequired)?;
            state.config = candidate;
            Ok(())
        })
    }
}

/// Decodes a request body the way gin's `ShouldBindJSON` (`json.Decoder`)
/// does before serde sees it: one JSON value only (trailing bytes ignored),
/// `null` is "leave the target unchanged", object keys match Go's
/// case-insensitive rule, a `null` member leaves that field unchanged,
/// unknown members are ignored by the caller's `serde(default)` types, and
/// duplicate members are decoded in order — occurrences of different JSON
/// kinds can never all decode into one field, which Go reports as an error,
/// while same-kind duplicates let the last value win.
///
/// Returns `Ok(None)` for `null`.
///
/// # Errors
///
/// Returns the decode error for malformed JSON or duplicate members of
/// conflicting kinds.
pub fn go_json_body(bytes: &[u8]) -> Result<Option<Value>, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let tree = serde::Deserialize::deserialize(&mut deserializer)?;
    normalize(tree).map(|value| match value {
        Value::Null => None,
        other => Some(other),
    })
}

/// JSON tree that keeps duplicate object members in order.
enum Tree {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Tree>),
    Object(Vec<(String, Tree)>),
}

impl<'de> serde::Deserialize<'de> for Tree {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TreeVisitor;
        impl<'de> serde::de::Visitor<'de> for TreeVisitor {
            type Value = Tree;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any JSON value")
            }
            fn visit_unit<E>(self) -> Result<Tree, E> {
                Ok(Tree::Null)
            }
            fn visit_bool<E>(self, value: bool) -> Result<Tree, E> {
                Ok(Tree::Bool(value))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Tree, E> {
                Ok(Tree::Number(value.into()))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Tree, E> {
                Ok(Tree::Number(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Tree, E> {
                serde_json::Number::from_f64(value)
                    .map(Tree::Number)
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Tree, E> {
                Ok(Tree::String(value.to_owned()))
            }
            fn visit_string<E>(self, value: String) -> Result<Tree, E> {
                Ok(Tree::String(value))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Tree, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Tree::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Tree, A::Error> {
                let mut members = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Tree>()? {
                    members.push((key, value));
                }
                Ok(Tree::Object(members))
            }
        }
        deserializer.deserialize_any(TreeVisitor)
    }
}

fn kind(tree: &Tree) -> &'static str {
    match tree {
        Tree::Null => "null",
        Tree::Bool(_) => "bool",
        Tree::Number(_) => "number",
        Tree::String(_) => "string",
        Tree::Array(_) => "array",
        Tree::Object(_) => "object",
    }
}

fn normalize(tree: Tree) -> Result<Value, serde_json::Error> {
    Ok(match tree {
        Tree::Null => Value::Null,
        Tree::Bool(value) => Value::Bool(value),
        Tree::Number(value) => Value::Number(value),
        Tree::String(value) => Value::String(value),
        Tree::Array(items) => Value::Array(
            items
                .into_iter()
                .map(normalize)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Tree::Object(members) => {
            let mut object = serde_json::Map::new();
            let mut kinds: std::collections::BTreeMap<String, &'static str> =
                std::collections::BTreeMap::new();
            for (key, value) in members {
                // Go matches struct fields case-insensitively; every tag in
                // the namespace/config shapes is lowercase.
                let folded = key.to_ascii_lowercase();
                if matches!(value, Tree::Null) {
                    // A JSON null leaves the field unchanged.
                    continue;
                }
                let value_kind = kind(&value);
                if let Some(previous) = kinds.insert(folded.clone(), value_kind)
                    && previous != value_kind
                {
                    return Err(serde::de::Error::custom(format!(
                        "member {folded} decoded as {previous} and {value_kind}"
                    )));
                }
                object.insert(folded, normalize(value)?);
            }
            Value::Object(object)
        }
    })
}

/// Shared handle type the router stores.
pub type SharedConfigAdmin = Arc<dyn ConfigAdmin>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn body_decoder_follows_go_rules() {
        assert_eq!(go_json_body(b"null").unwrap(), None);
        assert_eq!(
            go_json_body(b"{\"Namespace\":\"a\"} trailing").unwrap(),
            Some(serde_json::json!({"namespace": "a"}))
        );
        assert_eq!(
            go_json_body(b"{\"user\":null,\"USER\":\"x\",\"user\":\"y\"}").unwrap(),
            Some(serde_json::json!({"user": "y"}))
        );
        assert!(go_json_body(b"{\"user\":1,\"user\":\"y\"}").is_err());
        assert!(go_json_body(b"").is_err());
        assert!(go_json_body(b"{").is_err());
        assert_eq!(
            go_json_body(b"{\"backend\":{\"Instances\":[\"a\"],\"security\":null}}").unwrap(),
            Some(serde_json::json!({"backend": {"instances": ["a"]}}))
        );
    }
}
