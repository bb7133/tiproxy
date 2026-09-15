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

//! Exact user-to-namespace resolution over the committed raw namespace view.

use std::collections::BTreeSet;
use std::sync::Arc;

use control_config::{
    CandidateValidator, ConfigNamespaceSnapshot, ConfigNamespaceSource, EffectiveConfig,
    NamespaceConfig, NamespaceIncarnation, PreparedArtifact,
};

use crate::RouteError;

const DEFAULT_NAMESPACE: &str = "default";

/// Rejects ambiguous nonempty frontend-user identities before a configuration
/// generation is published.
///
/// Empty configured users are deliberately excluded: their ambiguity is a
/// connection-level decision made by [`UserNamespaceResolver`], not a reason to
/// reject an otherwise valid namespace generation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RouteCandidateValidator;

impl CandidateValidator for RouteCandidateValidator {
    fn validate(
        &self,
        _effective: &EffectiveConfig,
        namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str> {
        let mut users = BTreeSet::new();
        for namespace in namespaces {
            let user = namespace.frontend.user.as_str();
            if !user.is_empty() && !users.insert(user) {
                return Err("routing_duplicate_frontend_user");
            }
        }
        Ok(PreparedArtifact::empty())
    }
}

/// A namespace resolution bound to the exact incarnation observed while the
/// client user was resolved.
///
/// Retaining this value does not retain admission authority. The router
/// registry must call [`Self::is_current`] at selector-open time.
#[derive(Clone, Debug)]
pub struct ResolvedNamespace {
    namespace: Arc<str>,
    incarnation: NamespaceIncarnation,
    origin: Arc<ConfigNamespaceSnapshot>,
}

impl ResolvedNamespace {
    pub(crate) fn named(
        origin: Arc<ConfigNamespaceSnapshot>,
        namespace: &str,
    ) -> Result<Self, RouteError> {
        let incarnation = origin
            .namespace_incarnation(namespace)
            .ok_or(RouteError::NamespaceMissing)?;
        Ok(Self {
            namespace: Arc::from(namespace),
            incarnation,
            origin,
        })
    }

    /// The resolved namespace name.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The exact namespace incarnation observed during resolution.
    #[must_use]
    pub const fn incarnation(&self) -> &NamespaceIncarnation {
        &self.incarnation
    }

    /// Whether this exact namespace incarnation remains current at `source`.
    #[must_use]
    pub fn is_current(&self, source: &dyn ConfigNamespaceSource) -> bool {
        self.origin
            .same_namespace_incarnation(&source.current(), &self.namespace)
    }

    pub(crate) fn origin(&self) -> Arc<ConfigNamespaceSnapshot> {
        Arc::clone(&self.origin)
    }
}

/// Resolves a decoded frontend user against the committed raw namespace set.
#[derive(Clone)]
pub struct UserNamespaceResolver {
    source: Arc<dyn ConfigNamespaceSource>,
}

impl UserNamespaceResolver {
    /// Binds the resolver to the process-local configuration source.
    #[must_use]
    pub fn new(source: Arc<dyn ConfigNamespaceSource>) -> Self {
        Self { source }
    }

    /// Resolves `user` and captures the selected namespace's exact incarnation.
    ///
    /// Nonempty users match a nonempty configured identity exactly, then fall
    /// back to namespace `default`. For an empty user, exactly one empty-user
    /// namespace wins; among several, an empty-user `default` wins; several
    /// without that default are rejected. With no empty-user namespace, the
    /// ordinary `default` fallback applies.
    ///
    /// # Errors
    ///
    /// Returns [`RouteError::NamespaceMissing`] when no deterministic namespace
    /// exists for this connection.
    pub fn resolve(&self, user: &str) -> Result<ResolvedNamespace, RouteError> {
        resolve_in(self.source.current(), user)
    }
}

fn resolve_in(
    snapshot: Arc<ConfigNamespaceSnapshot>,
    user: &str,
) -> Result<ResolvedNamespace, RouteError> {
    let namespaces = snapshot.namespaces();
    let selected = if user.is_empty() {
        let mut empty_users = namespaces
            .iter()
            .filter(|namespace| namespace.frontend.user.is_empty());
        match (empty_users.next(), empty_users.next()) {
            (Some(only), None) => Some(only),
            (Some(first), Some(second)) => std::iter::once(first)
                .chain(std::iter::once(second))
                .chain(empty_users)
                .find(|namespace| namespace.namespace == DEFAULT_NAMESPACE),
            (None, _) => namespaces
                .iter()
                .find(|namespace| namespace.namespace == DEFAULT_NAMESPACE),
        }
    } else {
        namespaces
            .iter()
            .find(|namespace| namespace.frontend.user == user)
            .or_else(|| {
                namespaces
                    .iter()
                    .find(|namespace| namespace.namespace == DEFAULT_NAMESPACE)
            })
    }
    .ok_or(RouteError::NamespaceMissing)?;

    let incarnation = snapshot
        .namespace_incarnation(&selected.namespace)
        .ok_or(RouteError::NamespaceMissing)?;
    Ok(ResolvedNamespace {
        namespace: Arc::from(selected.namespace.as_str()),
        incarnation,
        origin: snapshot,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use control_config::{
        CandidateValidator, ConfigNamespaceSource, ConfigNamespaceStore, EffectiveConfig,
        NamespaceConfig, SourceRevision, StoreError,
    };

    use super::{RouteCandidateValidator, RouteError, UserNamespaceResolver};

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
    }

    fn must_some<T>(value: Option<T>) -> T {
        value.unwrap_or_else(|| unreachable!("fixture: expected value"))
    }

    fn namespace(name: &str, user: &str) -> NamespaceConfig {
        let mut namespace = NamespaceConfig {
            namespace: name.to_owned(),
            ..NamespaceConfig::default()
        };
        namespace.frontend.user = user.to_owned();
        namespace
    }

    fn store(namespaces: Vec<NamespaceConfig>) -> ConfigNamespaceStore {
        must(ConfigNamespaceStore::new_with_validator(
            EffectiveConfig::default(),
            namespaces,
            SourceRevision {
                file_revision: 1,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
            Arc::new(RouteCandidateValidator),
        ))
    }

    fn resolver(store: &ConfigNamespaceStore) -> UserNamespaceResolver {
        UserNamespaceResolver::new(Arc::new(store.clone()))
    }

    #[test]
    fn nonempty_user_matches_exact_identity_then_falls_back_to_default() {
        let store = store(vec![
            namespace("default", "root"),
            namespace("analytics", "analyst"),
        ]);
        let resolver = resolver(&store);

        assert_eq!(must(resolver.resolve("analyst")).namespace(), "analytics");
        assert_eq!(must(resolver.resolve("unknown")).namespace(), "default");
    }

    #[test]
    fn nonempty_user_without_exact_or_default_namespace_is_rejected() {
        let store = store(vec![namespace("analytics", "analyst")]);
        assert_eq!(
            resolver(&store).resolve("unknown").map(|_| ()),
            Err(RouteError::NamespaceMissing)
        );
    }

    #[test]
    fn empty_user_uses_the_only_empty_identity_before_default_fallback() {
        let store = store(vec![
            namespace("default", "root"),
            namespace("anonymous", ""),
        ]);
        assert_eq!(must(resolver(&store).resolve("")).namespace(), "anonymous");
    }

    #[test]
    fn empty_user_uses_empty_default_among_several_empty_identities() {
        let store = store(vec![
            namespace("default", ""),
            namespace("anonymous-a", ""),
            namespace("anonymous-b", ""),
        ]);
        assert_eq!(must(resolver(&store).resolve("")).namespace(), "default");
    }

    #[test]
    fn empty_user_rejects_several_empty_identities_without_empty_default() {
        let store = store(vec![
            namespace("default", "root"),
            namespace("anonymous-a", ""),
            namespace("anonymous-b", ""),
        ]);
        assert_eq!(
            resolver(&store).resolve("").map(|_| ()),
            Err(RouteError::NamespaceMissing)
        );
    }

    #[test]
    fn empty_user_without_empty_identity_uses_ordinary_default_fallback() {
        let store = store(vec![
            namespace("default", "root"),
            namespace("analytics", "analyst"),
        ]);
        assert_eq!(must(resolver(&store).resolve("")).namespace(), "default");
    }

    #[test]
    fn validator_rejects_duplicate_nonempty_users_but_allows_empty_users() {
        let validator = RouteCandidateValidator;
        assert_eq!(
            validator
                .validate(
                    &EffectiveConfig::default(),
                    &[namespace("a", "same"), namespace("b", "same")],
                )
                .map(|_| ()),
            Err("routing_duplicate_frontend_user")
        );
        assert!(
            validator
                .validate(
                    &EffectiveConfig::default(),
                    &[namespace("a", ""), namespace("b", "")],
                )
                .is_ok()
        );
    }

    #[test]
    fn duplicate_nonempty_user_candidate_is_rejected_atomically() {
        let store = store(vec![namespace("default", "root")]);
        let before = store.current();
        let Err(error) = store.apply(
            (**before.effective()).clone(),
            vec![namespace("a", "same"), namespace("b", "same")],
            SourceRevision {
                file_revision: 2,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
        ) else {
            unreachable!("duplicate user must fail");
        };
        assert!(matches!(
            error,
            StoreError::CandidateRejected {
                class: "routing_duplicate_frontend_user"
            }
        ));
        assert!(Arc::ptr_eq(&before, &store.current()));
    }

    #[test]
    fn resolution_carries_exact_incarnation_and_replacement_retires_it() {
        let store = store(vec![namespace("default", "root")]);
        let resolved = must(resolver(&store).resolve("root"));
        assert!(resolved.is_current(&store));
        let old_incarnation = resolved.incarnation().clone();

        let published = must(store.apply(
            (**store.current().effective()).clone(),
            vec![namespace("default", "new-root")],
            SourceRevision {
                file_revision: 2,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
        ));
        let _ = must_some(published);

        assert!(!resolved.is_current(&store));
        let replacement = must(resolver(&store).resolve("new-root"));
        assert!(!old_incarnation.same_as(replacement.incarnation()));
        assert!(replacement.is_current(&store));
    }
}
