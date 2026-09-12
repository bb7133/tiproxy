// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-only delivery of whole external observer results. This reuses the real
//! publishers and their authority checks; it cannot seed router groups, scores,
//! reservations, or decisions. Network discovery/probing belongs to recording.

use crate::health_overlay::{HealthOverlayPublisher, HealthPublishOutcome};
use crate::{
    BackendHealth, EpochResult, HealthOverlayHandle, MergedTopology, ObserverError,
    RoutingSnapshotHandle, RoutingSnapshotPublisher,
};
use control_external::GenerationGate;
use control_plane::OwnerToken;
use std::collections::HashMap;
use std::sync::Arc;

/// Owns the external source publications for one replay; dropping it revokes
/// both handles. An input contains backend metadata and health verdicts only.
pub struct HealthInput {
    routing: RoutingSnapshotPublisher,
    health: HealthOverlayPublisher,
    owner: OwnerToken,
}

impl HealthInput {
    /// Delivers a failed observer result without inventing a healthy/empty list.
    /// # Errors
    /// Rejects absent, superseded, withdrawn or retired source authority.
    pub fn deliver_error(&self, error: ObserverError) -> Result<(), &'static str> {
        if !self.owner.is_current() {
            return Err("health input owner retired");
        }
        let source = self
            .routing
            .handle()
            .current()
            .ok_or("routing input retired")?;
        if self.health.publish_error(&source, error) != HealthPublishOutcome::Published {
            return Err("health input retired");
        }
        Ok(())
    }

    pub(crate) fn new(owner: OwnerToken) -> (Self, RoutingSnapshotHandle, HealthOverlayHandle) {
        let (routing, routing_handle) = RoutingSnapshotPublisher::new();
        let (health, health_handle) = HealthOverlayPublisher::new();
        (
            Self {
                routing,
                health,
                owner,
            },
            routing_handle,
            health_handle,
        )
    }

    /// Publishes a completed health result, including unhealthy entries and an
    /// authoritative empty inventory. No background poll can overwrite it.
    /// # Errors
    /// Rejects a retired owner or exhausted/withdrawn publication.
    pub fn deliver(
        &self,
        topology: MergedTopology,
        health: HashMap<Arc<str>, BackendHealth>,
        redirection: HashMap<Arc<str>, bool>,
    ) -> Result<(), &'static str> {
        if !self.owner.is_current() {
            return Err("health input owner retired");
        }
        self.routing
            .publish(EpochResult {
                client_epoch: 1,
                value: topology,
            })
            .map_err(|_| "routing generation exhausted")?;
        let source = self
            .routing
            .handle()
            .current()
            .ok_or("routing input retired")?;
        if self.health.publish_result(
            &source,
            health,
            redirection,
            GenerationGate::new(),
            &self.owner,
        ) != HealthPublishOutcome::Published
        {
            return Err("health input retired");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::HealthInput;
    use crate::{MergedTopology, ObserverError};
    use control_plane::{OwnerScope, OwnershipRegistry};
    use std::collections::HashMap;

    #[test]
    fn observer_error_recovery_and_owner_retirement_fence_retained_health() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "api-observer-error")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let (input, routing, health) = HealthInput::new(lease.token());
        let publish = || {
            input
                .deliver(
                    MergedTopology {
                        backends: Vec::new(),
                    },
                    HashMap::new(),
                    HashMap::new(),
                )
                .unwrap_or_else(|error| unreachable!("publish: {error}"));
        };
        publish();
        let source = routing.current().unwrap_or_else(|| unreachable!("source"));
        let good = health
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("health"));
        input
            .deliver_error(ObserverError::TopologyUnavailable)
            .unwrap_or_else(|error| unreachable!("error result: {error}"));
        let failed = health
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("failed"));
        assert_eq!(
            failed.observer_error(),
            Some(ObserverError::TopologyUnavailable)
        );
        assert!(!health.still_current_for(&good, &source, &routing));
        assert!(health.still_current_for(&failed, &source, &routing));
        publish();
        assert!(!health.still_current_for(&failed, &source, &routing));
        let recovered = health
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("recovered"));
        assert_eq!(recovered.observer_error(), None);
        drop(lease);
        assert!(input.deliver_error(ObserverError::Cancelled).is_err());
        assert!(health.current_for(&source).is_none());
    }
}
