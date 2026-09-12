// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-only delivery of whole external observer results. This reuses the real
//! publishers and their authority checks; it cannot seed router groups, scores,
//! reservations, or decisions. Network discovery/probing belongs to recording.

use crate::health_overlay::{HealthOverlayPublisher, HealthPublishOutcome};
use crate::{
    BackendHealth, EpochResult, HealthOverlayHandle, MergedTopology, RoutingSnapshotHandle,
    RoutingSnapshotPublisher,
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
