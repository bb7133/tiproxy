// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Whole query values at the same merged public boundary as the Go recorder.

use crate::metric_collector::api_replay::InputBuffer;
use crate::metric_source::MetricPublication;
use crate::metrics::{QueryId, QueryResult, Sample, Series, ValueKind, query_catalog};
use crate::{DiscoveryHandle, MetricOverlayHandle, ModeEpoch, RoutingSnapshotHandle};
use control_config::{ConfigNamespaceSource, HealthCheckConfig};
use control_plane::OwnerToken;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputSample {
    timestamp_ms: i64,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputSeries {
    labels: BTreeMap<String, String>,
    samples: Vec<InputSample>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputResult {
    kind: String,
    updated_nanos: Option<i64>,
    series: Vec<InputSeries>,
}

fn decode(value: serde_json::Value) -> Result<BTreeMap<QueryId, QueryResult>, &'static str> {
    let mut packet: BTreeMap<String, Option<InputResult>> =
        serde_json::from_value(value).map_err(|_| "metric input fields")?;
    if packet.len() != query_catalog().len() {
        return Err("whole metric input required");
    }
    let mut queries = BTreeMap::new();
    for spec in query_catalog() {
        let result = packet.remove(spec.id.key()).ok_or("missing metric query")?;
        let Some(result) = result else {
            continue;
        };
        let kind = match result.kind.as_str() {
            "matrix" => ValueKind::Matrix,
            "vector" => ValueKind::Vector,
            _ => return Err("metric result kind"),
        };
        let updated_nanos = result.updated_nanos;
        let mut series = Vec::new();
        for input in result.series {
            if kind == ValueKind::Vector && input.samples.len() != 1 {
                return Err("vector metric sample count");
            }
            let mut samples = Vec::new();
            for sample in input.samples {
                let value = match sample.value.as_str() {
                    "NaN" => f64::NAN,
                    "+Inf" => f64::INFINITY,
                    "-Inf" => f64::NEG_INFINITY,
                    value => {
                        let parsed = value.parse::<f64>().map_err(|_| "metric sample number")?;
                        if !parsed.is_finite() {
                            return Err("metric sample overflow");
                        }
                        parsed
                    }
                };
                samples.push(Sample {
                    timestamp_ms: sample.timestamp_ms,
                    value,
                });
            }
            series.push(Series {
                labels: input.labels,
                samples,
            });
        }
        queries.insert(
            spec.id,
            QueryResult {
                kind,
                series,
                updated_nanos,
            },
        );
    }
    Ok(queries)
}

/// One unique replay writer. Routing/config/discovery and process authority are
/// supplied by the real topology module, never reconstructed from trace fields.
/// Drop revokes retained metric snapshots and releases the bound listener.
pub struct MetricInput {
    publication: MetricPublication,
    buffer: InputBuffer,
    routing: RoutingSnapshotHandle,
    discovery: DiscoveryHandle,
    mode: watch::Receiver<Arc<ModeEpoch>>,
    owner: OwnerToken,
}
impl MetricInput {
    pub(crate) async fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        owner: OwnerToken,
        routing: RoutingSnapshotHandle,
        discovery: DiscoveryHandle,
        mode: watch::Receiver<Arc<ModeEpoch>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (mut publication, handle) =
            MetricPublication::new(source, HealthCheckConfig::default());
        publication.enable()?;
        let buffer = InputBuffer::new(handle, owner.clone()).await?;
        Ok(Self {
            publication,
            buffer,
            routing,
            discovery,
            mode,
            owner,
        })
    }
    /// Read-only handle consumed by the existing router factor path.
    #[must_use]
    pub fn handle(&self) -> MetricOverlayHandle {
        self.buffer.handle()
    }

    /// Re-pairs unchanged public data after an applied health/config event.
    /// # Errors
    /// A retired source/owner or absent dynamic discovery remains unavailable.
    pub fn sync(&mut self) -> Result<(), &'static str> {
        if !self.owner.is_current() {
            return Err("metric input owner retired");
        }
        let routing = self.routing.current().ok_or("routing input unavailable")?;
        let discovery = self
            .discovery
            .capture()
            .map_err(|_| "discovery input unavailable")?;
        self.publication.pair_replay(
            routing,
            discovery,
            self.mode.borrow().clone(),
            &self.owner,
        )?;
        self.buffer.sync(false)
    }

    /// Decodes and replaces one entire public set. No query getter mutates it.
    /// # Errors
    /// Rejects malformed values, unsupported Go zero time and stale authority.
    pub fn deliver(&mut self, queries: serde_json::Value) -> Result<(), &'static str> {
        let queries = decode(queries)?;
        self.sync()?;
        self.buffer.replace(queries)
    }
}
