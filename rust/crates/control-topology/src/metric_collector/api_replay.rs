// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Whole merged external query delivery for the test-only API input adapter.
//! This owns a real bound collector lifetime but never starts network workers.

use super::{
    Arc, BTreeMap, GenerationGate, MetricCollector, MetricCollectorError, MetricOverlayHandle,
    MetricSourceHandle, QueryId, QueryLifetime, QueryResult, SocketAddr,
};

pub(super) struct ExternalResult {
    pub queries: BTreeMap<QueryId, QueryResult>,
    pub lineage: Arc<()>,
    pub gate: GenerationGate,
    lifetime: QueryLifetime,
}
impl ExternalResult {
    pub fn current(&self) -> bool {
        self.gate.is_live() && self.lifetime.is_live()
    }
}

pub(crate) struct InputBuffer {
    collector: MetricCollector,
    queries: BTreeMap<QueryId, QueryResult>,
    lineage: Arc<()>,
    incarnation: Option<control_config::ResourceIncarnation>,
}
impl InputBuffer {
    pub async fn new(
        source: MetricSourceHandle,
        owner: control_plane::OwnerToken,
    ) -> Result<Self, MetricCollectorError> {
        let (collector, _) =
            MetricCollector::bind_for_routing(source, SocketAddr::from(([127, 0, 0, 1], 0)))
                .await?;
        collector.shared.serving.activate(owner);
        Ok(Self {
            collector,
            queries: BTreeMap::new(),
            lineage: Arc::new(()),
            incarnation: None,
        })
    }
    pub fn handle(&self) -> MetricOverlayHandle {
        MetricOverlayHandle {
            shared: Arc::clone(&self.collector.shared),
        }
    }
    pub fn replace(&mut self, queries: BTreeMap<QueryId, QueryResult>) -> Result<(), &'static str> {
        self.queries = queries;
        self.sync(true)
    }
    pub fn sync(&mut self, replace: bool) -> Result<(), &'static str> {
        let shared = &self.collector.shared;
        if !shared.serving.is_live() {
            return Err("metric input owner retired");
        }
        let incarnation = shared.source.resource_incarnation();
        if !incarnation.enabled() {
            shared.lock().clear();
            self.incarnation = None;
            return Ok(());
        }
        let capture = shared
            .source
            .capture()
            .ok_or("metric input source unavailable")?;
        let same_incarnation = self
            .incarnation
            .as_ref()
            .is_some_and(|old| old.same_as(&incarnation));
        if !same_incarnation {
            self.lineage = Arc::new(());
        }
        let unchanged = {
            let published = shared.lock();
            published
                .capture
                .as_ref()
                .is_some_and(|old| old.same_generation(&capture))
                && published.external.as_ref().is_some_and(|old| old.current())
        };
        if unchanged && same_incarnation && !replace {
            return Ok(());
        }
        let result = Arc::new(ExternalResult {
            queries: self.queries.clone(),
            lineage: Arc::clone(&self.lineage),
            gate: GenerationGate::new(),
            lifetime: QueryLifetime {
                source: shared.source.clone(),
                incarnation: incarnation.clone(),
            },
        });
        let installed = shared
            .serving
            .with_live(|| {
                capture.with_current(|| {
                    if !result.current() {
                        return false;
                    }
                    let mut published = shared.lock();
                    published.clear();
                    published.capture = Some(capture.clone());
                    published.external = Some(result);
                    true
                })
            })
            .flatten()
            .unwrap_or(false);
        if !installed {
            return Err("metric input publication retired");
        }
        self.incarnation = Some(incarnation);
        Ok(())
    }
}
impl Drop for InputBuffer {
    fn drop(&mut self) {
        self.collector.shared.serving.close();
        self.collector.shared.lock().clear();
    }
}
