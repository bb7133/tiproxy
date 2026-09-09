// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The existing single-time staged API adapts to the shared ordered phases.

use super::{
    Input, Queries,
    window::{Backend, ClockSite, Count, Query, Window},
};
use control_topology::metrics::{QueryId, QueryResult, Sample, ValueKind};
use std::{borrow::Cow, convert::Infallible};

impl Backend for Input {
    fn key(&self) -> &str {
        &self.id
    }
    fn instance(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.instance)
    }
    fn cluster(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.cluster)
    }
    fn physical(&self) -> Count {
        Count::Legacy(self.counts.active())
    }
    fn score_count(&self) -> Count {
        Count::Legacy(self.counts.connection_score())
    }
    fn healthy(&self) -> bool {
        self.healthy
    }
}
impl Query for QueryResult {
    type Time = i64;
    fn time(&self) -> i64 {
        self.updated_nanos
    }
    fn empty(&self) -> bool {
        self.is_empty()
    }
    fn samples<'a>(&'a self, backend: &impl Backend, matrix: bool) -> &'a [Sample] {
        let expected = if matrix {
            ValueKind::Matrix
        } else {
            ValueKind::Vector
        };
        if self.kind != expected {
            return &[];
        }
        self.samples_for(&backend.instance(), &backend.cluster())
            .unwrap_or_default()
    }
}
pub(super) struct RepeatedTime<'a> {
    pub queries: &'a Queries,
    pub now: i64,
}
impl<'a> Window<'a, QueryResult> for RepeatedTime<'a> {
    type Error = Infallible;
    fn query(&mut self, id: QueryId) -> Result<Option<&'a QueryResult>, Self::Error> {
        Ok(self.queries.get(&id))
    }
    fn clock(&mut self, _: ClockSite) -> Result<i64, Self::Error> {
        Ok(self.now)
    }
}
