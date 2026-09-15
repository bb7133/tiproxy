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
    type Time = Option<i64>;
    fn time(&self) -> Self::Time {
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
    fn clock(&mut self, _: ClockSite) -> Result<Option<i64>, Self::Error> {
        Ok(Some(self.now))
    }
}

// All representable Unix nanoseconds are later than Go's year-one zero.
// Widen only the comparisons; mapping zero to i64::MIN or Unix epoch would
// corrupt first-publication equality and exact expiry boundaries.
impl super::window::Time for Option<i64> {
    fn before(self, other: Self) -> bool {
        self < other
    }
    fn expired(self, now: Self, seconds: i64) -> bool {
        const GO_ZERO_NANOS: i128 = -62_135_596_800_000_000_000;
        let nanos = |value: Self| value.map_or(GO_ZERO_NANOS, i128::from);
        nanos(self) + i128::from(seconds) * 1_000_000_000 < nanos(now)
    }
    fn stale(self, now: Self, seconds: i64) -> bool {
        self.expired(now, seconds)
    }
    fn sample(milliseconds: i64, _: Self) -> Self {
        Some(milliseconds.saturating_mul(1_000_000))
    }
    fn sample_delta(new: i64, old: i64) -> i64 {
        new.saturating_mul(1_000_000)
            .saturating_sub(old.saturating_mul(1_000_000))
    }
    fn initial_key(zero: Self) -> Option<Self> {
        Some(zero)
    }
    fn is_zero(self) -> bool {
        self.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::super::window::Time;

    #[test]
    fn go_zero_and_unix_epoch_keep_distinct_cache_and_expiry_keys() {
        assert_eq!(Option::<i64>::initial_key(None), Some(None));
        assert!(None::<i64>.is_zero());
        assert!(!Some(0_i64).is_zero());
        assert!(None.before(Some(i64::MIN)));
        assert!(!Some(i64::MIN).before(None));
        assert!(None.expired(Some(i64::MIN), 120));
        assert!(!Some(i64::MAX).expired(None, 120));
        for seconds in [60, 120] {
            let limit = seconds * 1_000_000_000;
            assert!(!Some(0).stale(Some(limit), seconds));
            assert!(Some(0).stale(Some(limit + 1), seconds));
            assert!(!Some(i64::MAX).expired(Some(i64::MAX), seconds));
        }
        assert_eq!(Option::<i64>::sample(0, None), Some(0));
    }
}
