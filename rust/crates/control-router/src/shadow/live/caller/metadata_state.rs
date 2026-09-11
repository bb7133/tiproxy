// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{InvalidReason, LiveState, Progress, Scope, metadata};

impl LiveState {
    /// Consume one router metadata frame's sequence with a childless caller
    /// scope. The independent metadata comparison happens in the caller's
    /// `metadata::Tracker`, whose retention is not installed here; its result
    /// decides whether this sequence commits or invalidates the owner. No
    /// production routing capability is installed by this API.
    #[must_use]
    pub fn observe_metadata_boundary(
        &mut self,
        boundary: &metadata::Boundary,
        frame_bytes: usize,
        comparison: Result<(), InvalidReason>,
    ) -> Progress {
        let previous = self.progress(boundary.epoch).compared_sequence;
        let result = self.begin_caller(Scope {
            epoch: boundary.epoch,
            group: 0,
            sequence: boundary.sequence,
            span: 1,
            sessions: &[],
            frame_bytes,
        });
        match result {
            Ok(stage) => stage.finish(comparison),
            Err(reason) => Progress {
                status: super::Status::Invalid(reason),
                compared_sequence: previous,
                transition: None,
            },
        }
    }
}
