// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{Begin, Construction, MAX_BACKENDS, MAX_GROUPS, Open, Tracker};
use std::mem::size_of;

// Preserve the reserved capacities: future pushes into an open generation may
// use that reservation, so a derived Vec::clone (capacity == len) is not enough.
fn reserved_clone<T: Clone>(values: &[T], capacity: usize) -> Vec<T> {
    let mut result = Vec::with_capacity(capacity);
    result.extend_from_slice(values);
    result
}

impl Tracker {
    pub(super) fn snapshot_charge(&self) -> usize {
        size_of::<Self>()
            + self.state.working_clone_heap()
            + self.open.as_ref().map_or(0, |open| {
                open.working.working_clone_heap()
                    + open.begin.inputs.len() * size_of::<super::Input>()
                    + Open::SCRATCH_HEAP
            })
    }

    pub(super) fn snapshot(&self) -> Self {
        Self {
            last_generation: self.last_generation,
            state: self.state.working_clone(),
            open: self.open.as_ref().map(|open| Open {
                begin: Begin {
                    generation: open.begin.generation,
                    observer_error: open.begin.observer_error,
                    rule: open.begin.rule,
                    inputs: open.begin.inputs.clone(),
                },
                working: open.working.working_clone(),
                decided: reserved_clone(&open.decided, MAX_BACKENDS),
                revisit: open.revisit,
                expected_decisions: open.expected_decisions,
                created: open.created,
                removed: open.removed,
                refresh_failed: open.refresh_failed,
                refresh_cursor: open.refresh_cursor,
                next_index: open.next_index,
                pending_created: reserved_clone::<Construction>(&open.pending_created, MAX_GROUPS),
                failed_constructions: reserved_clone(&open.failed_constructions, MAX_GROUPS),
                pending_removed: reserved_clone(&open.pending_removed, MAX_GROUPS),
                read_values: open.read_values,
                read_bytes: open.read_bytes,
                require_native_init: open.require_native_init,
            }),
            failed: self.failed,
            require_native_init: self.require_native_init,
        }
    }
}
