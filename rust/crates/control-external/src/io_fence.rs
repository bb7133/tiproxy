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

//! Composable local authority checks at external I/O boundaries.

use crate::GenerationGate;
use std::sync::Arc;

/// A live local capability checked before and after external effects.
///
/// Implementations must be short, synchronous, and non-blocking. A fence does
/// not mint publication authority: callers retain their actual owner/material/
/// source capabilities and perform the final synchronized publication check.
pub trait IoFence: Send + Sync {
    /// Whether every retained capability is still admissible for this operation.
    fn is_live(&self) -> bool;
}

impl IoFence for GenerationGate {
    fn is_live(&self) -> bool {
        GenerationGate::is_live(self)
    }
}

impl<T: IoFence + ?Sized> IoFence for Arc<T> {
    fn is_live(&self) -> bool {
        self.as_ref().is_live()
    }
}

/// Checks both capabilities at every effect boundary, without copying their state.
pub struct CombinedFence<'a> {
    first: &'a dyn IoFence,
    second: &'a dyn IoFence,
}

impl<'a> CombinedFence<'a> {
    /// Borrows two live checks for the duration of one operation.
    #[must_use]
    pub fn new(first: &'a dyn IoFence, second: &'a dyn IoFence) -> Self {
        Self { first, second }
    }
}

impl IoFence for CombinedFence<'_> {
    fn is_live(&self) -> bool {
        self.first.is_live() && self.second.is_live()
    }
}

/// Owned equivalent for a forked client that outlives a borrowed call frame.
pub(crate) struct OwnedCombinedFence(pub Arc<dyn IoFence>, pub Arc<dyn IoFence>);

impl IoFence for OwnedCombinedFence {
    fn is_live(&self) -> bool {
        self.0.is_live() && self.1.is_live()
    }
}
