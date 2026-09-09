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

//! Actual Go `BackendsToBalance` priority walk, separate from new connections.

use super::{BalancePair, FactorScore, Input, phases};

pub(super) fn select(sorted: &[(&Input, FactorScore)]) -> Option<BalancePair> {
    let (source, advice) = phases::balance(
        sorted.len(),
        |i| &sorted[i].1,
        |i| sorted[i].0.counts.active() > 0 && sorted[i].0.counts.connection_score() > 0,
        |i, factor| {
            sorted[i]
                .1
                .advice_to_best
                .iter()
                .copied()
                .find(|a| a.factor == factor)
                .unwrap_or(super::FactorAdvice {
                    factor,
                    advice: super::BalanceAdvice::Neutral,
                    count: 0.0,
                })
        },
    )?;
    Some(BalancePair {
        from: sorted[source].0.id.clone(),
        to: sorted[0].1.backend_id.clone(),
        rate: advice.count,
        reason: advice.factor,
    })
}
