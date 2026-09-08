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

use super::{BalanceAdvice, BalancePair, FactorScore, Input};

pub(super) fn select(sorted: &[(&Input, FactorScore)]) -> Option<BalancePair> {
    let (_, best) = sorted.first()?;
    let (_, worst) = sorted.last()?;
    if !best.routeable || best.score == worst.score {
        return None;
    }
    for (source, row) in sorted.iter().skip(1).rev() {
        if source.counts.active() == 0 || source.counts.connection_score() == 0 {
            continue;
        }
        for (((_, from), (_, to)), advice) in
            row.parts.iter().zip(&best.parts).zip(&row.advice_to_best)
        {
            // Negative advice also vetoes an EQUAL higher-priority segment.
            // A later factor may not undo this protection.
            if from < to || advice.advice == BalanceAdvice::Negative {
                break;
            }
            if from > to && advice.advice == BalanceAdvice::Positive && advice.count > 0.0001 {
                return Some(BalancePair {
                    from: source.id.clone(),
                    to: best.backend_id.clone(),
                    rate: advice.count,
                    reason: advice.factor,
                });
            }
        }
    }
    None
}
