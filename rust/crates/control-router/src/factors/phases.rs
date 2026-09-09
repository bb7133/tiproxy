// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared arithmetic phases. These inputs contain values only, with no account,
//! source, router, candidate or reservation identity. Both normal evaluation and
//! native shadow evaluation must compute their own history before supplying them.

use super::{BalanceAdvice, Factor, FactorAdvice};
use control_config::RoutingConfig;

#[derive(Clone, Copy)]
pub(crate) struct ScoreValues {
    pub label_matches: bool,
    pub healthy: bool,
    pub local: bool,
    pub connections: u64,
    pub health_risk: u8,
    pub memory_risk: u8,
    pub cpu_usage: f64,
    pub go_arch: super::window::GoArch,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn score(factor: Factor, value: ScoreValues, active: [bool; 3], multiple: bool) -> u64 {
    match factor {
        Factor::Label => u64::from(!value.label_matches),
        Factor::Status => u64::from(!value.healthy),
        Factor::Location => u64::from(multiple && !value.local),
        Factor::Connection => value.connections.min(u64::from(u16::MAX)),
        Factor::Health => {
            if active[0] {
                u64::from(value.health_risk)
            } else {
                0
            }
        }
        Factor::Memory => {
            if active[1] {
                u64::from(value.memory_risk)
            } else {
                0
            }
        }
        Factor::Cpu => {
            if active[2] {
                (value.go_arch.duration(value.cpu_usage * 100.0) / 5).clamp(0, 31) as u64
            } else {
                0
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AdviceValues {
    pub connections: super::window::Count,
    pub status_count: f64,
    pub health: (u8, f64),
    pub memory: (u8, f64),
    pub cpu: (f64, f64),
}

pub(crate) fn advice(
    factor: Factor,
    from: AdviceValues,
    to: AdviceValues,
    usage_per_conn: f64,
    policy: &RoutingConfig,
) -> FactorAdvice {
    use BalanceAdvice::{Negative, Neutral, Positive};
    let configured = |rate: f64, default: f64| if rate > 0.0 { rate } else { default };
    let (advice, count) = match factor {
        Factor::Label => (Positive, 1.0),
        Factor::Status => (
            Positive,
            configured(policy.status.migrations_per_second, from.status_count),
        ),
        Factor::Location => (
            Positive,
            configured(policy.location.migrations_per_second, 1.0),
        ),
        Factor::Health => {
            if i16::from(from.health.0) - i16::from(to.health.0) <= 1 {
                (Neutral, 0.0)
            } else {
                (
                    Positive,
                    configured(policy.health.migrations_per_second, from.health.1),
                )
            }
        }
        Factor::Memory => {
            if i16::from(from.memory.0) - i16::from(to.memory.0) <= 1 {
                (Neutral, 0.0)
            } else {
                (
                    Positive,
                    configured(policy.memory.migrations_per_second, from.memory.1),
                )
            }
        }
        Factor::Cpu => {
            let (fa, fl) = from.cpu;
            let (ta, tl) = to.cpu;
            let per = usage_per_conn;
            if (1.3 - (ta + per)) * 1.1 < 1.3 - (fa - per)
                || (1.3 - (tl + per)) * 1.1 < 1.3 - (fl - per)
            {
                (Negative, 0.0)
            } else if 1.3 - ta < (1.3 - fa) * 1.2 || 1.3 - tl < (1.3 - fl) * 1.2 {
                (Neutral, 0.0)
            } else {
                (
                    Positive,
                    configured(policy.cpu.migrations_per_second, 1.0 / per / 600.0),
                )
            }
        }
        Factor::Connection => {
            let from = from.connections;
            let to = to.connections;
            let native = matches!(from, super::window::Count::Go(_));
            let ratio = if native || policy.connection.count_ratio_threshold > 1.0 {
                policy.connection.count_ratio_threshold
            } else {
                1.2
            };
            if from.value() <= to.plus_one() * ratio {
                (Neutral, 0.0)
            } else {
                let count = (from.sum_plus_one(to) / (1.0 + ratio) - to.plus_one()) / 120.0;
                // Go's explicit comparison preserves NaN; f64::max would erase it.
                let count = if native {
                    if count < 0.0 { 0.0 } else { count }
                } else {
                    count.max(0.0)
                };
                (
                    Positive,
                    configured(policy.connection.migrations_per_second, count),
                )
            }
        }
    };
    FactorAdvice {
        factor,
        advice,
        count,
    }
}

pub(crate) fn compose(parts: &[(Factor, u64)]) -> (u64, bool) {
    let mut packed = 0;
    let mut routeable = true;
    for &(factor, part) in parts {
        packed = (packed << factor.bits()) + part;
        if matches!(factor, Factor::Label | Factor::Status) && part != 0 {
            routeable = false;
        }
    }
    (packed, routeable)
}

pub(crate) fn preferred<'a>(
    n: usize,
    row: impl Fn(usize) -> &'a super::FactorScore,
    mut advice: impl FnMut(usize, Factor) -> FactorAdvice,
) -> Vec<usize> {
    let mut result = Vec::new();
    if n == 0 || !row(0).routeable {
        return result;
    }
    for source in (1..n).rev() {
        let mut count = 0.0;
        for (&(factor, from), &(_, to)) in row(source).parts.iter().zip(&row(0).parts) {
            if from > to {
                let answer = advice(source, factor);
                count = answer.count;
                if answer.advice == BalanceAdvice::Positive && count > 0.0001 {
                    break;
                }
            } else if from < to {
                break;
            }
        }
        if count <= 0.0001 {
            result.push(source);
        }
    }
    result.push(0);
    result
}

pub(crate) fn balance<'a>(
    n: usize,
    row: impl Fn(usize) -> &'a super::FactorScore,
    mut positive: impl FnMut(usize) -> bool,
    mut advice: impl FnMut(usize, Factor) -> FactorAdvice,
) -> Option<(usize, FactorAdvice)> {
    if n <= 1 || !row(0).routeable || row(0).score == row(n - 1).score {
        return None;
    }
    for source in (1..n).rev() {
        if !positive(source) {
            continue;
        }
        for (&(factor, from), &(_, to)) in row(source).parts.iter().zip(&row(0).parts) {
            if from < to {
                break;
            }
            let answer = advice(source, factor);
            if answer.advice == BalanceAdvice::Negative {
                break;
            }
            if from > to && answer.advice == BalanceAdvice::Positive && answer.count > 0.0001 {
                return Some((source, answer));
            }
        }
    }
    None
}

pub(crate) fn ticket(n: usize, random: bool, seed: u128) -> Option<usize> {
    if n == 0 {
        return None;
    }
    let n = n as u128;
    usize::try_from(if random {
        seed % (10 * n + 1) % n
    } else {
        seed % n
    })
    .ok()
}
