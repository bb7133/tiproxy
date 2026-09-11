// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pure arithmetic for the actual Go Group.Balance caller. This does not change
//! the staged scheduler's documented clamps, invoke clocks, or issue operations.

use crate::shadow::native::{BalanceRate, GoArch};
use control_routing::go_time::GoTime;

const TICK_NANOS: i64 = 10_000_000;
const SECOND_NANOS: f64 = 1_000_000_000.0;

/// The zero-rate check precedes both the Group clock and keyspace reads.
#[derive(Clone, Copy, Debug)]
pub enum Start {
    /// Either IEEE signed zero returns before consulting a clock or pair.
    NoRate,
    /// The caller must consume its one balance clock and keyspace reads next.
    ReadClock(Rate),
}

/// A nonzero independently computed factor rate, bound to the observed Go
/// architecture. Its constructor does not accept a Go output as proof of rate.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    value: f64,
    arch: GoArch,
}

/// Caller outcome after its actual balance clock and keyspace comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterClock {
    /// The whole pair is refused before interval conversion or any list scan.
    CrossKeyspace,
    /// Go reaches integer division by zero. It must not publish a normal caller
    /// envelope; producer unwinding invalidates and releases its owned capture.
    DivideByZero,
    /// A slow interval has not elapsed. Go returns before examining the list.
    Wait {
        /// Architecture-specific signed duration, in nanoseconds.
        interval: i64,
    },
    /// Go evaluates its linked-list/context/quota loop condition. The signed
    /// quota is deliberately not clamped to zero or to physical population.
    Scan {
        /// Architecture-specific signed duration, in nanoseconds.
        interval: i64,
        /// Raw Go int quota on the two supported 64-bit architectures.
        quota: i64,
    },
}

/// Classify the independently recomputed rate before consuming any caller read.
/// The installed comparator must compare the captured rate separately and may
/// never substitute the captured Go rate to repair a scheduling difference.
#[must_use]
pub fn start(rate: BalanceRate, arch: GoArch) -> Start {
    start_value(rate.value(), arch)
}

fn start_value(rate: f64, arch: GoArch) -> Start {
    if rate == 0.0 {
        Start::NoRate
    } else {
        Start::ReadClock(Rate { value: rate, arch })
    }
}

impl Rate {
    /// Calculate Go's exact next branch from already consumed inputs and the
    /// independently retained last accepted redirect time. This performs no
    /// clock, keyspace, context or production callback read itself.
    #[must_use]
    pub fn after_clock(self, same_keyspace: bool, now: GoTime, last: GoTime) -> AfterClock {
        if !same_keyspace {
            return AfterClock::CrossKeyspace;
        }
        let interval = duration_cast(SECOND_NANOS / self.value, self.arch);
        if interval == 0 {
            return AfterClock::DivideByZero;
        }
        if interval < TICK_NANOS * 2 {
            // Go signed division truncates toward zero. Negative intervals can
            // produce a negative quota; the literal loop still reads ctx.Err
            // if its first element exists before comparing i < count.
            AfterClock::Scan {
                interval,
                quota: (TICK_NANOS - 1) / interval + 1,
            }
        } else if now.sub_nanoseconds(last) >= interval {
            AfterClock::Scan { interval, quota: 1 }
        } else {
            AfterClock::Wait { interval }
        }
    }
}

// Pinned Go1.25.12 probes establish ARM64 saturating FCVTZS versus AMD64's
// CVTTSD2SQ indefinite MIN result for NaN and out-of-range inputs. Dispatch on
// the immutable producer architecture, never on the Rust observer host.
#[allow(clippy::cast_possible_truncation)]
fn duration_cast(value: f64, arch: GoArch) -> i64 {
    const EXCLUSIVE_MAX: f64 = 9_223_372_036_854_775_808.0;
    if arch == GoArch::Amd64
        && (!value.is_finite() || !(-EXCLUSIVE_MAX..EXCLUSIVE_MAX).contains(&value))
    {
        i64::MIN
    } else {
        // Rust's specified saturating float cast matches the ARM64 probe,
        // including NaN -> 0; finite in-range values truncate on both arches.
        value as i64
    }
}

#[cfg(test)]
mod tests;
