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

//! Pure time arithmetic shared by routing phases. No clock, cache or runtime
//! authority is consulted here. Go wall/monotonic values and Prometheus sample
//! ticks deliberately have different types and subtraction implementations.

use std::cmp::Ordering;

const NS: i64 = 1_000_000_000;
const UNIX_TO_INTERNAL: i64 = 62_135_596_800;
const PACKED_MIN: i64 = 59_453_308_800; // 1885-01-01, Go wallToInternal.
const PACKED_MAX: i64 = PACKED_MIN + (1_i64 << 33) - 1;

/// Pinned source implementation whose String baseline and arithmetic were audited.
pub const SUPPORTED_GO_VERSION: &str = "go1.25.12";

/// Validated startup baseline, bound by the transport to a process/nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    monotonic: Option<i64>,
}

impl Origin {
    /// Accept only the audited toolchain and an explicitly present baseline.
    /// Wall-only origins are supported; a later monotonic value cannot use one.
    #[must_use]
    pub fn new(version: &str, baseline_present: bool, baseline: i64) -> Option<Self> {
        if version != SUPPORTED_GO_VERSION || (!baseline_present && baseline != 0) {
            return None;
        }
        Some(Self {
            monotonic: baseline_present.then_some(baseline),
        })
    }

    /// Restore the raw Go monotonic value with checked, exact arithmetic.
    #[must_use]
    pub fn restore(self, relative: i64) -> Option<i64> {
        self.monotonic?.checked_add(relative)
    }
}

/// Complete Go `time.Time` equality identity and comparison operands.
/// Derived equality represents Go raw `==`, including the location identity;
/// [`Self::same_instant`] represents Go's separate `Equal` method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoTime {
    seconds: i64,
    nanoseconds: u32,
    location: u64,
    monotonic: Option<i64>,
}

impl GoTime {
    /// Construct a canonical value after restoring any captured monotonic offset.
    /// Wall seconds are relative to year 1, rather than a limited Unix-nanosecond
    /// scalar. A monotonic value must fit Go's packed wall-second representation.
    #[must_use]
    pub fn new(
        seconds: i64,
        nanoseconds: u32,
        location: u64,
        monotonic: Option<i64>,
    ) -> Option<Self> {
        if nanoseconds >= 1_000_000_000
            || location == 0
            || (monotonic.is_some() && !(PACKED_MIN..=PACKED_MAX).contains(&seconds))
        {
            return None;
        }
        Some(Self {
            seconds,
            nanoseconds,
            location,
            monotonic,
        })
    }

    /// Decode a monotonic-bearing capture. A missing origin or overflow fails
    /// before the value can participate in a qualified comparison.
    #[must_use]
    pub fn from_relative(
        seconds: i64,
        nanoseconds: u32,
        location: u64,
        origin: Origin,
        relative: i64,
    ) -> Option<Self> {
        Self::new(
            seconds,
            nanoseconds,
            location,
            Some(origin.restore(relative)?),
        )
    }

    /// Expose value fields for codecs and independent oracle checks.
    #[must_use]
    pub fn parts(self) -> (i64, u32, u64, Option<i64>) {
        (
            self.seconds,
            self.nanoseconds,
            self.location,
            self.monotonic,
        )
    }

    /// Compare using monotonic data if and only if both values carry it.
    #[must_use]
    pub fn compare(self, other: Self) -> Ordering {
        if let (Some(a), Some(b)) = (self.monotonic, other.monotonic) {
            return a.cmp(&b);
        }
        (self.seconds, self.nanoseconds).cmp(&(other.seconds, other.nanoseconds))
    }

    /// Go `Equal`, which deliberately ignores Location identity.
    #[must_use]
    pub fn same_instant(self, other: Self) -> bool {
        self.compare(other) == Ordering::Equal
    }

    /// Go `IsZero` depends only on wall seconds and nanoseconds.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.seconds == 0 && self.nanoseconds == 0
    }

    /// Go `Add`, including normalization, packed-wall and monotonic-overflow
    /// stripping, and the asymmetric negative wall-second overflow clamp.
    #[must_use]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn add_nanoseconds(self, duration: i64) -> Self {
        let mut seconds = duration / NS;
        let mut nanos = i64::from(self.nanoseconds) + duration % NS;
        if nanos >= NS {
            seconds += 1;
            nanos -= NS;
        } else if nanos < 0 {
            seconds -= 1;
            nanos += NS;
        }
        let wall = self.seconds.checked_add(seconds).unwrap_or(if seconds > 0 {
            i64::MAX
        } else {
            -i64::MAX
        });
        let monotonic = if (PACKED_MIN..=PACKED_MAX).contains(&wall) {
            self.monotonic.and_then(|value| value.checked_add(duration))
        } else {
            None
        };
        Self {
            seconds: wall,
            nanoseconds: nanos as u32,
            location: self.location,
            monotonic,
        }
    }

    /// Go `Sub` returns signed nanoseconds, saturating when a duration does not
    /// fit. The wall-only branch mirrors Go's Add/Equal overflow check exactly.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn sub_nanoseconds(self, other: Self) -> i64 {
        if let (Some(a), Some(b)) = (self.monotonic, other.monotonic) {
            return (i128::from(a) - i128::from(b)).clamp(i128::from(i64::MIN), i128::from(i64::MAX))
                as i64;
        }
        let duration = self
            .seconds
            .wrapping_sub(other.seconds)
            .wrapping_mul(NS)
            .wrapping_add(i64::from(self.nanoseconds) - i64::from(other.nanoseconds));
        if other.add_nanoseconds(duration).same_instant(self) {
            duration
        } else if self.compare(other) == Ordering::Less {
            i64::MIN
        } else {
            i64::MAX
        }
    }
}

/// Prometheus `model.Time`'s original signed millisecond tick value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleTime(pub i64);

impl SampleTime {
    /// Go model.Time subtraction wraps milliseconds first, then wraps the
    /// multiplication by one millisecond. It does not use `GoTime` saturation.
    #[must_use]
    pub fn sub_nanoseconds(self, other: Self) -> i64 {
        self.0.wrapping_sub(other.0).wrapping_mul(1_000_000)
    }

    /// Project the instant as Go `UnixMilli` does, preserving the caller's actual
    /// Location identity. Sample arithmetic must still use the original ticks.
    #[must_use]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn as_go_time(self, location: u64) -> Option<GoTime> {
        GoTime::new(
            self.0.div_euclid(1000) + UNIX_TO_INTERNAL,
            (self.0.rem_euclid(1000) * 1_000_000) as u32,
            location,
            None,
        )
    }
}

/// Explicit arithmetic-domain variant; a codec must not infer a domain from a
/// numeric magnitude or merge Go clocks and sample timestamps into one scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeValue {
    /// Go wall/monotonic time with complete raw cache identity.
    Go(GoTime),
    /// Prometheus signed millisecond sample time.
    Sample(SampleTime),
}

#[cfg(test)]
mod tests;
