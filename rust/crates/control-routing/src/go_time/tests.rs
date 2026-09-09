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

use super::*;

fn integer<T: std::str::FromStr>(value: &str) -> T {
    value
        .parse()
        .unwrap_or_else(|_| unreachable!("oracle integer {value}"))
}

fn go(value: &str, origin: Origin) -> GoTime {
    let parts: Vec<_> = value.split(',').collect();
    assert_eq!(parts.len(), 5);
    let mono = if integer::<bool>(parts[3]) {
        Some(
            origin
                .restore(integer(parts[4]))
                .unwrap_or_else(|| unreachable!("oracle origin")),
        )
    } else {
        assert_eq!(integer::<i64>(parts[4]), 0);
        None
    };
    GoTime::new(
        integer(parts[0]),
        integer(parts[1]),
        integer(parts[2]),
        mono,
    )
    .unwrap_or_else(|| unreachable!("oracle time"))
}

#[test]
fn actual_go_oracle() {
    let supplied = std::env::var("TIPROXY_CLOCK_ORACLE").ok().map(|path| {
        std::fs::read_to_string(path).unwrap_or_else(|error| unreachable!("oracle file: {error}"))
    });
    let text = supplied.as_deref().unwrap_or(include_str!(
        "../../../../../tests/controlplane/cproute/shadow/time-oracle.tsv"
    ));
    let mut lines = text.lines();
    let header: Vec<_> = lines
        .next()
        .unwrap_or_else(|| unreachable!("origin header"))
        .split('\t')
        .collect();
    assert_eq!(header[0], "origin");
    let origin = Origin::new(header[1], integer(header[2]), integer(header[3]))
        .unwrap_or_else(|| unreachable!("valid oracle origin"));
    let (mut clocks, mut samples) = (0, 0);
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        match fields[0] {
            "go" => {
                assert_eq!(fields.len(), 11);
                let (a, b) = (go(fields[2], origin), go(fields[3], origin));
                assert_eq!(
                    a.add_nanoseconds(integer(fields[4])),
                    go(fields[5], origin),
                    "TIME_GO_ADD: {}",
                    fields[1]
                );
                assert_eq!(
                    a.sub_nanoseconds(b),
                    integer(fields[6]),
                    "TIME_GO_SUB_SATURATION: {}",
                    fields[1]
                );
                assert_eq!(a.compare(b) == Ordering::Less, integer::<bool>(fields[7]));
                assert_eq!(
                    a.compare(b) == Ordering::Greater,
                    integer::<bool>(fields[8])
                );
                assert_eq!(a.same_instant(b), integer::<bool>(fields[9]));
                assert_eq!(
                    a == b,
                    integer::<bool>(fields[10]),
                    "TIME_GO_RAW_IDENTITY: {}",
                    fields[1]
                );
                clocks += 1;
            }
            "sample" => {
                assert_eq!(fields.len(), 7);
                let (a, b) = (
                    SampleTime(integer(fields[2])),
                    SampleTime(integer(fields[3])),
                );
                assert_eq!(
                    a.sub_nanoseconds(b),
                    integer(fields[4]),
                    "TIME_SAMPLE_WRAPPING: {}",
                    fields[1]
                );
                let expected = go(fields[6], origin);
                let av = a
                    .as_go_time(expected.location)
                    .unwrap_or_else(|| unreachable!("sample time"));
                let bv = b
                    .as_go_time(expected.location)
                    .unwrap_or_else(|| unreachable!("sample time"));
                assert_eq!(av, expected, "TIME_SAMPLE_WALL_CONVERSION");
                let reference = GoTime::new(PACKED_MIN, 0, expected.location, Some(17))
                    .unwrap_or_else(|| unreachable!("reference"));
                assert_eq!(
                    a.as_go_time_at(reference),
                    expected,
                    "TIME_SAMPLE_REFERENCE_CONVERSION"
                );
                assert_eq!(
                    av.sub_nanoseconds(bv),
                    integer(fields[5]),
                    "TIME_SAMPLE_SEPARATE_DOMAIN"
                );
                samples += 1;
            }
            other => unreachable!("oracle domain {other}"),
        }
    }
    assert_eq!((clocks, samples), (12, 5));
}

fn value(seconds: i64, monotonic: Option<i64>) -> GoTime {
    GoTime::new(seconds, 0, 1, monotonic).unwrap_or_else(|| unreachable!("valid fixture"))
}

#[test]
fn baseline_checked_reconstruction_and_monotonic_add_stripping() {
    let upper = Origin::new(SUPPORTED_GO_VERSION, true, i64::MAX - 1)
        .unwrap_or_else(|| unreachable!("origin"));
    assert_eq!(
        upper.restore(1),
        Some(i64::MAX),
        "TIME_ORIGIN_REBUILD_EQUAL"
    );
    assert_eq!(upper.restore(2), None, "TIME_ORIGIN_REBUILD_PLUS_ONE");
    let lower = Origin::new(SUPPORTED_GO_VERSION, true, i64::MIN + 1)
        .unwrap_or_else(|| unreachable!("origin"));
    assert_eq!(
        lower.restore(-1),
        Some(i64::MIN),
        "TIME_ORIGIN_REBUILD_EQUAL"
    );
    assert_eq!(lower.restore(-2), None, "TIME_ORIGIN_REBUILD_PLUS_ONE");
    let a = GoTime::from_relative(PACKED_MIN + 1, 0, 1, upper, 1)
        .unwrap_or_else(|| unreachable!("time"));
    assert_eq!(
        a.add_nanoseconds(1).monotonic,
        None,
        "TIME_MONOTONIC_ADD_STRIP"
    );
    assert_eq!(a.add_nanoseconds(0).monotonic, Some(i64::MAX));
    assert_eq!(a.add_nanoseconds(-1).monotonic, Some(i64::MAX - 1));
    let b = GoTime::from_relative(PACKED_MIN + 1, 0, 1, lower, -1)
        .unwrap_or_else(|| unreachable!("time"));
    assert_eq!(
        b.add_nanoseconds(-1).monotonic,
        None,
        "TIME_MONOTONIC_ADD_STRIP"
    );
    assert_eq!(
        a.sub_nanoseconds(b),
        i64::MAX,
        "TIME_MONOTONIC_SUB_SATURATION"
    );
    assert_eq!(
        b.sub_nanoseconds(a),
        i64::MIN,
        "TIME_MONOTONIC_SUB_SATURATION"
    );
}

#[test]
fn invalid_origin_and_time_values_cannot_be_qualified() {
    assert!(
        Origin::new("go1.26.0", true, 1).is_none(),
        "TIME_ORIGIN_VERSION_REJECT"
    );
    assert!(Origin::new(SUPPORTED_GO_VERSION, false, 1).is_none());
    let absent = Origin::new(SUPPORTED_GO_VERSION, false, 0)
        .unwrap_or_else(|| unreachable!("wall-only origin"));
    assert!(
        GoTime::from_relative(PACKED_MIN, 0, 1, absent, 0).is_none(),
        "TIME_ORIGIN_BASELINE_REQUIRED"
    );
    assert!(GoTime::new(PACKED_MIN, 0, 0, None).is_none());
    assert!(GoTime::new(0, 1_000_000_000, 1, None).is_none());
    assert!(GoTime::new(PACKED_MIN - 1, 0, 1, Some(1)).is_none());
    assert!(GoTime::new(PACKED_MAX + 1, 0, 1, Some(1)).is_none());
}

#[test]
fn clock_adjustment_and_extreme_wall_add_follow_distinct_rules() {
    let a = value(PACKED_MIN + 10, Some(1));
    let b = value(PACKED_MIN, Some(2));
    assert_eq!(a.compare(b), Ordering::Less, "TIME_MONOTONIC_COMPARE");
    assert_eq!(a.sub_nanoseconds(b), -1);
    let wall = value(PACKED_MIN, None);
    assert_eq!(a.compare(wall), Ordering::Greater);
    assert_eq!(a.sub_nanoseconds(wall), 10 * NS, "TIME_MIXED_USES_WALL");
    assert_eq!(value(i64::MAX, None).add_nanoseconds(NS).seconds, i64::MAX);
    assert_eq!(
        value(i64::MIN, None).add_nanoseconds(-NS).seconds,
        -i64::MAX,
        "TIME_WALL_NEGATIVE_CLAMP"
    );
    assert_eq!(
        value(PACKED_MAX, Some(1)).add_nanoseconds(NS).monotonic,
        None,
        "TIME_PACKED_WALL_STRIP"
    );
    assert!(value(0, None).is_zero());
}
