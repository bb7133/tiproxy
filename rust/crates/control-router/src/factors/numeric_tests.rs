// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn native_numeric_architecture_is_capture_metadata() {
    let upper = 9_223_372_036_854_775_808.0;
    for (value, arm, amd) in [
        (f64::NAN, 0, i64::MIN),
        (f64::INFINITY, i64::MAX, i64::MIN),
        (f64::NEG_INFINITY, i64::MIN, i64::MIN),
        (upper, i64::MAX, i64::MIN),
        (-upper, i64::MIN, i64::MIN),
        (
            f64::from_bits(upper.to_bits() - 1),
            i64::MAX - 1023,
            i64::MAX - 1023,
        ),
        (f64::from_bits(upper.to_bits() + 1), i64::MAX, i64::MIN),
        (1.999, 1, 1),
        (-1.999, -1, -1),
    ] {
        assert_eq!(
            GoArch::Arm64.duration(value),
            arm,
            "NATIVE_ARM64_CONVERSION"
        );
        assert_eq!(
            GoArch::Amd64.duration(value),
            amd,
            "NATIVE_AMD64_CONVERSION"
        );
    }
    // A long observed sample delta makes the first horizon exceed int64, and
    // the second conversion also overflows on ARM64. This changes the risk.
    let samples = [
        Sample {
            timestamp_ms: 0,
            value: 0.4998,
        },
        Sample {
            timestamp_ms: 8_000_000_000_000,
            value: 0.5,
        },
    ];
    assert_eq!(
        memory_usage::<i64>(&samples, GoArch::Arm64).1,
        i64::MAX,
        "NATIVE_MEMORY_ARCHITECTURE"
    );
    assert_eq!(
        memory_usage::<i64>(&samples, GoArch::Amd64).1,
        i64::MIN,
        "NATIVE_MEMORY_ARCHITECTURE"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn native_numeric_actual_go_oracle() {
    let Ok(path) = std::env::var("CP_ROUTE_NATIVE_NUMERIC") else {
        return;
    };
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| unreachable!("oracle: {e}"));
    let rows: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| unreachable!("oracle: {e}"));
    let arch = match rows["arch"].as_str() {
        Some("arm64") => GoArch::Arm64,
        Some("amd64") => GoArch::Amd64,
        _ => unreachable!("captured architecture"),
    };
    let rows = rows["rows"]
        .as_array()
        .unwrap_or_else(|| unreachable!("rows"));
    assert!(rows.len() >= 60);
    for row in rows {
        let bits = row["bits"].as_u64().unwrap_or_else(|| unreachable!("bits"));
        let expected = row["integer"]
            .as_i64()
            .unwrap_or_else(|| unreachable!("integer"));
        let actual = arch.duration(f64::from_bits(bits));
        assert_eq!(actual, expected, "NATIVE_GO_NUMERIC_ORACLE {row}");
        if let Some(health) = row["health_bits"].as_u64() {
            assert_eq!(
                (actual as f64).to_bits(),
                health,
                "NATIVE_GO_HEALTH_PRODUCER_ORACLE"
            );
        }
    }
}
