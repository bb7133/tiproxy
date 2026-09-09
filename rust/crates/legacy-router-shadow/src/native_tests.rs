// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    native::{self, Frame},
};
use control_routing::go_time::Origin;
use serde_json::{Value, json};

fn encode(value: &Value) -> Vec<u8> {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(error) => unreachable!("fixture: {error}"),
    };
    let mut frame = (u32::try_from(body.len()).unwrap_or(u32::MAX))
        .to_be_bytes()
        .to_vec();
    frame.extend(body);
    frame
}
fn origin() -> Origin {
    match Origin::new("go1.25.12", true, 10) {
        Some(origin) => origin,
        None => unreachable!("origin"),
    }
}
fn zero() -> Value {
    json!(["go", "0", 0, "1", false, "0"])
}
fn coverage() -> Value {
    json!({"version":3,"kind":"native_coverage","process":"1","owner":"2","nonce":"3","lifecycle_only":false,"factors":true,"selection":false,"scheduler":false,
        "origin":{"seconds":"63900000000","nanoseconds":0,"has_monotonic":true,"baseline_present":true,"baseline":"10","go_version":"go1.25.12"},"zero_time":zero(),"go_arch":"arm64"})
}
fn evaluation() -> Value {
    json!({"version":3,"kind":"evaluation","process":"1","owner":"2","nonce":"3","sequence":"3","group":"4","policy":"5","config":"6","resource":"0","evaluation":"1","entry":"config",
        "configuration":{"balance":"connection","routing":"idlest","label":"","self_label":"","rates":["0","0","0","0","0","0"],"count_ratio":"4608083138725491507"},
        "factors":[["status",1],["connection",16]],"accounts":[],"reads":[],"sorted":[],"advice":[],"returned":[],"from":-1,"to":-1,"balance_count":"0","reason":""})
}
fn query() -> Value {
    json!({"kind":"query","query":"cpu","time":zero(),"provenance":{"cluster":"7","generation":"1","source":2,"producer":"8","registration":"9","publication":"10","read_registration":"9"},"value_kind":"matrix","typed_nil":false,"empty":false,"series":[[true,"a:10080",false,"",[["-1","9221120237041090561"],["2","4607182418800017408"]]]]})
}
fn accepts(value: &Value) -> bool {
    native::decode(&encode(value), Some(origin())).is_ok()
}

#[test]
fn native_schema_is_strict_and_origin_bound() {
    assert!(
        matches!(
            native::decode(&encode(&coverage()), None),
            Ok(Frame::Coverage(_))
        ),
        "NATIVE_COVERAGE_ORIGIN"
    );
    for arch in ["amd64", "arm64"] {
        let mut value = coverage();
        value["go_arch"] = json!(arch);
        let Ok(Frame::Coverage(c)) = native::decode(&encode(&value), None) else {
            unreachable!("coverage")
        };
        assert_eq!(
            c.go_arch,
            if arch == "amd64" {
                control_router::shadow::native::GoArch::Amd64
            } else {
                control_router::shadow::native::GoArch::Arm64
            },
            "NATIVE_ARCH_LABEL"
        );
    }
    for arch in [json!("386"), json!(null)] {
        let mut value = coverage();
        value["go_arch"] = arch;
        assert!(
            native::decode(&encode(&value), None).is_err(),
            "NATIVE_ARCH_UNSUPPORTED"
        );
    }
    let value = evaluation();
    assert!(matches!(
        native::decode(&encode(&value), Some(origin())),
        Ok(Frame::Evaluation(_))
    ));
    assert!(
        native::decode(&encode(&value), None).is_err(),
        "NATIVE_REQUIRES_PRIOR_ORIGIN"
    );
    let mut unknown = value.clone();
    unknown["secret"] = json!("never accepted");
    assert!(!accepts(&unknown), "NATIVE_UNKNOWN_FIELD");
    let mut missing = value.clone();
    missing.as_object_mut().map(|value| value.remove("config"));
    assert!(!accepts(&missing), "NATIVE_MISSING_FIELD");
    for invalid in [
        json!("0"),
        json!("01"),
        json!("-0"),
        json!(1),
        json!("18446744073709551616"),
    ] {
        let mut bad = value.clone();
        bad["policy"] = invalid;
        assert!(!accepts(&bad), "NATIVE_CANONICAL_NONZERO_ID");
    }
    let mut duplicate = encode(&value);
    let mut body = duplicate.split_off(4);
    body.splice(1..1, br#""policy":"5","#.iter().copied());
    let mut frame = (u32::try_from(body.len()).unwrap_or(u32::MAX))
        .to_be_bytes()
        .to_vec();
    frame.extend(body);
    assert!(
        native::decode(&frame, Some(origin())).is_err(),
        "NATIVE_DUPLICATE_FIELD"
    );
    let mut old = value;
    old["version"] = json!(2);
    assert!(
        matches!(
            native::decode(&encode(&old), Some(origin())),
            Err(Error::Version)
        ),
        "NATIVE_DIALECT_SEPARATE"
    );
}

#[test]
fn native_query_preserves_labels_samples_and_empty_semantics() {
    let mut value = evaluation();
    value["reads"] = json!([query()]);
    let decoded = match native::decode(&encode(&value), Some(origin())) {
        Ok(Frame::Evaluation(value)) => value,
        other => unreachable!("decode: {other:?}"),
    };
    let control_router::shadow::native::Read::Query(query) = &decoded.reads[0] else {
        unreachable!("query")
    };
    assert_eq!(query.series[0].instance.as_deref(), Some("a:10080"));
    assert_eq!(query.series[0].cluster, None, "NATIVE_ABSENT_CLUSTER");
    assert_eq!(
        query.series[0].samples.len(),
        2,
        "NATIVE_FULL_SAMPLE_SERIES"
    );
    assert_eq!(
        query.series[0].samples[0].timestamp_ms, -1,
        "NATIVE_SIGNED_SAMPLE_DOMAIN"
    );
    assert_eq!(
        query.series[0].samples[0].value.to_bits(),
        9_221_120_237_041_090_561,
        "NATIVE_IEEE_NAN_BITS"
    );
    let mut empty = value.clone();
    empty["reads"][0]["empty"] = json!(true);
    assert!(!accepts(&empty), "NATIVE_EMPTY_RECOMPUTED");
    let mut absent = value.clone();
    absent["reads"][0]["series"][0][2] = json!(true);
    assert!(accepts(&absent), "NATIVE_PRESENT_EMPTY_CLUSTER");
    let mut invalid = value.clone();
    invalid["reads"][0]["typed_nil"] = json!(true);
    assert!(!accepts(&invalid), "NATIVE_TYPED_NIL_NO_SERIES");
    invalid = value.clone();
    invalid["reads"][0]["time"][0] = json!("sample");
    assert!(!accepts(&invalid), "NATIVE_CLOCK_DOMAIN_EXPLICIT");
    invalid = value.clone();
    invalid["reads"][0]["provenance"]["producer"] = json!("0");
    assert!(!accepts(&invalid), "NATIVE_PRODUCER_ID_REQUIRED");
    invalid = value;
    invalid["reads"][0]["query"] = json!("other");
    assert!(!accepts(&invalid), "NATIVE_QUERY_ALLOWLIST");
}

#[test]
fn native_read_clock_sample_and_string_bounds() {
    let mut empty = query();
    empty["value_kind"] = json!("nil");
    empty["empty"] = json!(true);
    empty["series"] = json!([]);
    let mut value = evaluation();
    value["reads"] = json!(vec![empty.clone(); 128]);
    assert!(accepts(&value), "NATIVE_READ_EQUAL");
    value["reads"] = json!(vec![empty; 129]);
    assert!(!accepts(&value), "NATIVE_READ_PLUS_ONE");
    let clock = json!({"kind":"clock","site":"cpu_expiry","ordinal":0,"time":zero()});
    value["reads"] = json!(vec![clock.clone(); 64]);
    assert!(accepts(&value), "NATIVE_CLOCK_EQUAL");
    value["reads"] = json!(vec![clock; 65]);
    assert!(!accepts(&value), "NATIVE_CLOCK_PLUS_ONE");
    let sample = json!(["1", "0"]);
    let mut first = query();
    first["series"][0][4] = json!(vec![sample.clone(); 2048]);
    let mut second = first.clone();
    second["query"] = json!("memory");
    value["reads"] = json!([first.clone(), second.clone()]);
    assert!(accepts(&value), "NATIVE_SAMPLE_TOTAL_EQUAL");
    second["series"][0][4] = json!(vec![sample; 2049]);
    value["reads"] = json!([first, second]);
    assert!(!accepts(&value), "NATIVE_SAMPLE_TOTAL_PLUS_ONE");
    value = evaluation();
    value["configuration"]["label"] = json!("x".repeat(512));
    assert!(accepts(&value), "NATIVE_TEXT_EQUAL");
    value["configuration"]["label"] = json!("x".repeat(513));
    assert!(!accepts(&value), "NATIVE_TEXT_PLUS_ONE");
    let mut read = query();
    read["series"] = json!([[true, "x".repeat(512), false, "", []]]);
    let mut reads = vec![read; 128];
    reads[0]["series"][0][1] = json!("x".repeat(496));
    value = evaluation();
    value["reads"] = json!(reads);
    assert!(accepts(&value), "NATIVE_TEXT_TOTAL_EQUAL");
    value["reads"][0]["series"][0][1] = json!("x".repeat(497));
    assert!(!accepts(&value), "NATIVE_TEXT_TOTAL_PLUS_ONE");
}

#[test]
fn native_body_limit_is_independent_of_legacy_ceiling() {
    let mut frame = encode(&evaluation());
    frame.resize(native::MAX_BODY + 4, b' ');
    frame[..4]
        .copy_from_slice(&(u32::try_from(native::MAX_BODY).unwrap_or(u32::MAX)).to_be_bytes());
    assert!(
        native::decode(&frame, Some(origin())).is_ok(),
        "NATIVE_BODY_EQUAL"
    );
    frame.push(b' ');
    frame[..4]
        .copy_from_slice(&(u32::try_from(native::MAX_BODY + 1).unwrap_or(u32::MAX)).to_be_bytes());
    assert!(
        matches!(
            native::decode(&frame, Some(origin())),
            Err(Error::Oversized)
        ),
        "NATIVE_BODY_PLUS_ONE"
    );
}

#[test]
fn actual_go_factor_capture_computes_independently() {
    let Ok(path) = std::env::var("CP_ROUTE_NATIVE_ORACLE") else {
        return;
    };
    let bytes = std::fs::read(path).unwrap_or_else(|error| unreachable!("oracle: {error}"));
    // Finish the unmodified corpus first: history/read faults must retain their
    // original NATIVE_ACTUAL_FACTOR evidence before forged output probes run.
    // The second pass starts with fresh state and independently exercises each
    // forged witness class without retaining hundreds of cloned histories.
    for verify_forged in [false, true] {
        let mut rest = bytes.as_slice();
        let mut origin = None;
        let mut state = None;
        let mut evaluations = 0;
        let mut last_resource = 0;
        let mut forged_proofs = [0_usize; 3];
        while !rest.is_empty() {
            let prefix: [u8; 4] = rest[..4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("prefix"));
            let end = u32::from_be_bytes(prefix) as usize + 4;
            let frame = native::decode(&rest[..end], origin)
                .unwrap_or_else(|error| unreachable!("NATIVE_ACTUAL_FRAME: {error:?}"));
            match frame {
                Frame::Coverage(c) => {
                    assert!(state.is_none());
                    origin = Some(c.origin);
                    state = Some(control_router::shadow::native::FactorState::new(c));
                }
                Frame::Evaluation(e) => {
                    let state = state.as_mut().unwrap_or_else(|| unreachable!("coverage"));
                    if e.entry == control_router::shadow::native::Entry::Config
                        && e.resource > last_resource
                        && last_resource != 0
                    {
                        let mut reused = e.as_ref().clone();
                        reused.resource = last_resource;
                        assert!(
                            state.clone().apply(&reused).is_err(),
                            "NATIVE_RESOURCE_TOKEN_REUSE"
                        );
                    }
                    last_resource = last_resource.max(e.resource);
                    if verify_forged {
                        for (count, exercised) in forged_proofs
                            .iter_mut()
                            .zip(forged_output_proofs(state, &e))
                        {
                            *count += usize::from(exercised);
                        }
                    }
                    assert_eq!(
                        state.apply(&e),
                        Ok(()),
                        "NATIVE_ACTUAL_FACTOR: evaluation {} {:?}",
                        e.evaluation,
                        e.entry
                    );
                    evaluations += 1;
                }
            }
            rest = &rest[end..];
        }
        assert!(evaluations >= 400, "NATIVE_ACTUAL_FULL_CORPUS");
        if verify_forged {
            assert!(
                forged_proofs.iter().all(|count| *count > 0),
                "NATIVE_FORGED_PROOFS_EXERCISED"
            );
        }
    }
}

fn forged_output_proofs(
    state: &control_router::shadow::native::FactorState,
    e: &control_router::shadow::native::Evaluation,
) -> [bool; 3] {
    let mut exercised = [false; 3];
    if e.sorted.is_empty() {
        return exercised;
    }
    let mut wrong_score = e.clone();
    wrong_score.accounts[0].packed ^= 1;
    assert!(
        state.clone().apply(&wrong_score).is_err(),
        "NATIVE_OUTPUT_COMPUTED"
    );
    exercised[0] = true;
    if e.entry != control_router::shadow::native::Entry::Routeable
        || e.sorted.len() < 2
        || e.returned != e.sorted
    {
        return exercised;
    }
    // Forge the returned order too: only the independently established score
    // ordering can reject this otherwise self-consistent permutation.
    if let Some(other) = (1..e.sorted.len()).find(|&i| {
        e.accounts[usize::from(e.sorted[i])].packed != e.accounts[usize::from(e.sorted[0])].packed
    }) {
        let mut unequal = e.clone();
        unequal.sorted.swap(0, other);
        unequal.returned.swap(0, other);
        assert!(
            state.clone().apply(&unequal).is_err(),
            "NATIVE_SORT_UNEQUAL"
        );
        exercised[1] = true;
    }
    // Repeat an index and adjust the output/getter witness consistently, so a
    // later output comparison cannot substitute for the permutation check.
    let mut duplicate = e.clone();
    let omitted = usize::from(duplicate.sorted[1]);
    duplicate.sorted[1] = duplicate.sorted[0];
    duplicate.returned[1] = duplicate.returned[0];
    duplicate.accounts[omitted].routeability_seen = false;
    duplicate.accounts[omitted].routeable = false;
    assert!(
        state.clone().apply(&duplicate).is_err(),
        "NATIVE_SORT_DUPLICATE"
    );
    exercised[2] = true;
    exercised
}
