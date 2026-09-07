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

//! Differential observations and capacity/cancellation-independent core rows.

use super::*;

#[test]
fn history_keeps_source_selection_separate_from_backend_result_updates() {
    let query = |value| QueryResult {
        kind: ValueKind::Vector,
        series: vec![Series {
            labels: BTreeMap::default(),
            samples: vec![Sample {
                timestamp_ms: 1,
                value,
            }],
        }],
        updated_nanos: 1,
    };
    let mut reader = ReaderState::default();
    reader.complete_backend(BTreeMap::from([(QueryId::FailurePd, query(1.0))]), true);
    reader.complete_backend(BTreeMap::from([(QueryId::FailurePd, query(2.0))]), false);
    assert_eq!(
        reader
            .get(QueryId::FailurePd)
            .map(|result| result.series[0].samples[0].value),
        Some(2.0)
    );
    reader.complete_prom(BTreeMap::new());
    reader.complete_backend(BTreeMap::from([(QueryId::FailurePd, query(3.0))]), false);
    assert_eq!(reader.source(), Source::Prometheus);
    assert!(reader.get(QueryId::FailurePd).is_none());
}

fn query_value(query: &QueryResult) -> serde_json::Value {
    use serde_json::json;
    let data: Vec<_> = query
        .series
        .iter()
        .map(|series| match query.kind {
            ValueKind::Vector => json!({"metric":series.labels,"value":series.samples[0]}),
            ValueKind::Matrix => json!({"metric":series.labels,"values":if series.samples.is_empty() { None } else { Some(&series.samples) }}),
        })
        .collect();
    json!({"kind":match query.kind {ValueKind::Vector=>"vector",ValueKind::Matrix=>"matrix"},"data":data,"updated_nanos":query.updated_nanos})
}

fn same_json(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| same_json(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, left)| right.get(key).is_some_and(|right| same_json(left, right)))
        }
        _ => left == right,
    }
}

// Keep each observed operation beside its actual production call; exact float
// equality intentionally detects semantic drift in these shared inputs.
#[allow(clippy::too_many_lines, clippy::float_cmp)]
#[test]
fn actual_go_core_observations() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::{Value, json};
    let Ok(rules_path) = std::env::var("CPMETRICS_RULE_OUTPUT") else {
        return Ok(());
    };
    let history_path = std::env::var("CPMETRICS_HISTORY_OUTPUT")?;
    let mut rows = 0;
    for path in [
        rules_path,
        history_path,
        std::env::var("CPMETRICS_SOURCE_OUTPUT")?,
        std::env::var("CPMETRICS_MERGE_OUTPUT")?,
        std::env::var("CPMETRICS_PROM_OUTPUT")?,
        std::env::var("CPMETRICS_BACKEND_OUTPUT")?,
    ] {
        for line in std::fs::read_to_string(path)?.lines() {
            let row: Value = serde_json::from_str(line)?;
            let input = &row["input"];
            let expected = &row["expected"];
            let text = |key: &str| -> Result<&str, Box<dyn std::error::Error>> {
                input[key]
                    .as_str()
                    .ok_or_else(|| format!("missing input {key}").into())
            };
            let rule = || -> Result<QueryId, Box<dyn std::error::Error>> {
                QueryId::from_key(text("key")?).ok_or_else(|| "unknown fixed rule".into())
            };
            let pairs = |value: &Value| -> Result<Vec<Sample>, Box<dyn std::error::Error>> {
                Ok(serde_json::from_str(&value.to_string())?)
            };
            let actual = match row["op"].as_str().ok_or("missing operation")? {
                "source" => {
                    let mut reader = ReaderState::default();
                    let mut observed = Vec::new();
                    for action in input.as_array().ok_or("source actions")? {
                        let results = if let Some(value) = action["value"].as_f64() {
                            BTreeMap::from([(
                                QueryId::Memory,
                                QueryResult {
                                    kind: ValueKind::Vector,
                                    series: vec![Series {
                                        labels: BTreeMap::new(),
                                        samples: vec![Sample {
                                            timestamp_ms: 1,
                                            value,
                                        }],
                                    }],
                                    updated_nanos: 1,
                                },
                            )])
                        } else {
                            BTreeMap::new()
                        };
                        if action["kind"] == "prom" {
                            reader.complete_prom(results);
                        } else {
                            reader.complete_backend(
                                results,
                                action["success"].as_bool().ok_or("source success")?,
                            );
                        }
                        observed.push(json!({"source":match reader.source(){Source::None=>"none",Source::Prometheus=>"prometheus",Source::Backend=>"backend"},"value":reader.get(QueryId::Memory).and_then(|query| query.series.first()).and_then(|series|series.samples.first()).map(|pair|pair.value)}));
                    }
                    json!(observed)
                }
                "merge_results" => {
                    let queries: Result<Vec<_>, Box<dyn std::error::Error>> = input
                        .as_array()
                        .ok_or("cluster query inputs")?
                        .iter()
                        .map(|input| {
                            Ok(decode_prometheus(
                                input["body"].as_str().ok_or("query body")?.as_bytes(),
                                input["cluster"].as_str().ok_or("cluster")?,
                                input["updated_nanos"].as_i64().ok_or("update")?,
                            )?)
                        })
                        .collect();
                    query_value(&QueryResult::merge(queries?)?.ok_or("missing merged query")?)
                }
                "backend_decode" => {
                    match decode_backend(input.as_str().ok_or("backend body")?.as_bytes()) {
                        Err(_) => json!({"error":true}),
                        Ok(metrics) => {
                            let result: BTreeMap<_, Vec<Value>> = metrics
                                .into_iter()
                                .map(|(name, points)| {
                                    (
                                        name,
                                        points
                                            .into_iter()
                                            .map(|point| {
                                                let value = if point.value.is_nan() {
                                                    "NaN".into()
                                                } else if point.value == f64::INFINITY {
                                                    "+Inf".into()
                                                } else if point.value == f64::NEG_INFINITY {
                                                    "-Inf".into()
                                                } else {
                                                    point.value.to_string()
                                                };
                                                json!({"labels":point.labels,"value":value})
                                            })
                                            .collect(),
                                    )
                                })
                                .collect();
                            json!(result)
                        }
                    }
                }
                "catalog" => {
                    let spec = QueryId::from_key(input.as_str().ok_or("catalog key")?)
                        .ok_or("unknown query")?
                        .spec();
                    let queries = spec.expressions();
                    json!({"queries":queries,"window":spec.window(100_000)?,"range_ms":spec.range_ms,"retention_ms":spec.retention_ms,"kind":match spec.kind {ValueKind::Vector=>"vector",ValueKind::Matrix=>"matrix"},"names":spec.names})
                }
                "metric" | "range" => {
                    let value = if row["op"] == "metric" {
                        rule()?.metric_value(&decode_backend(text("text")?.as_bytes())?)
                    } else {
                        rule()?.range_value(&pairs(&input["pairs"])?)
                    };
                    let expected_value =
                        expected.as_str().ok_or("expected scalar")?.parse::<f64>()?;
                    assert!(
                        (value.is_nan() && expected_value.is_nan()) || value == expected_value,
                        "{}: {value} != {expected_value}",
                        row["name"]
                    );
                    rows += 1;
                    continue;
                }
                "owner_decode" => {
                    match decode_owner_history(input.as_str().ok_or("owner body")?.as_bytes()) {
                        Ok(history) => json!({"history":history.entries()}),
                        Err(_) => json!({"error":true}),
                    }
                }
                "merge" => {
                    let mut history = decode_owner_history(text("local")?.as_bytes())?;
                    history.merge(decode_owner_history(text("incoming")?.as_bytes())?)?;
                    json!(history.entries())
                }
                "purge" => {
                    let mut history = History::from_entries(BTreeMap::from([(
                        "memory".into(),
                        BTreeMap::from([(
                            "a".into(),
                            BackendHistory {
                                step1: pairs(&input["pairs"])?,
                                step2: vec![],
                            },
                        )]),
                    )]))?;
                    history.purge(
                        &[QueryId::Memory],
                        input["now_ms"].as_i64().ok_or("purge time")?,
                    );
                    json!(
                        history
                            .entries()
                            .get("memory")
                            .and_then(|entries| entries.get("a"))
                            .map_or(&[][..], |history| history.step1.as_slice())
                    )
                }
                "missing" => {
                    let addresses: Vec<String> =
                        serde_json::from_value(input["addresses"].clone())?;
                    json!(
                        decode_owner_history(text("history")?.as_bytes())?
                            .missing(&[QueryId::Cpu, QueryId::Memory], &addresses)
                    )
                }
                "label" => json!(instance_label(
                    text("address")?,
                    text("ip")?,
                    input["port"].as_u64().ok_or("port")?
                )),
                "prom_decode" => match decode_prometheus(
                    text("body")?.as_bytes(),
                    text("cluster")?,
                    input["updated_nanos"].as_i64().ok_or("update time")?,
                ) {
                    Ok(result) => query_value(&result),
                    Err(_) => json!({"error":true}),
                },
                "lookup" => {
                    let body = text("body")?;
                    let wire_series: Vec<Value> = serde_json::from_str(body)?;
                    let mut query=decode_prometheus(format!("{{\"status\":\"success\",\"data\":{{\"resultType\":\"matrix\",\"result\":{body}}}}}").as_bytes(),"",0)?;
                    // Deliberately exercise the public consumer lookup with its
                    // original absent/foreign label, independent of producers.
                    for (series, wire) in query.series.iter_mut().zip(wire_series) {
                        series.labels = serde_json::from_value(wire["metric"].clone())?;
                    }
                    match query.samples_for(text("instance")?, text("cluster")?) {
                        Some(samples) => json!(samples),
                        None => Value::Null,
                    }
                }
                "owner_filter" => {
                    let selected: Vec<String> = serde_json::from_value(input["selected"].clone())?;
                    serde_json::from_slice(
                        &decode_owner_history(text("history")?.as_bytes())?
                            .owner_json(&selected)?,
                    )?
                }
                other => return Err(format!("unknown observation {other}").into()),
            };
            assert!(
                same_json(&actual, expected),
                "{}: actual={actual}, expected={expected}",
                row["name"]
            );
            rows += 1;
        }
    }
    assert!(rows >= 120, "missing mandatory Go observations: {rows}");
    println!("CP-METRICS actual-Go observations passed: {rows}");
    Ok(())
}

#[test]
fn history_observation_is_atomic_on_capacity_failure() -> Result<(), Box<dyn std::error::Error>> {
    let pair = Sample {
        timestamp_ms: 0,
        value: 1.0,
    };
    let mut history = History::from_entries(BTreeMap::from([(
        "memory".into(),
        BTreeMap::from([(
            "a".into(),
            BackendHistory {
                step1: vec![pair; MAX_SAMPLES],
                step2: vec![],
            },
        )]),
    )]))?;
    let metrics =
        decode_backend(b"process_resident_memory_bytes 2\ntidb_server_memory_quota_bytes 4\n")?;
    assert_eq!(
        history.observe(&[QueryId::Memory], "a", &metrics, 1),
        Err(MetricError::Limit)
    );
    assert_eq!(history.entries()["memory"]["a"].step1.len(), MAX_SAMPLES);
    assert!(history.entries()["memory"]["a"].step2.is_empty());
    history.purge(&[QueryId::Memory], 60_000);
    history.observe(&[QueryId::Memory], "a", &metrics, 60_001)?;
    assert_eq!(history.entries()["memory"]["a"].step1.len(), 1);
    assert_eq!(history.entries()["memory"]["a"].step2.len(), 1);
    // Empty foreign rules count toward the same key cap as wire decoding.
    let mut history = History::from_entries(
        (0..MAX_SERIES)
            .map(|index| (format!("foreign-{index}"), BTreeMap::new()))
            .collect(),
    )?;
    assert_eq!(
        history.observe(&[QueryId::Memory], "a", &metrics, 1),
        Err(MetricError::Limit)
    );
    assert_eq!(history.entries().len(), MAX_SERIES);
    assert!(!history.entries().contains_key("memory"));
    history.purge(&[QueryId::Memory], 60_000);
    history.observe(&[QueryId::Memory], "a", &metrics, 60_001)?;
    assert_eq!(history.entries().len(), 1);
    Ok(())
}

#[test]
fn history_raw_sample_survives_missing_range_until_a_valid_cpu_interval()
-> Result<(), Box<dyn std::error::Error>> {
    let mut history = History::default();
    let first = decode_backend(b"process_cpu_seconds_total 2\ntidb_server_maxprocs 2\n")?;
    let next = decode_backend(b"process_cpu_seconds_total 6\ntidb_server_maxprocs 2\n")?;
    history.observe(&[QueryId::Cpu], "a", &first, 1000)?;
    history.observe(&[QueryId::Cpu], "a", &next, 1999)?;
    assert_eq!(history.entries()["cpu"]["a"].step1.len(), 2);
    assert!(history.entries()["cpu"]["a"].step2.is_empty());
    history.observe(&[QueryId::Cpu], "a", &next, 2000)?;
    assert_eq!(
        history.entries()["cpu"]["a"].step2,
        vec![Sample {
            timestamp_ms: 2000,
            value: 2.0
        }]
    );
    let result = history.results(&[QueryId::Cpu], "cluster", 2_000_000_001);
    assert_eq!(result[&QueryId::Cpu].updated_nanos, 2_000_000_001);
    assert_eq!(
        result[&QueryId::Cpu].series[0].samples[0].timestamp_ms,
        2000
    );
    let missing = decode_backend(b"process_cpu_seconds_total 8\n")?;
    history.observe(&[QueryId::Cpu], "a", &missing, 3000)?;
    assert_eq!(history.entries()["cpu"]["a"].step1.len(), 3);
    Ok(())
}

#[test]
fn parser_limits_cover_unknown_fields_and_selected_exposition_labels() {
    assert_eq!(
        decode_owner_history(&vec![b' '; MAX_BYTES + 1]),
        Err(MetricError::Limit)
    );
    let nested = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    assert_eq!(
        decode_owner_history(nested.as_bytes()),
        Err(MetricError::Limit)
    );
    let unknown = format!("{{\"unknown\":\"{}\"}}", "x".repeat(MAX_TOKEN * 6 + 1));
    assert_eq!(
        decode_owner_history(unknown.as_bytes()),
        Err(MetricError::Limit)
    );
    let labels = (0..=MAX_LABELS)
        .map(|index| format!("l{index}=\"x\""))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        decode_backend(format!("process_cpu_seconds_total{{{labels}}} 1\n").as_bytes()),
        Err(MetricError::Limit)
    );
    let label = format!(
        "process_cpu_seconds_total{{label=\"{}\"}} 1\n",
        "x".repeat(MAX_TOKEN + 1)
    );
    assert_eq!(decode_backend(label.as_bytes()), Err(MetricError::Limit));
}

#[test]
fn owner_output_stops_before_exceeding_wire_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let pair = Sample {
        timestamp_ms: 1,
        value: f64::MAX,
    };
    let history = History::from_entries(BTreeMap::from([(
        "memory".into(),
        BTreeMap::from([(
            "a".into(),
            BackendHistory {
                step1: vec![pair; 60_000],
                step2: vec![],
            },
        )]),
    )]))?;
    assert_eq!(history.owner_json(&["a".into()]), Err(MetricError::Limit));
    assert_eq!(history.owner_json(&[])?, b"{}");
    Ok(())
}
