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

//! Actual Go factor observations drive the same Rust state used by the router.

use super::*;
use crate::ledger::Ledger;
use control_config::{EffectiveConfig, RoutingFactorConfig};
use control_topology::metrics::{Sample, Series, ValueKind};
use serde_json::Value;

fn must<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}
fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}
fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
fn integer(value: &Value) -> i64 {
    must(value.as_i64().ok_or("integer"))
}
fn float(value: &Value) -> f64 {
    must(value.as_f64().ok_or("float"))
}
fn natural(value: &Value) -> u64 {
    must(value.as_u64().ok_or("natural"))
}
fn query_id(name: &str) -> QueryId {
    match name {
        "cpu" => QueryId::Cpu,
        "memory" => QueryId::Memory,
        "failure_pd" => QueryId::FailurePd,
        "total_pd" => QueryId::TotalPd,
        "failure_tikv" => QueryId::FailureTikv,
        "total_tikv" => QueryId::TotalTikv,
        _ => unreachable!("query name"),
    }
}
fn queries(step: &Value) -> Queries {
    must(step["queries"].as_object().ok_or("queries"))
        .iter()
        .map(|(name, query)| {
            let result = QueryResult {
                updated_nanos: Some(integer(&query["time"])),
                kind: if query["matrix"] == true {
                    ValueKind::Matrix
                } else {
                    ValueKind::Vector
                },
                series: array(&query["series"])
                    .iter()
                    .map(|series| Series {
                        labels: BTreeMap::from([
                            ("instance".into(), text(&series["instance"]).into()),
                            (
                                "tiproxy_cluster".into(),
                                control_topology::metrics::cluster_label(text(&series["cluster"])),
                            ),
                        ]),
                        samples: array(&series["samples"])
                            .iter()
                            .map(|sample| Sample {
                                timestamp_ms: integer(&sample["time"]),
                                value: must(text(&sample["value"]).parse()),
                            })
                            .collect(),
                    })
                    .collect(),
            };
            (query_id(name), result)
        })
        .collect()
}
fn policy(step: &Value) -> RoutingConfig {
    let mut policy = must(EffectiveConfig::default().routing());
    policy.balance_policy = match text(&step["policy"]) {
        "connection" => RoutingBalancePolicy::Connection,
        "location" => RoutingBalancePolicy::Location,
        "resource" => RoutingBalancePolicy::Resource,
        _ => unreachable!("policy"),
    };
    policy.label_name = text(&step["label"]).into();
    let rate = |index| RoutingFactorConfig {
        migrations_per_second: float(&step["rates"][index]),
    };
    policy.status = rate(0);
    policy.health = rate(1);
    policy.memory = rate(2);
    policy.cpu = rate(3);
    policy.location = rate(4);
    policy.connection.migrations_per_second = float(&step["rates"][5]);
    policy.connection.count_ratio_threshold = float(&step["ratio"]);
    policy
}
#[allow(clippy::float_cmp)] // Exact infinity as in the existing factor oracle.
fn compare_balance(report: &FactorReport, expected: &Value, context: &str) {
    let pair = &expected["balance"];
    if pair.is_null() {
        assert!(
            report.balance.is_none(),
            "FACTOR_BALANCE_NONE {context}: {:?}",
            report.balance
        );
    } else {
        let actual = report
            .balance
            .as_ref()
            .unwrap_or_else(|| unreachable!("FACTOR_BALANCE_MISSING {context}"));
        assert_eq!(
            actual.from.as_ref(),
            text(&pair["from"]),
            "FACTOR_BALANCE_SOURCE {context}"
        );
        assert_eq!(
            actual.to.as_ref(),
            text(&pair["to"]),
            "FACTOR_BALANCE_TARGET {context}"
        );
        let rate: f64 = must(text(&pair["rate"]).parse());
        assert!(
            (actual.rate - rate).abs() <= rate.abs() * 1e-10 || actual.rate == rate,
            "FACTOR_BALANCE_RATE {context}"
        );
        let reason = match actual.reason {
            Factor::Label => "label",
            Factor::Status => "status",
            Factor::Health => "health",
            Factor::Memory => "memory",
            Factor::Cpu => "cpu",
            Factor::Location => "location",
            Factor::Connection => "conn",
        };
        assert_eq!(
            reason,
            text(&pair["reason"]),
            "FACTOR_BALANCE_REASON {context}"
        );
    }
}

#[allow(clippy::float_cmp)] // Also compare the actual Go infinity result.
fn compare(report: &FactorReport, step: &Value, context: &str) {
    let expected = &step["expected"];
    assert_eq!(
        report.rows.len(),
        array(&expected["scores"]).len(),
        "{context}"
    );
    for (row, expected) in report.rows.iter().zip(array(&expected["scores"])) {
        assert_eq!(
            row.backend_id.as_ref(),
            text(&expected["id"]),
            "FACTOR_ORDER {context}"
        );
        assert_eq!(
            row.score,
            natural(&expected["score"]),
            "FACTOR_SCORE {context} {}",
            row.backend_id
        );
        assert_eq!(
            row.routeable,
            expected["routeable"] == true,
            "FACTOR_ROUTEABLE {context}"
        );
        let parts: Vec<_> = row.parts.iter().map(|(_, score)| *score).collect();
        assert_eq!(
            parts,
            array(&expected["parts"])
                .iter()
                .map(natural)
                .collect::<Vec<_>>(),
            "FACTOR_PARTS {context}"
        );
        for (actual, expected) in row.advice_to_best.iter().zip(array(&expected["advice"])) {
            let kind = match actual.advice {
                BalanceAdvice::Negative => 1,
                BalanceAdvice::Neutral => 0,
                BalanceAdvice::Positive => 2,
            };
            assert_eq!(
                kind,
                integer(&expected["kind"]),
                "FACTOR_ADVICE {context} {} {:?}",
                row.backend_id,
                actual.factor
            );
            let count: f64 = must(text(&expected["count"]).parse());
            assert!(
                actual.count == count
                    || (actual.count - count).abs() <= 1e-10 * count.abs().max(1.0),
                "FACTOR_COUNT {context} {:?}: {} != {count}",
                actual.factor,
                actual.count
            );
        }
    }
    for (key, policy) in [
        ("random", RoutingSelectionPolicy::Random),
        ("prefer", RoutingSelectionPolicy::PreferIdle),
    ] {
        let mut weights: BTreeMap<String, u64> = array(&step["backends"])
            .iter()
            .map(|backend| (text(&backend["id"]).into(), 0))
            .collect();
        for ticket in 0..63 {
            if let Some(id) = report.choice(policy, ticket) {
                *must(weights.get_mut(id).ok_or("choice")) += 1;
            }
        }
        for (id, value) in must(expected[key].as_object().ok_or("weights")) {
            assert_eq!(
                weights[id],
                natural(value),
                "FACTOR_WEIGHTS {context} {key} {id}"
            );
        }
    }
    // Preserve the original factor mutation's first-divergence labels before
    // comparing the derived migration pair.
    compare_balance(report, expected, context);
}

#[test]
fn shared_go_factor_observations() {
    let Ok(path) = std::env::var("CPMETRICS_FACTOR_OUTPUT") else {
        return;
    };
    let cases: Value = must(serde_json::from_slice(&must(std::fs::read(path))));
    let inventory = if std::env::var("CPROUTE_BALANCE_CASES").as_deref() == Ok("1") {
        104
    } else {
        95
    };
    assert!(
        array(&cases).len() == inventory,
        "mandatory Go factor scenario inventory"
    );
    let selected = std::env::var("CPMETRICS_FACTOR_CASE").ok();
    let mut observed = 0;
    for case in array(&cases) {
        if selected
            .as_ref()
            .is_some_and(|name| name != text(&case["name"]))
        {
            continue;
        }
        observed += 1;
        let mut state = State::default();
        let mut ledger = Ledger::new(1);
        let mut owners = BTreeMap::new();
        for (index, step) in array(&case["steps"]).iter().enumerate() {
            let inputs: Vec<_> = array(&step["backends"])
                .iter()
                .map(|backend| {
                    let id: Arc<str> = text(&backend["id"]).into();
                    let owner = owners
                        .entry(Arc::clone(&id))
                        .or_insert_with(|| must(ledger.add_account()));
                    Input {
                        address: String::new(),
                        instance: format!("{id}:10080"),
                        id,
                        owner: Arc::clone(owner),
                        cluster: text(&backend["cluster"]).into(),
                        counts: Accounting::for_balance_test(
                            natural(&backend["active"]),
                            natural(&backend["pending"]),
                            backend["incoming"].as_u64().unwrap_or(0),
                            backend["outgoing"].as_u64().unwrap_or(0),
                        ),
                        healthy: backend["healthy"] == true,
                        local: backend["local"] == true,
                        label_matches: text(&step["label"]).is_empty() || backend["label"] == true,
                    }
                })
                .collect();
            let report = state.evaluate(
                &inputs,
                &policy(step),
                &queries(step),
                integer(&step["now"]),
            );
            compare(
                &report,
                step,
                &format!("{} step {index}", text(&case["name"])),
            );
        }
    }
    assert_eq!(
        observed,
        if selected.is_some() { 1 } else { inventory },
        "Go factor scenario selection"
    );
    println!("CP-METRIC-FACTORS actual Go observations passed: {observed}");
}

#[test]
fn retained_cache_requires_exact_ledger_owner() {
    let mut ledger = Ledger::new(1);
    let mut inputs: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|id| Input {
            address: String::new(),
            id: Arc::from(id),
            owner: must(ledger.add_account()),
            instance: format!("{id}:10080"),
            cluster: "default".into(),
            counts: Accounting::for_factor_test(10, 2),
            healthy: true,
            local: true,
            label_matches: true,
        })
        .collect();
    let now = 1_000_000_000_000;
    let query = QueryResult {
        kind: ValueKind::Matrix,
        updated_nanos: Some(now),
        series: inputs
            .iter()
            .map(|input| Series {
                labels: BTreeMap::from([("instance".into(), input.instance.clone())]),
                samples: vec![Sample {
                    timestamp_ms: now / 1_000_000,
                    value: 0.2,
                }],
            })
            .collect(),
    };
    let mut queries = BTreeMap::from([(QueryId::Cpu, query)]);
    let policy = must(EffectiveConfig::default().routing());
    let mut state = State::default();
    let _ = state.evaluate(&inputs, &policy, &queries, now);
    assert!(state.history.cache["a"].cpu.is_some());
    let previous_owner = Arc::clone(&inputs[0].owner);
    inputs[0].owner = must(ledger.add_account());
    let owners = inputs
        .iter()
        .map(|input| (Arc::clone(&input.id), Arc::clone(&input.owner)))
        .collect();
    state.retain_owners(&owners);
    assert!(
        !state.history.cache.contains_key("a"),
        "FACTOR_ACCOUNT_ABA_NO_REUSE"
    );
    let cpu = must(queries.get_mut(&QueryId::Cpu).ok_or("cpu"));
    cpu.series.remove(0);
    let result = state.evaluate(&inputs, &policy, &queries, now);
    let row = must(
        result
            .rows
            .iter()
            .find(|row| row.backend_id.as_ref() == "a")
            .ok_or("a"),
    );
    assert_eq!(
        row.parts.iter().find(|(factor, _)| *factor == Factor::Cpu),
        Some(&(Factor::Cpu, 20)),
        "FACTOR_NEW_ACCOUNT_MISSING_CPU"
    );
    assert!(!Arc::ptr_eq(&state.owners["a"].identity, &previous_owner));
    state.clear_cluster("default");
    assert!(
        state
            .history
            .cache
            .values()
            .all(|cache| cache.cpu.is_none()),
        "FACTOR_COLD_START_CLEARS_CACHE"
    );
}

#[test]
fn other_cluster_lineage_preserves_cached_health_indicator() {
    let mut ledger = Ledger::new(1);
    let inputs: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|id| Input {
            address: String::new(),
            id: Arc::from(id),
            owner: must(ledger.add_account()),
            instance: format!("{id}:10080"),
            cluster: id.into(),
            counts: Accounting::for_factor_test(10, 0),
            healthy: true,
            local: true,
            label_matches: true,
        })
        .collect();
    let now = 1_000_000_000_000;
    let query = |value| QueryResult {
        kind: ValueKind::Vector,
        updated_nanos: Some(now),
        series: vec![Series {
            labels: BTreeMap::from([
                ("instance".into(), "b:10080".into()),
                ("tiproxy_cluster".into(), "b".into()),
            ]),
            samples: vec![Sample {
                timestamp_ms: now / 1_000_000,
                value,
            }],
        }],
    };
    let mut queries = BTreeMap::from([
        (QueryId::FailurePd, query(5.0)),
        (QueryId::TotalPd, query(10.0)),
        (QueryId::FailureTikv, query(0.0)),
        (QueryId::TotalTikv, query(10.0)),
    ]);
    let policy = must(EffectiveConfig::default().routing());
    let mut state = State::default();
    let _ = state.evaluate(&inputs, &policy, &queries, now);
    // Go's cached PD indicator survives a temporary omission while another
    // indicator advances. Revocation of unrelated cluster a must not erase b.
    queries.remove(&QueryId::FailurePd);
    queries.remove(&QueryId::TotalPd);
    state.clear_cluster("a");
    let report = state.evaluate(&inputs, &policy, &queries, now + 1);
    let b = must(
        report
            .rows
            .iter()
            .find(|row| row.backend_id.as_ref() == "b")
            .ok_or("b"),
    );
    assert!(
        b.parts.contains(&(Factor::Health, 2)),
        "FACTOR_UNCHANGED_CLUSTER_RETAINS_HEALTH"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadKey {
    Query(QueryId),
    Clock(window::ClockSite),
}
struct RecordedWindow<'a> {
    queries: &'a Queries,
    now: i64,
    reads: Vec<ReadKey>,
}
impl<'a> window::Window<'a, QueryResult> for RecordedWindow<'a> {
    type Error = std::convert::Infallible;
    fn query(&mut self, id: QueryId) -> Result<Option<&'a QueryResult>, Self::Error> {
        self.reads.push(ReadKey::Query(id));
        Ok(self.queries.get(&id))
    }
    fn clock(&mut self, site: window::ClockSite) -> Result<Option<i64>, Self::Error> {
        self.reads.push(ReadKey::Clock(site));
        Ok(Some(self.now))
    }
}
fn same_history(left: &State, right: &State) {
    let snapshot = |state: &State| {
        state
            .history
            .cache
            .iter()
            .map(|(id, c)| {
                (
                    id.to_string(),
                    c.cpu.map(|v| {
                        (
                            v.time,
                            v.avg.to_bits(),
                            v.latest.to_bits(),
                            v.connections.value().to_bits(),
                        )
                    }),
                    c.memory.map(|v| (v.time, v.risk, v.balance.to_bits())),
                    c.health.map(|v| (v.time, v.risk, v.balance.to_bits())),
                    c.status.map(|(t, v)| (t, v.to_bits())),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        snapshot(left),
        snapshot(right),
        "NATIVE_SINGLE_TIME_NEXT_HISTORY"
    );
    assert_eq!(
        (
            left.history.cpu_time,
            left.history.memory_time,
            left.history.usage_per_conn.to_bits()
        ),
        (
            right.history.cpu_time,
            right.history.memory_time,
            right.history.usage_per_conn.to_bits()
        ),
        "NATIVE_SINGLE_TIME_QUERY_KEYS"
    );
    assert_eq!(left.history.health_dirty, right.history.health_dirty);
    let queries = |state: &State| {
        state
            .history
            .health_queries
            .iter()
            .map(|(id, q)| {
                (
                    *id,
                    q.updated_nanos,
                    q.kind,
                    q.series
                        .iter()
                        .map(|s| {
                            (
                                s.labels.clone(),
                                s.samples
                                    .iter()
                                    .map(|p| (p.timestamp_ms, p.value.to_bits()))
                                    .collect::<Vec<_>>(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        queries(left),
        queries(right),
        "NATIVE_SINGLE_TIME_RETAINED_QUERY"
    );
}

#[test]
fn single_time_entry_matches_ordered_windows_and_next_history() {
    let mut ledger = Ledger::new(1);
    let inputs: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|id| Input {
            address: String::new(),
            id: Arc::from(id),
            owner: must(ledger.add_account()),
            instance: format!("{id}:10080"),
            cluster: "default".into(),
            counts: Accounting::for_factor_test(if id == "a" { 10 } else { 100 }, 2),
            healthy: id == "a",
            local: true,
            label_matches: true,
        })
        .collect();
    let policy = must(EffectiveConfig::default().routing());
    let mut direct = State::default();
    let mut ordered = State::default();
    let mut query_map = Queries::new();
    for round in 0..5_i64 {
        let now = 1_000_000_000_000 + round * 30_000_000_000;
        if round == 0 || round == 3 {
            for id in [
                QueryId::Cpu,
                QueryId::Memory,
                QueryId::FailurePd,
                QueryId::TotalPd,
                QueryId::FailureTikv,
                QueryId::TotalTikv,
            ] {
                query_map.insert(
                    id,
                    QueryResult {
                        updated_nanos: Some(now),
                        kind: if matches!(id, QueryId::Cpu | QueryId::Memory) {
                            ValueKind::Matrix
                        } else {
                            ValueKind::Vector
                        },
                        series: inputs
                            .iter()
                            .map(|input| Series {
                                labels: BTreeMap::from([(
                                    "instance".into(),
                                    input.instance.clone(),
                                )]),
                                samples: vec![Sample {
                                    timestamp_ms: now / 1_000_000,
                                    value: 0.8,
                                }],
                            })
                            .collect(),
                    },
                );
            }
        }
        if round == 2 {
            query_map.remove(&QueryId::FailurePd);
        }
        let report = direct.evaluate(&inputs, &policy, &query_map, now);
        let mut window = RecordedWindow {
            queries: &query_map,
            now,
            reads: Vec::new(),
        };
        let repeated = must(ordered.evaluate_window(&inputs, &policy, &mut window));
        assert_eq!(report, repeated, "NATIVE_SINGLE_TIME_REPORT");
        same_history(&direct, &ordered);
        let position = |site| {
            window
                .reads
                .iter()
                .position(|read| *read == ReadKey::Clock(site))
        };
        if let Some(snapshot) = position(window::ClockSite::HealthSnapshot) {
            assert!(position(window::ClockSite::HealthExpiry) < Some(snapshot));
        }
        if let Some(snapshot) = position(window::ClockSite::CpuSnapshot) {
            assert!(Some(snapshot) < position(window::ClockSite::CpuExpiry));
        }
        if let Some(snapshot) = position(window::ClockSite::MemorySnapshot) {
            assert!(Some(snapshot) < position(window::ClockSite::MemoryExpiry));
        }
    }
}

/// `CodexM5`'s review regression, adopted rather than restated: all six
/// metrics for two real backends, the derived cpu average and memory
/// value, a 1ms-later update proving there is no throttle, rejected and
/// absent samples retaining what was already exposed, and a policy change
/// leaving the family alone because Go never resets it.
#[test]
#[allow(clippy::too_many_lines)] // One scenario end to end; splitting it would hide the ordering.
fn review_backend_metric_accepted_factor_samples_publish_derived_values() {
    use crate::BackendMetric::{Cpu, FailurePd, FailureTikv, Memory, TotalPd, TotalTikv};
    let metrics = Arc::new(crate::BackendMetricHistory::new());
    let mut state = State::default();
    state.set_backend_metrics(Some(Arc::clone(&metrics)));
    let mut ledger = Ledger::new(2);
    let inputs: Vec<_> = [0, 1]
        .into_iter()
        .map(|i| Input {
            id: Arc::from(format!("opaque-backend-{i}")),
            address: format!("sql-{i}:4000"),
            instance: format!("status-{i}:10080"),
            cluster: "default".to_owned(),
            owner: must(ledger.add_account()),
            counts: Accounting::for_factor_test(10, 0),
            healthy: true,
            local: true,
            label_matches: true,
        })
        .collect();
    let mut policy = must(EffectiveConfig::default().routing());
    policy.balance_policy = RoutingBalancePolicy::Resource;
    let t = 1_000_000_000_000_i64;
    let make_queries = |updated, sample_ms, cpu: [f64; 2], mem: f64| -> Queries {
        [
            (
                QueryId::Cpu,
                ValueKind::Matrix,
                vec![(sample_ms - 1000, cpu[0]), (sample_ms, cpu[1])],
            ),
            (
                QueryId::Memory,
                ValueKind::Matrix,
                vec![(sample_ms - 1000, 0.4), (sample_ms, mem)],
            ),
            (
                QueryId::FailurePd,
                ValueKind::Vector,
                vec![(sample_ms, 2.0)],
            ),
            (QueryId::TotalPd, ValueKind::Vector, vec![(sample_ms, 10.0)]),
            (
                QueryId::FailureTikv,
                ValueKind::Vector,
                vec![(sample_ms, 3.0)],
            ),
            (
                QueryId::TotalTikv,
                ValueKind::Vector,
                vec![(sample_ms, 20.0)],
            ),
        ]
        .into_iter()
        .map(|(id, kind, values)| {
            (
                id,
                QueryResult {
                    updated_nanos: Some(updated),
                    kind,
                    series: inputs
                        .iter()
                        .map(|input| Series {
                            labels: BTreeMap::from([
                                ("instance".to_owned(), input.instance.clone()),
                                ("tiproxy_cluster".to_owned(), "default".to_owned()),
                            ]),
                            samples: values
                                .iter()
                                .map(|&(timestamp_ms, value)| Sample {
                                    timestamp_ms,
                                    value,
                                })
                                .collect(),
                        })
                        .collect(),
                },
            )
        })
        .collect()
    };
    let first = state.evaluate(
        &inputs,
        &policy,
        &make_queries(t, t / 1_000_000, [0.2, 0.6], 0.95),
        t,
    );
    // Publication is the commit-time step the router runs under the
    // combined authority; at this layer it is called directly.
    state.publish_backend_metrics();
    assert_eq!(first.rows.len(), 2);
    let first_values = metrics.snapshot().values;
    println!("accepted actual factor sample -> backend_metric {first_values:?}");
    assert_eq!(
        first_values.len(),
        12,
        "all six accepted values for both actual addresses"
    );
    for input in &inputs {
        for (metric, expected) in [
            (Cpu, 0.4),
            (Memory, 0.9),
            (FailurePd, 2.0),
            (TotalPd, 10.0),
            (FailureTikv, 3.0),
            (TotalTikv, 20.0),
        ] {
            let actual = first_values.get(&(input.address.clone(), metric)).copied();
            assert!(
                actual.is_some_and(|v| (v - expected).abs() < 1e-12),
                "{metric:?}: {actual:?} expected {expected}"
            );
        }
    }
    let next = make_queries(t + 1_000_000, t / 1_000_000 + 1, [0.1, 0.3], 0.5);
    let _ = state.evaluate(&inputs, &policy, &next, t + 1_000_000);
    state.publish_backend_metrics();
    let second = metrics.snapshot().values;
    for input in &inputs {
        assert!((second[&(input.address.clone(), Cpu)] - 0.2).abs() < 1e-12);
        assert!((second[&(input.address.clone(), Memory)] - 0.5).abs() < 1e-12);
    }
    println!("accepted 1ms later without score throttle -> {second:?}");
    let mut skipped = make_queries(t + 2_000_000, t / 1_000_000 + 2, [f64::NAN; 2], f64::NAN);
    for (id, query) in &mut skipped {
        if *id == QueryId::Memory {
            for s in &mut query.series {
                for sample in &mut s.samples {
                    sample.value = f64::NAN;
                }
            }
        }
    }
    skipped.retain(|id, _| matches!(id, QueryId::Cpu | QueryId::Memory));
    let _ = state.evaluate(&inputs, &policy, &skipped, t + 2_000_000);
    state.publish_backend_metrics();
    assert_eq!(
        metrics.snapshot().values,
        second,
        "rejected resource values and absent health samples retain exposure"
    );
    policy.balance_policy = RoutingBalancePolicy::Connection;
    let _ = state.evaluate(&inputs, &policy, &Queries::new(), t + 3_000_000);
    state.publish_backend_metrics();
    assert_eq!(
        metrics.snapshot().values,
        second,
        "configuration does not Reset backend_metric"
    );
}

/// A round whose commit was refused never reaches the family, and never
/// reaches it later either.
///
/// This is the property the deferral exists for. Go writes each accepted
/// value inline, which cannot be fenced: by the time a source is found to
/// have been revoked, the write has already happened. Recording the
/// values and publishing them inside the combined commit moves the write
/// to a point where refusing it is still possible.
///
/// Scope, because the obvious stronger reading is wrong: this does not by
/// itself prove that a revoked source refuses publication. It proves the
/// two halves that compose into that -- `evaluate` publishes nothing on
/// its own, and an unpublished round is discarded rather than carried --
/// while the refusal itself belongs to `commit_all`, which has its own
/// tests. The connection between them is structural: the only callers of
/// `publish_backend_metrics` outside this file are the two `commit_valid`
/// closures in the selector.
#[test]
fn a_round_that_never_commits_never_publishes() {
    use crate::BackendMetric::Cpu;
    let metrics = Arc::new(crate::BackendMetricHistory::new());
    let mut state = State::default();
    state.set_backend_metrics(Some(Arc::clone(&metrics)));
    let mut ledger = Ledger::new(1);
    let inputs: Vec<_> = [0, 1]
        .into_iter()
        .map(|i| Input {
            id: Arc::from(format!("opaque-backend-{i}")),
            address: format!("sql-{i}:4000"),
            instance: format!("status-{i}:10080"),
            cluster: "default".to_owned(),
            owner: must(ledger.add_account()),
            counts: Accounting::for_factor_test(10, 0),
            healthy: true,
            local: true,
            label_matches: true,
        })
        .collect();
    let mut policy = must(EffectiveConfig::default().routing());
    policy.balance_policy = RoutingBalancePolicy::Resource;
    let t = 1_000_000_000_000_i64;
    // `only` selects which backends have a sample this round, so a round
    // can stop reporting a backend the previous round did report.
    let cpu_for = |sample_ms: i64, value: f64, only: &[usize]| -> Queries {
        [(
            QueryId::Cpu,
            QueryResult {
                updated_nanos: Some(sample_ms * 1_000_000),
                kind: ValueKind::Matrix,
                series: inputs
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| only.contains(index))
                    .map(|(_, input)| Series {
                        labels: BTreeMap::from([
                            ("instance".to_owned(), input.instance.clone()),
                            ("tiproxy_cluster".to_owned(), "default".to_owned()),
                        ]),
                        samples: vec![
                            Sample {
                                timestamp_ms: sample_ms - 1000,
                                value,
                            },
                            Sample {
                                timestamp_ms: sample_ms,
                                value,
                            },
                        ],
                    })
                    .collect(),
            },
        )]
        .into_iter()
        .collect()
    };

    // A committed round: accepted, then published.
    let _ = state.evaluate(&inputs, &policy, &cpu_for(t / 1_000_000, 0.4, &[0, 1]), t);
    assert!(
        metrics.snapshot().values.is_empty(),
        "evaluation alone publishes nothing -- the write waits for the commit"
    );
    state.publish_backend_metrics();
    let committed = metrics.snapshot().values;
    for input in &inputs {
        let value = committed.get(&(input.address.clone(), Cpu)).copied();
        assert!(
            value.is_some_and(|v| (v - 0.4).abs() < 1e-12),
            "the committed round is exposed: {value:?}"
        );
    }

    // A refused round: accepted by the factors, never committed. It must
    // leave the previous value standing rather than overwrite it.
    let _ = state.evaluate(
        &inputs,
        &policy,
        &cpu_for(t / 1_000_000 + 1, 0.9, &[0, 1]),
        t + 1_000_000,
    );
    assert_eq!(
        metrics.snapshot().values,
        committed,
        "a round whose commit was refused exposes nothing"
    );

    // And it must not ride along on the next round that does commit. The
    // next round reports backend 0 only, so if the refused round were
    // merely queued rather than discarded, backend 1 -- which this round
    // says nothing about -- would still move to 0.9.
    let _ = state.evaluate(
        &inputs,
        &policy,
        &cpu_for(t / 1_000_000 + 2, 0.2, &[0]),
        t + 2_000_000,
    );
    state.publish_backend_metrics();
    let after = metrics.snapshot().values;
    let reported = after.get(&(inputs[0].address.clone(), Cpu)).copied();
    assert!(
        reported.is_some_and(|v| (v - 0.2).abs() < 1e-12),
        "the backend this round reported takes its committed value: {reported:?}"
    );
    let silent = after.get(&(inputs[1].address.clone(), Cpu)).copied();
    assert!(
        silent.is_some_and(|v| (v - 0.4).abs() < 1e-12),
        "the backend it did not report keeps its last committed value,          not the refused round's 0.9: {silent:?}"
    );
}
