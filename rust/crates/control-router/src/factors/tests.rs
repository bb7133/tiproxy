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
                updated_nanos: integer(&query["time"]),
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
        updated_nanos: now,
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
    assert!(state.cache["a"].cpu.is_some());
    let previous_owner = Arc::clone(&inputs[0].owner);
    inputs[0].owner = must(ledger.add_account());
    let owners = inputs
        .iter()
        .map(|input| (Arc::clone(&input.id), Arc::clone(&input.owner)))
        .collect();
    state.retain_owners(&owners);
    assert!(
        !state.cache.contains_key("a"),
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
    assert!(!Arc::ptr_eq(&state.cache["a"].owner, &previous_owner));
    state.clear_cluster("default");
    assert!(
        state.cache.values().all(|cache| cache.cpu.is_none()),
        "FACTOR_COLD_START_CLEARS_CACHE"
    );
}

#[test]
fn other_cluster_lineage_preserves_cached_health_indicator() {
    let mut ledger = Ledger::new(1);
    let inputs: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|id| Input {
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
        updated_nanos: now,
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
