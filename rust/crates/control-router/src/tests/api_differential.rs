// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-only API adapter. Real modules consume source inputs and Router/Selector
//! own every selection/reservation. Go observations never enter this adapter.

use super::{Harness, TestResult};
use crate::{Reservation, RouteError, Router, Selector, Settlement};
use control_routing::group::ClientInfo;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

struct Slot {
    selector: Selector,
    pending: Option<Reservation>,
    active: Option<String>,
    client: String,
    proxy: String,
    port: String,
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn outcome(error: RouteError) -> String {
    match error {
        RouteError::NoBackend => "no_backend".into(),
        RouteError::PortConflict => "port_conflict".into(),
        // Preserve unexpected domain failures for comparison/diagnosis rather
        // than normalizing them into an allowed no-backend result.
        other => format!("rust:{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay() -> TestResult {
    let Ok(input) = std::env::var("CPROUTE_API_INPUT") else {
        return Ok(());
    };
    let trace: Value = serde_json::from_slice(&std::fs::read(input)?)?;
    assert_eq!(trace["version"], 1);
    let cfg = &trace["config"];
    let mut h = Harness::with_backends(text(cfg, "rule"), "connection", &[]).await?;
    let initial = format!(
        "[balance]\npolicy={:?}\nrouting-policy={:?}\n",
        text(cfg, "policy"),
        text(cfg, "selection")
    );
    h.patch(&initial, 3);
    h.source.deliver();
    h.applied().await;
    h.router = Arc::new(
        Router::new_with_factors(
            Arc::new(h.source.clone()),
            &h.topology,
            &h.runtime.handle().module_context(),
            "default",
            100_000,
            None,
        )
        .map_err(|e| format!("router init: {e:?}"))?,
    );
    let mut sessions: BTreeMap<String, Slot> = BTreeMap::new();
    let mut known = BTreeSet::new();
    let mut output = Vec::new();
    let events = trace["events"].as_array().ok_or("missing events")?;
    for (index, event) in events.iter().enumerate() {
        let id = text(event, "session");
        let op = text(event, "op");
        let mut row =
            json!({"seq":index,"op":op,"session":id,"outcome":"ok","backend":"","effects":[]});
        match op {
            "health" => {
                let backends = event["backends"].as_array().ok_or("health backends")?;
                let labels: Vec<Vec<(&str, &str)>> = backends
                    .iter()
                    .map(|b| {
                        b["labels"]
                            .as_object()
                            .into_iter()
                            .flatten()
                            .map(|(k, v)| (k.as_str(), v.as_str().unwrap_or_default()))
                            .collect()
                    })
                    .collect();
                let values: Vec<(&str, &[(&str, &str)])> = backends
                    .iter()
                    .zip(&labels)
                    .map(|(b, l)| (text(b, "address"), l.as_slice()))
                    .collect();
                let wanted: BTreeSet<String> = values
                    .iter()
                    .map(|(addr, _)| format!("default/{addr}"))
                    .collect();
                known.extend(wanted.iter().cloned());
                h.fixture.backends(&values);
                // Await the real source delivery. This barrier checks source
                // inventory, never a selected group/factor/internal shortlist.
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if let Ok(candidate) = h.router.capture() {
                            let seen: BTreeSet<String> = candidate
                                .routing
                                .backends
                                .backends
                                .iter()
                                .map(|b| b.backend_id.to_string())
                                .collect();
                            if seen == wanted {
                                break;
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await?;
            }
            "config" => {
                if h.source
                    .store
                    .apply_toml(
                        text(event, "toml").as_bytes(),
                        None,
                        u64::try_from(index)? + 4,
                        Path::new("/tmp"),
                    )
                    .is_err()
                {
                    row["outcome"] = json!("invalid_config");
                } else {
                    h.source.deliver();
                    h.applied().await;
                }
            }
            "open" => {
                let selector = h.router.selector().map_err(|e| format!("open: {e:?}"))?;
                let prior = sessions.insert(
                    id.into(),
                    Slot {
                        selector,
                        pending: None,
                        active: None,
                        client: text(event, "client").into(),
                        proxy: text(event, "proxy").into(),
                        port: text(event, "port").into(),
                    },
                );
                assert!(prior.is_none(), "duplicate logical session");
            }
            "next" => {
                let s = sessions.get_mut(id).ok_or("missing session")?;
                let client = ClientInfo {
                    client_address: (!s.client.is_empty()).then_some(s.client.as_str()),
                    proxy_address: (!s.proxy.is_empty()).then_some(s.proxy.as_str()),
                };
                match s.selector.next(client, &s.port) {
                    Ok(reservation) => {
                        row["backend"] = json!(reservation.assignment().backend_id);
                        s.pending = Some(reservation);
                    }
                    Err(error) => row["outcome"] = json!(outcome(error)),
                }
            }
            "finish" => {
                let s = sessions.get_mut(id).ok_or("missing session")?;
                let pending = s.pending.take().ok_or("missing reservation")?;
                let connected = event["success"].as_bool().unwrap_or(false);
                assert_eq!(s.selector.finish(&pending, connected), Settlement::Applied);
                s.active = connected.then(|| pending.assignment().backend_id.clone());
            }
            "close" => {
                let s = sessions.remove(id).ok_or("missing session")?;
                assert!(
                    s.pending.is_none(),
                    "pending creation requires its Finish callback"
                );
                drop(s);
            }
            "checkpoint" => {
                let assignments: BTreeMap<&str, &str> = sessions
                    .iter()
                    .filter_map(|(id, s)| s.active.as_deref().map(|backend| (id.as_str(), backend)))
                    .collect();
                let count: u64 = known
                    .iter()
                    .filter_map(|id| h.router.accounting(id))
                    .map(|a| a.active())
                    .sum();
                row["assignments"] = json!(assignments);
                row["conn_count"] = json!(count);
            }
            _ => return Err(format!("unsupported API input {op}").into()),
        }
        output.push(row);
    }
    assert!(
        sessions.is_empty(),
        "trace must settle and close all logical sessions"
    );
    assert_eq!(
        known
            .iter()
            .filter_map(|id| h.router.accounting(id))
            .map(|a| a.active())
            .sum::<u64>(),
        0
    );
    std::fs::write(
        std::env::var("CPROUTE_API_OUTPUT")?,
        serde_json::to_vec(&output)?,
    )?;
    h.runtime
        .begin_shutdown(control_plane::ShutdownReason::Requested)?;
    Ok(())
}
