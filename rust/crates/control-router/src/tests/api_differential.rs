// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-only API adapter. Real modules consume source inputs and Router/Selector
//! own every selection/reservation. Go observations never enter this adapter.

use super::{Harness, TestResult, must};
use crate::scheduler::{CommandQueue, RoundClock};
use crate::{Accounting, MigrationCommand, Reservation, RouteError, Router, Selector, Settlement};
use control_routing::group::ClientInfo;
use control_topology::{BackendHealth, BackendInfo, MergedBackend, MergedTopology, ObserverError};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Slot {
    selector: Selector,
    pending: Option<Reservation>,
    active: Option<String>,
    client: String,
    proxy: String,
    port: String,
}

#[derive(Default)]
struct ClientEffects {
    names: BTreeMap<u64, String>,
    ordinals: BTreeMap<String, u64>,
    refused: BTreeSet<String>,
    offered: Vec<(Value, MigrationCommand)>,
}
impl ClientEffects {
    fn accept(&mut self, command: &MigrationCommand) -> bool {
        let (kind, from, to) = match command {
            MigrationCommand::Redirect(r) => ("redirect", r.from(), r.to().backend_id.as_str()),
            MigrationCommand::ForceClose(c) => ("force_close", c.assignment(), ""),
        };
        let id = &self.names[&from.connection_id];
        let ordinal = self.ordinals.entry(id.clone()).or_default();
        *ordinal += 1;
        let accepted = !self.refused.contains(id);
        let effect = json!({"kind":kind,"session":id,"operation":format!("{id}/{ordinal}"),
            "from":from.backend_id,"to":to,"accepted":accepted});
        self.offered.push((effect, command.clone()));
        accepted
    }
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn outcome(error: RouteError) -> String {
    match error {
        RouteError::NoBackend => "no_backend".into(),
        RouteError::WrappedNoBackend => "wrapped_no_backend".into(),
        RouteError::PortConflict => "port_conflict".into(),
        RouteError::Observer(ObserverError::TopologyUnavailable) => {
            "source_error:topology_unavailable".into()
        }
        RouteError::Observer(ObserverError::Cancelled) => "source_error:cancelled".into(),
        RouteError::Observer(ObserverError::DeadlineExceeded) => {
            "source_error:deadline_exceeded".into()
        }
        // Preserve unexpected domain failures for comparison/diagnosis rather
        // than normalizing them into an allowed no-backend result.
        other => format!("rust:{other:?}"),
    }
}

fn source_error(name: &str) -> Result<ObserverError, &'static str> {
    Ok(match name {
        "no_backend" => ObserverError::NoBackend,
        "wrapped_no_backend" => ObserverError::WrappedNoBackend,
        "port_conflict" => ObserverError::PortConflict,
        "topology_unavailable" => ObserverError::TopologyUnavailable,
        "cancelled" => ObserverError::Cancelled,
        "deadline_exceeded" => ObserverError::DeadlineExceeded,
        _ => return Err("unsupported observer error input"),
    })
}

// One finite external event dispatcher keeps the lifecycle readable in order.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay() -> TestResult {
    let Ok(input) = std::env::var("CPROUTE_API_INPUT") else {
        return Ok(());
    };
    let trace: Value = serde_json::from_slice(&std::fs::read(input)?)?;
    assert_eq!(trace["version"], 1);
    let cfg = &trace["config"];
    let origin = cfg["clock_origin_nanos"]
        .as_i64()
        .unwrap_or(1_700_000_000_000_000_000);
    let mut h = Harness::with_backends(text(cfg, "rule"), "connection", &[]).await?;
    let initial = format!(
        "[balance]\npolicy={:?}\nrouting-policy={:?}\n",
        text(cfg, "policy"),
        text(cfg, "selection")
    );
    h.patch(&initial, 3);
    h.source.deliver();
    h.applied().await;
    let health_input = h
        .topology
        .replay_health_input(h.runtime.handle().module_context().owner().clone());
    health_input.deliver(
        MergedTopology {
            backends: Vec::new(),
        },
        HashMap::new(),
        HashMap::new(),
    )?;
    let mut metric_input = h
        .topology
        .replay_metric_input(h.runtime.handle().module_context().owner().clone())
        .await?;
    metric_input.sync()?;
    h.router = Arc::new(
        Router::new_with_factors(
            Arc::new(h.source.clone()),
            &h.topology,
            &h.runtime.handle().module_context(),
            "default",
            100_000,
            Some(metric_input.handle()),
        )
        .map_err(|e| format!("router init: {e:?}"))?,
    );
    let mut sessions: BTreeMap<String, Slot> = BTreeMap::new();
    let mut known = BTreeSet::new();
    let mut output = Vec::new();
    let start = Instant::now();
    let effects = Arc::new(Mutex::new(ClientEffects::default()));
    let sink = Arc::clone(&effects);
    let queue = CommandQueue::with_api_sink(
        100_000,
        Box::new(move |command| must(sink.lock()).accept(command)),
    );
    let mut operations: BTreeMap<String, (String, MigrationCommand, bool)> = BTreeMap::new();
    let (_stop, stop) = tokio::sync::watch::channel(false);
    let events = trace["events"].as_array().ok_or("missing events")?;
    for (index, event) in events.iter().enumerate() {
        let id = text(event, "session");
        let op = text(event, "op");
        let mut row =
            json!({"seq":index,"op":op,"session":id,"outcome":"ok","backend":"","effects":[]});
        let elapsed = event["at_nanos"].as_u64().unwrap_or(0);
        let now = start + Duration::from_nanos(elapsed);
        let wall = origin
            .checked_add(i64::try_from(elapsed)?)
            .ok_or("event clock overflow")?;
        h.router.set_replay_wall(wall);
        match op {
            "metrics" => metric_input.deliver(event["queries"].clone())?,
            "source_error" => health_input.deliver_error(source_error(text(event, "error"))?)?,
            "health" => {
                let backends = event["backends"].as_array().ok_or("health backends")?;
                let mut topology = Vec::new();
                let mut verdicts = HashMap::new();
                let mut redirection = HashMap::new();
                for b in backends {
                    let cluster = b["cluster"].as_str().unwrap_or("default");
                    let address = text(b, "address");
                    let id: Arc<str> = if cluster.is_empty() {
                        Arc::from(address)
                    } else {
                        Arc::from(format!("{cluster}/{address}"))
                    };
                    known.insert(id.to_string());
                    topology.push(MergedBackend {
                        backend_id: Arc::clone(&id),
                        cluster_name: Arc::from(cluster),
                        backend: BackendInfo {
                            addr: address.into(),
                            keyspace: text(b, "keyspace").into(),
                            ip: b["ip"].as_str().unwrap_or("127.0.0.1").into(),
                            status_port: b["status_port"].as_u64().unwrap_or(0),
                            version: String::new(),
                            git_hash: String::new(),
                            deploy_path: String::new(),
                            start_timestamp: 0,
                            labels: serde_json::from_value(b["labels"].clone())?,
                        },
                    });
                    verdicts.insert(
                        Arc::clone(&id),
                        BackendHealth {
                            healthy: b["healthy"].as_bool().unwrap_or(true),
                            local: b["local"].as_bool().unwrap_or(true),
                            server_version: Some(text(b, "server_version").into()),
                        },
                    );
                    redirection.insert(id, b["support_redirection"].as_bool().unwrap_or(true));
                }
                health_input.deliver(
                    MergedTopology { backends: topology },
                    verdicts,
                    redirection,
                )?;
                metric_input.sync()?;
                let candidate = h
                    .router
                    .capture()
                    .map_err(|e| format!("health apply: {e:?}"))?;
                h.router
                    .refresh_failover(&candidate, now)
                    .map_err(|e| format!("failover: {e:?}"))?;
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
                    metric_input.sync()?;
                    let candidate = h.ready().await;
                    h.router
                        .refresh_failover(&candidate, now)
                        .map_err(|e| format!("failover config: {e:?}"))?;
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
            "lookup" => match h.router.lookup_backend(text(event, "backend")) {
                Ok(assignment) => row["backend"] = json!(assignment.backend_id),
                Err(RouteError::NoBackend) => row["outcome"] = json!("unknown_backend"),
                Err(error) => row["outcome"] = json!(outcome(error)),
            },
            "rehydrate" => {
                let s = sessions.get_mut(id).ok_or("missing session")?;
                match s.selector.rehydrate(text(event, "backend")) {
                    Ok(assignment) => {
                        row["backend"] = json!(assignment.backend_id);
                        s.active = Some(assignment.backend_id);
                        must(effects.lock())
                            .names
                            .insert(assignment.connection_id, id.into());
                    }
                    Err(RouteError::NoBackend) => row["outcome"] = json!("unknown_backend"),
                    Err(error) => row["outcome"] = json!(outcome(error)),
                }
            }
            "tick" => {
                must(effects.lock()).refused = event["refuse"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|v| v.as_str().unwrap_or_default().to_string())
                    .collect();
                let candidate = h
                    .router
                    .capture()
                    .map_err(|e| format!("tick capture: {e:?}"))?;
                let clock = RoundClock {
                    fixed: Some((now, now, wall)),
                };
                h.router
                    .migration_round(&candidate, &queue, true, &stop, &clock)
                    .map_err(|e| format!("tick: {e:?}"))?;
                let mut rows = Vec::new();
                for (effect, command) in must(effects.lock()).offered.drain(..) {
                    if effect["accepted"] == true {
                        assert!(queue.take().is_some());
                        operations.insert(
                            text(&effect, "operation").into(),
                            (text(&effect, "session").into(), command, false),
                        );
                    }
                    rows.push(effect);
                }
                assert!(queue.take().is_none());
                row["effects"] = json!(rows);
            }
            "redirect_result" => {
                let (session, command, completed) = operations
                    .get_mut(text(event, "operation"))
                    .ok_or("unknown operation")?;
                let MigrationCommand::Redirect(redirect) = command else {
                    return Err("not a redirect".into());
                };
                let success = event["success"].as_bool().ok_or("missing success")?;
                let settlement = h.router.finish_redirect(redirect, success, now);
                if !*completed && let Some(s) = sessions.get_mut(session) {
                    assert_eq!(settlement, Settlement::Applied);
                    if success {
                        s.active = Some(redirect.to().backend_id.clone());
                    }
                } else {
                    assert_eq!(settlement, Settlement::Ignored);
                }
                *completed = true;
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
                        must(effects.lock())
                            .names
                            .insert(reservation.assignment().connection_id, id.into());
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
                    .map(Accounting::active)
                    .sum();
                row["assignments"] = json!(assignments);
                row["conn_count"] = json!(count);
                row["healthy_backend_count"] = json!(h.router.healthy_backend_count());
                row["server_version"] = json!(h.router.server_version());
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
            .map(Accounting::active)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rehydration_rejects_non_idle_or_closed_sessions_without_extra_charge() -> TestResult {
    let h = Harness::new("", "connection").await?;
    let backend = "default/127.0.0.1:4000";
    let session = h.router.open().map_err(|e| format!("open: {e:?}"))?;
    assert!(matches!(
        h.router.lookup_backend("missing"),
        Err(RouteError::NoBackend)
    ));
    assert!(matches!(
        h.router.rehydrate(&session, "missing"),
        Err(RouteError::NoBackend)
    ));
    let assignment = h
        .router
        .rehydrate(&session, backend)
        .map_err(|e| format!("restore: {e:?}"))?;
    assert_eq!(assignment.backend_id, backend);
    assert!(matches!(
        h.router.rehydrate(&session, backend),
        Err(RouteError::AlreadyActive)
    ));
    assert_eq!(
        h.router.accounting(backend).map(Accounting::active),
        Some(1)
    );
    assert_eq!(h.router.close(&session), Settlement::Applied);
    assert!(matches!(
        h.router.rehydrate(&session, backend),
        Err(RouteError::InvalidSession)
    ));
    assert_eq!(
        h.router.accounting(backend).map(Accounting::active),
        Some(0)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // One ordered source lifetime, including retained old snapshots.
async fn metric_input_preserves_values_and_fences_replacement_config_and_drop() -> TestResult {
    use control_topology::metrics::QueryId;
    let mut h = Harness::new("", "resource").await?;
    let health = h
        .topology
        .replay_health_input(h.runtime.handle().module_context().owner().clone());
    health.deliver(MergedTopology::default(), HashMap::new(), HashMap::new())?;
    let mut input = h
        .topology
        .replay_metric_input(h.runtime.handle().module_context().owner().clone())
        .await?;
    let overlay = input.handle();
    let mut packet = json!({"cpu":{"kind":"matrix","updated_nanos":0,"series":[
        {"labels":{"instance":"a"},"samples":[{"timestamp_ms":3,"value":"-0"},{"timestamp_ms":2,"value":"NaN"}]},
        {"labels":{"instance":"a","duplicate":"second"},"samples":[]}]},
        "memory":null,"failure_pd":null,"total_pd":null,"failure_tikv":null,"total_tikv":null});
    input.deliver(packet.clone())?;
    let capture = || {
        overlay
            .routing_current_for(
                &h.topology
                    .routing_handle()
                    .current()
                    .unwrap_or_else(|| unreachable!("routing")),
                &h.source.store.current().resource_incarnation(),
            )
            .ok_or("metric snapshot")
    };
    let first = capture()?;
    let result = first.query_result(QueryId::Cpu)?.ok_or("cpu")?;
    assert_eq!(result.updated_nanos, 0);
    assert!(result.series[0].samples[0].value.is_sign_negative());
    assert!(result.series[0].samples[1].value.is_nan());
    assert_eq!(result.series[0].samples[1].timestamp_ms, 2);
    assert_eq!(result.series[1].labels["duplicate"], "second");
    let lineage = first
        .cache_lineage("any-recorded-cluster")
        .ok_or("lineage")?;
    let mut invalid = packet.clone();
    invalid["memory"] = json!({"kind":"scalar","updated_nanos":1,"series":[]});
    assert!(input.deliver(invalid).is_err());
    assert!(
        first.still_current(),
        "malformed whole input cannot install its valid CPU prefix"
    );
    packet["cpu"]["updated_nanos"] = json!(1);
    input.deliver(packet.clone())?;
    assert!(!first.still_current());
    assert_eq!(first.with_current(|| true), None);
    let second = capture()?;
    assert!(
        lineage.same_history(
            &second
                .cache_lineage("any-recorded-cluster")
                .ok_or("lineage")?
        )
    );
    assert_eq!(
        second
            .query_result(QueryId::Cpu)?
            .ok_or("cpu")?
            .updated_nanos,
        1
    );
    h.source.store.apply_toml(
        b"[balance]\npolicy='connection'",
        None,
        100,
        Path::new("/tmp"),
    )?;
    assert!(
        !second.still_current(),
        "accepted policy transition revokes before watcher polling"
    );
    input.sync()?;
    h.source.store.apply_toml(
        b"[balance]\npolicy='resource'",
        None,
        101,
        Path::new("/tmp"),
    )?;
    input.sync()?;
    let resumed = capture()?;
    assert!(
        !lineage.same_history(
            &resumed
                .cache_lineage("any-recorded-cluster")
                .ok_or("lineage")?
        )
    );
    input.deliver(json!({"cpu":null,"memory":null,"failure_pd":null,"total_pd":null,"failure_tikv":null,"total_tikv":null}))?;
    assert!(!resumed.still_current());
    let cleared = capture()?;
    assert!(cleared.query_result(QueryId::Cpu)?.is_none());
    assert_eq!(cleared.with_current(|| 7), Some(7));
    drop(input);
    assert!(!cleared.still_current());
    assert_eq!(cleared.with_current(|| 7), None);
    assert!(capture().is_err());
    Ok(())
}
