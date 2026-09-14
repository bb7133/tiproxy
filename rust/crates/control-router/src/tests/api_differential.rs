// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-only API adapter. Real modules consume source inputs and Router/Selector
//! own every selection/reservation. Go observations never enter this adapter.

use super::{Harness, TestResult, must};
use crate::scheduler::{CommandQueue, RoundClock};
use crate::{Accounting, MigrationCommand, Reservation, RouteError, Router, Selector, Settlement};
use control_config::ConfigNamespaceSource;
use control_routing::group::ClientInfo;
use control_topology::{BackendHealth, BackendInfo, MergedBackend, MergedTopology, ObserverError};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Slot {
    selector: Option<Selector>,
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
    refuse_next: u64,
    refusal_attempts: u64,
    delay_next: u64,
    delay_attempts: u64,
    delayed_operation: Option<String>,
    delayed_settled_early: bool,
    offered: Vec<(Value, MigrationCommand)>,
}
impl ClientEffects {
    fn arm_refusal(&mut self, refusal: u64, index: usize) {
        assert_eq!(refusal, 1, "one-shot refusal input at event {index}");
        assert_eq!(
            self.refuse_next, 0,
            "one-shot refusal armed while one is pending at event {index}"
        );
        self.refuse_next = refusal;
        self.refusal_attempts = 0;
    }

    fn expire_refusal(&mut self, boundary: &str, index: usize) {
        if self.refuse_next == 0 {
            return;
        }
        assert_eq!(
            self.refusal_attempts, 0,
            "one-shot refusal survived {} eligible attempts before {boundary} at event {index}",
            self.refusal_attempts
        );
        self.refuse_next = 0;
    }

    fn arm_delay(&mut self, delay: u64, index: usize) {
        assert_eq!(delay, 1, "delayed callback input at event {index}");
        assert_eq!(
            self.delay_next, 0,
            "delayed callback armed while one is pending at event {index}"
        );
        assert!(
            self.delayed_operation.is_none() && !self.delayed_settled_early,
            "delayed callback operation still pending at event {index}"
        );
        self.delay_next = delay;
        self.delay_attempts = 0;
    }

    fn expire_delay(&mut self, boundary: &str, index: usize) {
        if self.delay_next == 0 {
            return;
        }
        assert_eq!(
            self.delay_attempts, 0,
            "delayed callback survived {} accepted redirects before {boundary} at event {index}",
            self.delay_attempts
        );
        self.delay_next = 0;
    }

    fn accept(&mut self, command: &MigrationCommand) -> bool {
        let (kind, from, to) = match command {
            MigrationCommand::Redirect(r) => ("redirect", r.from(), r.to().backend_id.as_str()),
            MigrationCommand::ForceClose(c) => ("force_close", c.assignment(), ""),
        };
        let id = &self.names[&from.connection_id];
        let ordinal = self.ordinals.entry(id.clone()).or_default();
        *ordinal += 1;
        let mut refused = self.refused.contains(id);
        if !refused && self.refuse_next > 0 {
            self.refusal_attempts += 1;
            self.refuse_next -= 1;
            refused = true;
        }
        let accepted = !refused;
        let operation = format!("{id}/{ordinal}");
        if accepted && kind == "redirect" && self.delay_next > 0 {
            self.delay_attempts += 1;
            self.delay_next -= 1;
            self.delayed_operation = Some(operation.clone());
        }
        let effect = json!({"kind":kind,"session":id,"operation":operation,
            "from":from.backend_id,"to":to,"accepted":accepted});
        self.offered.push((effect, command.clone()));
        accepted
    }
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn backend_address(id: &str) -> &str {
    id.split_once('/').map_or(id, |(_, address)| address)
}

fn swap_logical_session(
    logical_sessions: &mut BTreeMap<String, String>,
    logical: &str,
    actual: &str,
    boundary: &str,
) -> TestResult {
    let other = logical_sessions
        .iter()
        .find_map(|(candidate, mapped)| (mapped == actual).then(|| candidate.clone()))
        .ok_or_else(|| format!("{boundary} target"))?;
    let displaced = logical_sessions
        .get(logical)
        .ok_or_else(|| format!("{boundary} logical handle"))?
        .clone();
    logical_sessions.insert(logical.into(), actual.into());
    logical_sessions.insert(other, displaced);
    Ok(())
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

fn is_cluster_replacement_metric_gap(error: &str, backend_clusters_replaced: bool) -> bool {
    backend_clusters_replaced && error == "metric input source unavailable"
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
    metric_input
        .sync()
        .map_err(|error| format!("initial metric input sync: {error}"))?;
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
    let mut logical_sessions: BTreeMap<String, String> = BTreeMap::new();
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
    let mut effect_refs: BTreeMap<String, String> = BTreeMap::new();
    let mut effect_ref_sessions: BTreeMap<String, String> = BTreeMap::new();
    let mut skipped_effect_refs: BTreeSet<String> = BTreeSet::new();
    let mut unbound_redirects = VecDeque::new();
    let mut reset_previous: BTreeMap<String, String> = BTreeMap::new();
    let mut retired_operations: BTreeSet<String> = BTreeSet::new();
    let (_stop, stop) = tokio::sync::watch::channel(false);
    let events = trace["events"].as_array().ok_or("missing events")?;
    for (index, event) in events.iter().enumerate() {
        let logical_id = text(event, "session");
        let op = text(event, "op");
        let mut id = logical_sessions
            .get(logical_id)
            .map_or(logical_id, String::as_str)
            .to_string();
        let logical_actual = id.clone();
        let mut resolved_operation = text(event, "operation").to_string();
        let effect_ref = text(event, "effect_ref");
        let mut skipped_effect = false;
        if !effect_ref.is_empty() && (op == "lookup" || op == "rehydrate") {
            if let Some(operation) = effect_refs.get(effect_ref) {
                resolved_operation = operation.clone();
            } else {
                let delayed = must(effects.lock()).delayed_operation.clone();
                let operation = delayed.ok_or("unknown backend effect")?;
                if !unbound_redirects
                    .iter()
                    .any(|candidate| candidate == &operation)
                {
                    return Err("delayed backend effect left the public queue".into());
                }
                resolved_operation = operation;
                effect_refs.insert(effect_ref.into(), resolved_operation.clone());
            }
            if op == "rehydrate" {
                if let Some(owner) = effect_ref_sessions.get(effect_ref) {
                    if owner != logical_id {
                        return Err("relative backend effect crossed sessions".into());
                    }
                } else {
                    effect_ref_sessions.insert(effect_ref.into(), logical_id.into());
                }
                id = operations
                    .get(&resolved_operation)
                    .ok_or("relative backend operation")?
                    .0
                    .clone();
                swap_logical_session(&mut logical_sessions, logical_id, &id, "relative rehydrate")?;
            } else {
                id.clear();
            }
        } else if !effect_ref.is_empty() {
            let delayed = must(effects.lock()).delayed_operation.clone();
            let mut settled_early = false;
            let mut expired_delay = false;
            if let Some(operation) = effect_refs.get(effect_ref) {
                resolved_operation = operation.clone();
                if effect_ref_sessions.get(effect_ref).map(String::as_str) != Some(logical_id) {
                    return Err("relative callback crossed sessions".into());
                }
                let mut client = must(effects.lock());
                if op == "redirect_result" && client.delayed_operation.as_ref() == Some(operation) {
                    client.delayed_operation = None;
                }
            } else if !skipped_effect_refs.contains(effect_ref) {
                let delay_pending = must(effects.lock()).delay_next > 0;
                let early = must(effects.lock()).delayed_settled_early;
                let mut position = if op == "close" && early {
                    if event["optional_effect"].as_bool() != Some(true) {
                        return Err("early-settled delayed redirect was not optional".into());
                    }
                    must(effects.lock()).delayed_settled_early = false;
                    settled_early = true;
                    None
                } else if op == "close" && delayed.is_some() {
                    unbound_redirects
                        .iter()
                        .position(|operation| Some(operation) == delayed.as_ref())
                } else if op == "close" && delay_pending {
                    if event["optional_effect"].as_bool() != Some(true) {
                        return Err("missing delayed redirect".into());
                    }
                    must(effects.lock()).expire_delay("delayed-close opportunity", index);
                    expired_delay = true;
                    None
                } else {
                    unbound_redirects.iter().position(|operation| {
                        operations.get(operation).is_some_and(|(session, _, _)| {
                            session == &logical_actual
                                && (op == "close" || Some(operation) != delayed.as_ref())
                        })
                    })
                };
                if op == "close" && delayed.is_some() {
                    if position.is_none() {
                        return Err("delayed redirect left the public queue".into());
                    }
                    must(effects.lock()).delayed_operation = None;
                } else if position.is_none()
                    && op == "close"
                    && !delay_pending
                    && !settled_early
                    && !unbound_redirects.is_empty()
                {
                    if unbound_redirects.len() != 1 {
                        return Err("ambiguous strict relative effect".into());
                    }
                    position = Some(0);
                }
                if let Some(position) = position {
                    resolved_operation = unbound_redirects
                        .remove(position)
                        .ok_or("relative effect queue")?;
                    effect_refs.insert(effect_ref.into(), resolved_operation.clone());
                    effect_ref_sessions.insert(effect_ref.into(), logical_id.into());
                }
            } else if effect_ref_sessions.get(effect_ref).map(String::as_str) != Some(logical_id) {
                return Err("relative callback crossed sessions".into());
            }
            if resolved_operation.is_empty() {
                if operations
                    .iter()
                    .any(|(operation, (session, command, completed))| {
                        matches!(command, MigrationCommand::Redirect(_))
                            && session == &logical_actual
                            && !completed
                            && sessions.contains_key(session)
                            && (op == "close" || Some(operation) != delayed.as_ref())
                            && !settled_early
                            && !expired_delay
                    })
                {
                    return Err("relative callback skipped a same-session redirect".into());
                }
                if event["optional_effect"].as_bool() != Some(true) {
                    return Err("unknown relative effect".into());
                }
                if op != "close" {
                    id.clear();
                }
                skipped_effect = true;
                skipped_effect_refs.insert(effect_ref.into());
                effect_ref_sessions.insert(effect_ref.into(), logical_id.into());
            } else {
                id = operations
                    .get(&resolved_operation)
                    .ok_or("relative effect operation")?
                    .0
                    .clone();
            }
            if op == "close" && !skipped_effect {
                swap_logical_session(&mut logical_sessions, logical_id, &id, "relative close")?;
            }
        }
        let mut row =
            json!({"seq":index,"op":op,"session":id,"outcome":"ok","backend":"","effects":[]});
        let elapsed = event["at_nanos"].as_u64().unwrap_or(0);
        let now = start + Duration::from_nanos(elapsed);
        let wall = origin
            .checked_add(i64::try_from(elapsed)?)
            .ok_or("event clock overflow")?;
        h.router.set_replay_wall(wall);
        match op {
            "metrics" => metric_input
                .deliver(event["queries"].clone())
                .map_err(|error| format!("metric input at event {index}: {error}"))?,
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
                metric_input.sync().map_err(|error| {
                    format!("metric input health sync at event {index}: {error}")
                })?;
                let candidate = h
                    .router
                    .capture()
                    .map_err(|e| format!("health apply: {e:?}"))?;
                h.router
                    .refresh_failover(&candidate, now)
                    .map_err(|e| format!("failover: {e:?}"))?;
            }
            "config" => {
                let refusal = event["refuse_next"].as_u64().unwrap_or(0);
                if refusal > 0 {
                    must(effects.lock()).arm_refusal(refusal, index);
                }
                let delay = event["delay_next"].as_u64().unwrap_or(0);
                if delay > 0 {
                    must(effects.lock()).arm_delay(delay, index);
                }
                let relative_toml = if text(event, "fail_backend_ref").is_empty() {
                    None
                } else {
                    let logical = text(event, "fail_backend_ref");
                    let actual = logical_sessions
                        .get(logical)
                        .map_or(logical, String::as_str);
                    let backend = sessions
                        .get(actual)
                        .and_then(|slot| slot.active.as_deref())
                        .ok_or("relative failover requires an active session")?;
                    Some(format!(
                        "[proxy]\nfail-backend-list=[{:?}]\n",
                        backend_address(backend)
                    ))
                };
                let prior_backend_clusters = h.source.store.current().topology()?.backend_clusters;
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
                    if let Some(relative_toml) = relative_toml {
                        h.source
                            .store
                            .apply_toml(
                                relative_toml.as_bytes(),
                                None,
                                u64::try_from(index)? + 4,
                                Path::new("/tmp"),
                            )
                            .map_err(|error| {
                                format!("relative failover config at event {index}: {error}")
                            })?;
                    }
                    let backend_clusters_replaced =
                        h.source.store.current().topology()?.backend_clusters
                            != prior_backend_clusters;
                    h.source.deliver();
                    h.applied().await;
                    // A backend-cluster replacement retires the old routing
                    // source before the following recorded health event
                    // publishes its replacement. That public transient has no
                    // metric snapshot; the next health/metrics input must bind
                    // it, while every other replay-input failure stays fatal.
                    match metric_input.sync() {
                        Ok(()) => {}
                        Err(error)
                            if is_cluster_replacement_metric_gap(
                                error,
                                backend_clusters_replaced,
                            ) => {}
                        Err(error) => {
                            return Err(format!(
                                "metric input config sync at event {index}: {error}"
                            )
                            .into());
                        }
                    }
                    let candidate = h.ready().await;
                    h.router
                        .refresh_failover(&candidate, now)
                        .map_err(|e| format!("failover config: {e:?}"))?;
                    let failover_empty = h
                        .source
                        .store
                        .current()
                        .effective()
                        .routing()?
                        .failed_backends
                        .is_empty();
                    if refusal > 0 || delay > 0 {
                        assert!(
                            !failover_empty,
                            "config effect arm requires a nonempty failover list at event {index}"
                        );
                    }
                    if failover_empty {
                        must(effects.lock()).expire_refusal("failover clear", index);
                        must(effects.lock()).expire_delay("failover clear", index);
                    }
                }
            }
            "open" => {
                let selector = h.router.selector().map_err(|e| format!("open: {e:?}"))?;
                logical_sessions.insert(logical_id.into(), logical_id.into());
                let prior = sessions.insert(
                    logical_id.into(),
                    Slot {
                        selector: Some(selector),
                        pending: None,
                        active: None,
                        client: text(event, "client").into(),
                        proxy: text(event, "proxy").into(),
                        port: text(event, "port").into(),
                    },
                );
                assert!(prior.is_none(), "duplicate logical session");
            }
            "lookup" => {
                let backend = if resolved_operation.is_empty() {
                    text(event, "backend")
                } else {
                    let (_, MigrationCommand::Redirect(redirect), _) = operations
                        .get(&resolved_operation)
                        .ok_or("lookup backend operation")?
                    else {
                        return Err("lookup backend effect is not a redirect".into());
                    };
                    redirect.to().backend_id.as_str()
                };
                match h.router.lookup_backend(backend) {
                    Ok(assignment) => row["backend"] = json!(assignment.backend_id),
                    Err(RouteError::NoBackend) => row["outcome"] = json!("unknown_backend"),
                    Err(error) => row["outcome"] = json!(outcome(error)),
                }
            }
            "rehydrate" => {
                let s = sessions.get_mut(&id).ok_or("missing session")?;
                let backend = if text(event, "backend_ref") == "previous" {
                    reset_previous
                        .get(&id)
                        .ok_or("missing pre-reset assignment")?
                        .as_str()
                } else if !resolved_operation.is_empty() {
                    let (_, MigrationCommand::Redirect(redirect), _) = operations
                        .get(&resolved_operation)
                        .ok_or("rehydrate backend operation")?
                    else {
                        return Err("rehydrate backend effect is not a redirect".into());
                    };
                    redirect.to().backend_id.as_str()
                } else {
                    text(event, "backend")
                };
                match s
                    .selector
                    .as_ref()
                    .ok_or("missing fresh selector")?
                    .rehydrate(backend)
                {
                    Ok(assignment) => {
                        row["backend"] = json!(assignment.backend_id);
                        s.active = Some(assignment.backend_id);
                        must(effects.lock())
                            .names
                            .insert(assignment.connection_id, id.clone());
                        reset_previous.remove(&id);
                    }
                    Err(RouteError::NoBackend) => row["outcome"] = json!("unknown_backend"),
                    Err(error) => row["outcome"] = json!(outcome(error)),
                }
            }
            "router_reset" => {
                if !reset_previous.is_empty() {
                    return Err("router reset while one is unfinished".into());
                }
                for (session, slot) in &mut sessions {
                    if slot.pending.is_some() {
                        return Err("router reset with a pending reservation".into());
                    }
                    let backend = slot
                        .active
                        .take()
                        .ok_or("router reset with an inactive session")?;
                    reset_previous.insert(session.clone(), backend);
                    drop(slot.selector.take());
                }
                if reset_previous.is_empty() {
                    return Err("router reset requires a live assignment".into());
                }
                retired_operations.extend(
                    operations
                        .iter()
                        .filter(|(_, (_, _, completed))| !completed)
                        .map(|(operation, _)| operation.clone()),
                );
                h.router = Arc::new(
                    Router::new_with_factors(
                        Arc::new(h.source.clone()),
                        &h.topology,
                        &h.runtime.handle().module_context(),
                        "default",
                        100_000,
                        Some(metric_input.handle()),
                    )
                    .map_err(|e| format!("router reset init: {e:?}"))?,
                );
                h.router.set_replay_wall(wall);
                for slot in sessions.values_mut() {
                    slot.selector = Some(
                        h.router
                            .selector()
                            .map_err(|e| format!("router reset selector: {e:?}"))?,
                    );
                }
            }
            "tick" => {
                {
                    let mut client = must(effects.lock());
                    client.refused = event["refuse"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|v| {
                            let logical = v.as_str().unwrap_or_default();
                            logical_sessions
                                .get(logical)
                                .map_or(logical, String::as_str)
                                .to_string()
                        })
                        .collect();
                    let refusal = event["refuse_next"].as_u64().unwrap_or(0);
                    if refusal > 0 {
                        client.arm_refusal(refusal, index);
                    }
                }
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
                        if effect["kind"] == "redirect" {
                            unbound_redirects.push_back(text(&effect, "operation").into());
                        }
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
                if skipped_effect {
                    row["outcome"] = json!("no_effect");
                    output.push(row);
                    continue;
                }
                unbound_redirects.retain(|operation| operation != &resolved_operation);
                let (session, command, completed) = operations
                    .get_mut(&resolved_operation)
                    .ok_or("unknown operation")?;
                let MigrationCommand::Redirect(redirect) = command else {
                    return Err("not a redirect".into());
                };
                let success = event["success"].as_bool().ok_or("missing success")?;
                let settlement = h.router.finish_redirect(redirect, success, now);
                if retired_operations.remove(&resolved_operation) {
                    assert_eq!(settlement, Settlement::Ignored);
                    if success && let Some(s) = sessions.get_mut(session) {
                        s.active = Some(redirect.to().backend_id.clone());
                    }
                } else if !*completed && let Some(s) = sessions.get_mut(session) {
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
                let s = sessions.get_mut(&id).ok_or("missing session")?;
                let client = ClientInfo {
                    client_address: (!s.client.is_empty()).then_some(s.client.as_str()),
                    proxy_address: (!s.proxy.is_empty()).then_some(s.proxy.as_str()),
                };
                match s
                    .selector
                    .as_mut()
                    .ok_or("missing selector")?
                    .next(client, &s.port)
                {
                    Ok(reservation) => {
                        row["backend"] = json!(reservation.assignment().backend_id);
                        must(effects.lock())
                            .names
                            .insert(reservation.assignment().connection_id, id.clone());
                        s.pending = Some(reservation);
                    }
                    Err(error) => row["outcome"] = json!(outcome(error)),
                }
            }
            "finish" => {
                let s = sessions.get_mut(&id).ok_or("missing session")?;
                let pending = s.pending.take().ok_or("missing reservation")?;
                let connected = event["success"].as_bool().unwrap_or(false);
                assert_eq!(
                    s.selector
                        .as_ref()
                        .ok_or("missing selector")?
                        .finish(&pending, connected),
                    Settlement::Applied
                );
                s.active = connected.then(|| pending.assignment().backend_id.clone());
            }
            "close" => {
                let s = sessions.remove(&id).ok_or("missing session")?;
                assert!(
                    s.pending.is_none(),
                    "pending creation requires its Finish callback"
                );
                drop(s);
                if skipped_effect {
                    row["outcome"] = json!("no_effect");
                }
                let delayed = must(effects.lock()).delayed_operation.clone();
                if delayed.as_ref().is_some_and(|operation| {
                    operations
                        .get(operation)
                        .is_some_and(|(session, _, _)| session == &id)
                }) {
                    let mut client = must(effects.lock());
                    client.delayed_operation = None;
                    client.delayed_settled_early = true;
                }
                unbound_redirects.retain(|operation| {
                    operations
                        .get(operation)
                        .is_none_or(|(session, _, _)| session != &id)
                });
                let close_settled: Vec<String> = operations
                    .iter_mut()
                    .filter_map(|(operation, (session, _, completed))| {
                        if session != &id {
                            return None;
                        }
                        *completed = true;
                        Some(operation.clone())
                    })
                    .collect();
                for operation in close_settled {
                    retired_operations.remove(&operation);
                }
                logical_sessions.remove(logical_id);
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
    assert!(
        logical_sessions.is_empty(),
        "trace must close every logical handle"
    );
    assert!(
        reset_previous.is_empty(),
        "trace must rehydrate every reset survivor"
    );
    assert!(
        retired_operations.is_empty(),
        "trace must settle every pre-reset operation"
    );
    assert!(
        unbound_redirects.is_empty(),
        "trace must close or bind every accepted redirect"
    );
    let event_count = trace["events"].as_array().ok_or("events")?.len();
    must(effects.lock()).expire_refusal("trace end", event_count);
    must(effects.lock()).expire_delay("trace end", event_count);
    assert!(
        must(effects.lock()).delayed_operation.is_none(),
        "trace ended before the delayed callback close"
    );
    assert!(
        !must(effects.lock()).delayed_settled_early,
        "trace ended before the strict delayed-close opportunity"
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

#[test]
fn replay_metric_gap_is_bounded_to_backend_cluster_replacement() {
    assert!(is_cluster_replacement_metric_gap(
        "metric input source unavailable",
        true
    ));
    assert!(!is_cluster_replacement_metric_gap(
        "metric input source unavailable",
        false
    ));
    assert!(!is_cluster_replacement_metric_gap(
        "metric input publication retired",
        true
    ));
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
    assert_eq!(result.updated_nanos, Some(0));
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
    packet["cpu"]["updated_nanos"] = Value::Null;
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
        None
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
