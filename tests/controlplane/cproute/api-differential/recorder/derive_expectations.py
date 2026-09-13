#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Derive trace v1 `expect` blocks from recorded public inputs (contract a9c497c3 §2).

Input : a recorded trace (events without `expect`) and the recorded Go rows for the same
        events (output evidence: per-event outcome/backend/effects).
Output: the trace with `expect` per event, plus a `requires` list naming every runner
        dependency the slot needs before it can count (effects-v2,
        migration-cadence, metrics-input, policy-constraint:<pair>).
        Dependencies are decided from the
        public inputs and their history, never from what the recorded output happened to be.

Rules (README §2, rev 3): Next / Lookup / Rehydrate are derived separately; error classes map
1:1 from inputs; ordinary exhaustion is the exact `no_backend`; every unexplained outcome,
backend or effect is refused (exit 2 naming the seq) — never "whatever was recorded".

Public semantics mirrored (file:line at the reviewed tree):
- selector exclusions are backend identities per attempt cycle; the reset happens only when
  the legal candidates minus the *actual* excluded identities are empty and the exclusion
  list is non-empty, and it also happens on an exact `ErrNoBackend` observer error
  (backend_selector.go:24-37, router_score.go:127-130).
- routing: observed-healthy, not in active failover, member of the routed group, not
  excluded (group.go:352-386); the `random` selection may return any of them
  (factor_balance.go:255-279); `prefer-idle` evicts by factor advice and is derivable
  from public inputs plus each engine's own public connection history for `connection`.
  Bounded two-backend Resource/prefer-idle choices and migration ticks are
  derived from whole public CPU, memory and health metric packets. Resource/
  Location prefer-idle also reduces to the public connection ledger when the
  complete factor lifetime proves no CPU/memory data, only normal health, and
  equal locality within the routed group; other advice remains a constraint.
- failover guard is evaluated per group: the list is ignored for a group only when it would
  leave that group without a routeable backend (group.go:286-341); the timeout does not
  gate the marking (router.go:160-165, Healthy = observed && not in failover).
- retention: a backend enters `router.backends` when first consumed healthy; it leaves when
  consumed unhealthy/absent and idle — no listed connection, no pending reservation, no
  in-flight redirect score (router_score.go:264, 340-356, group.go:222-238). Rehydrate
  additionally needs group ownership (group.go:514-520).
- Connection-factor migration: a relative expectation carries only input-derived
  groups, health, keyspace and Status scoring calls. The common runner combines it
  with each engine's own active assignments to determine the pair, rate, physical
  insertion order, accepted-request cadence, one-shot refusal and failure cooldown.
  Closed random histories do not poison later ownership. Ambiguous group lifetimes,
  incomplete Status scoring and alternatives outside the bounded model remain
  dependencies. Resource/Location reduce to this path only when their complete
  metric-factor lifetime proves all higher-priority scores equal.
- Resource migration: the same rules are derived for a complete two-backend,
  single-group public metric history; unsupported factor calls remain dependencies.
"""

import argparse
import copy
from collections import Counter
import importlib.util
import ipaddress
import json
import math
import sys
import tomllib
from pathlib import Path

# Use the common comparator's public-history constraint for recorded Go validation.
# It consumes Go's own outputs only; emitted expectations never contain that ledger.
_RUNNER_SPEC = importlib.util.spec_from_file_location("api_runner", Path(__file__).resolve().parents[1] / "run.py")
_RUNNER = importlib.util.module_from_spec(_RUNNER_SPEC)
_RUNNER_SPEC.loader.exec_module(_RUNNER)

SOURCE_ERROR_MAP = {
    "no_backend": "no_backend",
    "wrapped_no_backend": "wrapped_no_backend",
    "port_conflict": "port_conflict",
    "topology_unavailable": "source_error:topology_unavailable",
    "cancelled": "source_error:cancelled",
    "deadline_exceeded": "source_error:deadline_exceeded",
}
PORT_LABEL = "tiproxy-port"
CIDR_RULES = {"client_cidr", "proxy_cidr"}
METRIC_POLICIES = {"resource", "location"}  # factor lists include health/memory/cpu (factor_balance.go:117-120)
UNSUPPORTED_CONFIG_KEYS = (("balance", "label-name"), ("labels",))  # label isolation: not specified for derivation


class Refuse(Exception):
    pass


def backend_id(b):
    cluster = b.get("cluster", "default")
    return f"{cluster}/{b['address']}" if cluster else b["address"]


def parse_toml(toml):
    """Full TOML parse (tomllib). Returns the document; refuses unsupported routing inputs."""
    try:
        doc = tomllib.loads(toml)
    except tomllib.TOMLDecodeError as e:
        raise Refuse(f"config TOML does not parse ({e}); the validator accepted it, so the deriver cannot follow it")
    for path in UNSUPPORTED_CONFIG_KEYS:
        node = doc
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if node is not None:
            raise Refuse(f"config key {'.'.join(path)} affects routing and is not specified for derivation")
    return doc


def toml_get(doc, *path):
    node = doc
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def cidr_values(backend):
    return frozenset(v.strip() for v in backend.labels.get("cidr", "").split(",") if v.strip())


def parse_cidrs(values):
    """Public label parsing, including Go's /32 default for bare IPv6 addresses.

    An invalid list rejects a new group. Refresh keeps the previously parsed list
    on any error, even though the group's textual values have already changed.
    """
    networks = []
    for value in values:
        text = value if "/" in value else value + "/32"
        prefix = text.rpartition("/")[2]
        if not prefix.isascii() or not prefix.isdecimal() or "%" in text:
            return None
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None
        if network.version == 6 and network.network_address.ipv4_mapped is not None:
            network = ipaddress.ip_network((network.network_address.ipv4_mapped, network.prefixlen - 96))
        networks.append(network)
    return networks


def address_ip(value):
    """Literal host from the public net.Addr string; no DNS or port validation."""
    if value.startswith("["):
        host, sep, port = value[1:].partition("]:")
        if not sep or any(c in port for c in "[]:"):
            return None
    else:
        host, sep, port = value.rpartition(":")
        if not sep or any(c in host + port for c in "[]:"):
            return None
    if "%" in host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return (ip.ipv4_mapped or ip) if ip.version == 6 else ip


class Backend:
    __slots__ = ("id", "address", "ip", "status_port", "cluster", "keyspace", "labels", "local", "observed_healthy", "version", "group", "ambiguous", "failover_since", "support_redirection")

    def __init__(self, bid, b):
        self.id = bid
        self.group = None
        self.ambiguous = False
        self.failover_since = None  # logical instant the backend entered failover (kept while marked)
        self.update(b)

    def update(self, b):
        self.address = b["address"]
        self.ip = b.get("ip", "")
        self.status_port = b.get("status_port", 0)
        self.cluster = b.get("cluster", "default")
        self.keyspace = b.get("keyspace", "")
        self.labels = dict(b.get("labels", {}) or {})
        self.local = bool(b.get("local", True))
        self.support_redirection = bool(b.get("support_redirection", True))
        self.observed_healthy = bool(b.get("healthy", True))
        if self.observed_healthy:
            self.ambiguous = False  # consumed healthy: present in the router again, whatever the ledger said
        self.version = b.get("server_version", "")


class Session:
    __slots__ = ("id", "port", "client", "proxy", "cycle", "relative_history", "pending", "assigned", "inflight", "force_closing", "ordinal", "created", "last_redirect", "redirect_failed")

    def __init__(self, sid, event):
        self.id = sid
        self.port = event.get("port", "")
        self.client = event.get("client", "")
        self.proxy = event.get("proxy", "")
        self.cycle = []  # [(backend_id, unique)] excluded identities of the current attempt cycle
        # A reset in Go need not coincide with a reset in the other engine.
        # Keep history relative until a public exact-no-backend resets both.
        self.relative_history = False
        self.pending = None  # frozenset of possible reserved backends (Next ok, Finish not yet)
        self.assigned = None  # frozenset of possible current assignments
        self.inflight = None  # frozenset of possible redirect destinations holding the score
        self.force_closing = False  # an accepted force_close was issued (group.go:566-569)
        self.ordinal = 0  # effects issued on this session so far (operation = "<session>/<n>")
        self.created = 0  # seq of the successful Finish (connList order)
        self.last_redirect = None  # public request time, not callback time
        self.redirect_failed = False

    def possible(self):
        out = set()
        for s in (self.pending, self.assigned, self.inflight):
            if s:
                out |= s
        return out

    def sure(self):
        out = set()
        for s in (self.pending, self.assigned, self.inflight):
            if s and len(s) == 1:
                out |= s
        return out


class State:
    def __init__(self, config, provenance=None):
        provenance = provenance or {}
        # Preserve the conservative flag on older recorded traces. New whole
        # publications below also mark actual data directly from public inputs;
        # removable provenance cannot hide their replay dependency.
        self.metrics_observed = bool(provenance.get("metrics_observed", provenance.get("kind") == "recorded"))
        self.rule = config["rule"]  # fixed at Init (router_score.go:90)
        self.policy = config["policy"]
        self.selection = config["selection"]
        self.backends = {}  # router.backends: id -> Backend
        self.groups = {}  # group value -> set(ids); MatchAll uses ""
        self.group_epochs = {}  # public-model identity; changes when a group is destroyed/recreated
        self.next_group_epoch = 0
        self.cidr_values = {}
        self.cidr_networks = {}
        self.next_cidr_group = 0
        self.ignore_failover = {}  # group value -> bool
        self.failover = set()  # ids currently marked (Healthy() false)
        self.observer_error = None
        self.support_redirection = False
        self.fail_list = set()
        self.failover_timeout = 60  # lib/config/proxy.go:171 default; seconds
        self.now = 0  # logical clock of the event being consumed
        self.sessions = {}
        self.unique_history = True
        self.requires = set()
        self.retained_version = ""
        self.recorded_connections = _RUNNER.PublicConnections(config)
        self.group_last_redirect = {}  # only accepted requests advance a group's cadence
        self.ambiguous_group_clocks = set()
        self.redirect_operations = {}  # public accepted operation handles and their settlement
        self.operation_refs = {}  # recorded operation -> engine-relative accepted-effect reference
        self.ref_operations = {}  # inverse map for already-relative recorder inputs
        self.accepted_redirects = 0
        # group -> backend -> (input-derived rate or None when an engine-relative
        # owner made the retained rate unknowable, last scoring time)
        self.status_snapshots = {}
        self.status_calls = []  # input-derived scoring calls made while consuming one event
        self.status_rate = 0.0
        self.clock_origin = config.get("clock_origin_nanos", 1_700_000_000_000_000_000)
        self.metric_queries = None  # latest whole public metrics publication
        self.resource_rates = {"health": 0.0, "memory": 0.0, "cpu": 0.0, "location": 0.0}
        self.reset_resource_metrics()
        self.resource_metric_history_trusted = True
        if self.rule not in {"", "port"} | CIDR_RULES:
            self.requires.add(f"policy-constraint:{self.rule}")

    # --- helpers -------------------------------------------------------------------------
    def held_possible(self, bid):
        return any(bid in s.possible() for s in self.sessions.values())

    def relative_history_active(self):
        return any(session.relative_history for session in self.sessions.values())

    def held_sure(self, bid):
        return any(bid in s.sure() for s in self.sessions.values())

    def group_value(self, b):
        if self.rule == "":
            return ""
        if self.rule == "port":
            port = b.labels.get(PORT_LABEL, "")
            if not port:
                return None
            return f"{b.cluster}:{port}" if b.cluster else port
        raise Refuse(f"routing rule {self.rule!r} derivation not specified")

    def healthy(self, bid):
        b = self.backends[bid]
        return b.observed_healthy and bid not in self.failover

    def ensure_group(self, value):
        if value not in self.groups:
            self.groups[value] = set()
            self.next_group_epoch += 1
            self.group_epochs[value] = f"group/{self.next_group_epoch}"
        return self.groups[value]

    # --- inputs (router_score.go updateBackendHealth / updateGroups / group.UpdateFailover) ---
    def apply_health(self, backends):
        prime_resource = False
        if self.metric_queries is not None and self.policy in METRIC_POLICIES:
            # Health delivery scores observed and proposed failover views. A
            # stable bounded Resource group can consume those public calls;
            # topology/failover changes remain explicit dependencies.
            prime_resource = _stable_resource_health_update(self, backends)
            self.resource_metric_history_trusted &= prime_resource
        self.observer_error = None
        seen = {}
        for raw in backends:
            bid = backend_id(raw)
            seen[bid] = raw
            if bid in self.backends:
                self.backends[bid].update(raw)
            elif raw.get("healthy", True):
                self.backends[bid] = Backend(bid, raw)
            # an unhealthy backend that was never healthy is not in the router (router_score.go:277-279)
        for bid, b in self.backends.items():
            if bid not in seen:
                b.observed_healthy = False  # removed from the list → unhealthy (router_score.go:242-254)
        # Go includes every delivered entry and the previous capability of
        # removed retained entries in its whole-result capability conjunction.
        self.support_redirection = all(raw.get("support_redirection", True) for raw in seen.values()) and all(
            b.support_redirection for bid, b in self.backends.items() if bid not in seen
        )
        self.update_groups()
        self.update_failover()
        if prime_resource and self.resource_metric_history_trusted:
            # With no fail list both routeable views contain the same members.
            # The second real scoring call sees the same metric timestamps, so
            # the first complete factor update determines the retained state.
            self.resource_metric_history_trusted &= _prime_resource_scoring(self)
        versions = [b.version for b in self.backends.values() if b.observed_healthy and b.version]
        if versions:
            self.retained_version = versions[-1]

    def update_groups(self):
        old_groups = set(self.groups)
        ambiguous_clocks = set(self.ambiguous_group_clocks)
        if self.rule not in CIDR_RULES:
            # Go walks a map: admitting a replacement before removing the last
            # old member preserves the group clock; reversing that order resets
            # it. A whole input must not silently choose either private order.
            fresh_values = {self.group_value(b) for b in self.backends.values()
                            if b.group is None and b.observed_healthy}
            for group, members in self.groups.items():
                if (group in fresh_values and group in self.group_last_redirect
                        and all(not self.backends[bid].observed_healthy
                                and not self.held_possible(bid) for bid in members)):
                    ambiguous_clocks.add(group)
        for bid in list(self.backends):
            b = self.backends[bid]
            if not b.observed_healthy:
                if not self.held_possible(bid):
                    self.remove_backend(bid)
                    continue
                if not self.held_sure(bid):
                    b.ambiguous = True  # retention depends on an engine-relative assignment
            if b.group is None and self.rule not in CIDR_RULES:
                value = self.group_value(b)
                if value is not None:
                    b.group = value
                    self.ensure_group(value).add(bid)
        if self.rule in CIDR_RULES:
            self.update_cidr_groups(old_groups - set(self.groups))
        self.ambiguous_group_clocks = ambiguous_clocks & set(self.groups)

    def update_cidr_groups(self, removed):
        # Admission uses previous group values; RefreshCidr runs only after the
        # complete update. Never use recorded Go group choices or map order.
        fresh = [(bid, cidr_values(b)) for bid, b in self.backends.items() if b.group is None and cidr_values(b)]
        if any(b.ambiguous for b in self.backends.values()):
            raise Refuse("CIDR membership depends on engine-relative retention")
        if removed and fresh:
            raise Refuse("simultaneous CIDR group removal/admission needs an order-independent constraint")
        destinations = {}
        for bid, values in fresh:
            matches = [g for g, prior in self.cidr_values.items() if prior & values]
            if len(matches) > 1:
                raise Refuse("CIDR admission intersects multiple retained groups")
            destinations[bid] = matches[0] if matches else None
        for i, (left, lv) in enumerate(fresh):
            for right, rv in fresh[i + 1:]:
                # A newly created group can win before a retained one or split
                # a chain of intersecting labels, depending on map iteration.
                if lv & rv and (destinations[left] is None or destinations[right] is None) and lv != rv:
                    raise Refuse("CIDR admission depends on new-backend traversal order")
        created = {}
        for bid, values in fresh:
            group = destinations[bid]
            if group is None:
                parsed = parse_cidrs(values)
                if parsed is None:
                    continue
                group = created.get(values)
                if group is None:
                    self.next_cidr_group += 1
                    group = f"cidr/{self.next_cidr_group}"
                    created[values] = group
                    self.ensure_group(group)
                    self.cidr_networks[group] = parsed
            self.backends[bid].group = group
            self.groups[group].add(bid)
        for group, members in self.groups.items():
            values = frozenset(v for bid in members for v in cidr_values(self.backends[bid]))
            self.cidr_values[group] = values
            parsed = parse_cidrs(values)
            if parsed is not None:
                self.cidr_networks[group] = parsed

    def remove_backend(self, bid):
        b = self.backends.pop(bid)
        if b.group is not None:
            members = self.groups.get(b.group)
            if members is not None:
                members.discard(bid)
                if not members:
                    del self.groups[b.group]
                    self.ignore_failover.pop(b.group, None)
                    self.cidr_values.pop(b.group, None)
                    self.cidr_networks.pop(b.group, None)
                    self.group_last_redirect.pop(b.group, None)
                    self.status_snapshots.pop(b.group, None)
                    self.group_epochs.pop(b.group, None)

    def reset_resource_metrics(self):
        """Mirror destruction/recreation of Resource factors on policy transitions."""
        self.cpu_last_metric = None  # None is Go's year-one zero time, distinct from Unix epoch 0
        self.cpu_snapshots = {}  # backend -> (sample ms, average, latest, score count)
        self.cpu_usage_per_conn = 0.0
        self.memory_last_metric = None
        self.memory_snapshots = {}  # backend -> (sample ms, usage, time-to-OOM ns, risk, rate)
        self.health_query_updates = {key: None for key in ("failure_pd", "total_pd", "failure_tikv", "total_tikv")}
        self.health_query_results = {}
        self.health_snapshots = {}  # backend -> (updated ns, range, retained rate)
        # Empty current CPU/memory results do not clear the real factor caches.
        # Only qualify the no-data reduction when the complete lifetime since
        # factor creation has been empty for both inputs.
        self.metric_cpu_memory_history_empty = True
        # A deliberately narrower invariant than the complete Resource model:
        # when every health sample ever visible to the current metric-policy
        # factors was normal, health cannot outrank the connection factor even
        # after engine-relative retry exclusions. Once disproved, keep it
        # false until the factors are recreated; a later packet may have first
        # been consumed by a different candidate subset in each engine.
        self.metric_health_history_neutral = True

    def apply_config(self, toml):
        old_policy = self.policy
        doc = parse_toml(toml)
        v = toml_get(doc, "proxy", "fail-backend-list")
        if v is not None:
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise Refuse("proxy.fail-backend-list must be an array of strings")
            self.fail_list = set(v)
        v = toml_get(doc, "proxy", "failover-timeout")
        if v is not None:
            if not isinstance(v, (int, float)) or v < 0:
                raise Refuse("proxy.failover-timeout must be a non-negative number")
            self.failover_timeout = v
        v = toml_get(doc, "balance", "policy")
        if v is not None:
            self.policy = v
        v = toml_get(doc, "balance", "routing-policy")
        if v is not None:
            self.selection = v
        v = toml_get(doc, "balance", "status", "migrations-per-second")
        if v is not None:
            if type(v) not in (int, float) or not math.isfinite(v) or v < 0:
                raise Refuse("balance.status.migrations-per-second must be finite and non-negative")
            self.status_rate = float(v)
        for factor in ("health", "memory", "cpu", "location"):
            v = toml_get(doc, "balance", factor, "migrations-per-second")
            if v is not None:
                if type(v) not in (int, float) or not math.isfinite(v) or v < 0:
                    raise Refuse(f"balance.{factor}.migrations-per-second must be finite and non-negative")
                self.resource_rates[factor] = float(v)
        old_metric, new_metric = old_policy in METRIC_POLICIES, self.policy in METRIC_POLICIES
        if old_metric != new_metric:
            self.reset_resource_metrics()
            self.resource_metric_history_trusted = True
        if new_metric and self.metric_queries is not None:
            # Group.SetConfig scores the observed view while refreshing its
            # failover mask. Mirror that factor call when the group shape is in
            # the same bounded model; otherwise keep later routing explicit.
            self.resource_metric_history_trusted &= _prime_resource_scoring(self)
        # balance.routing-rule at runtime is ignored by the router (matchType fixed at Init).
        self.update_failover()

    def apply_metrics(self, queries):
        self.metric_queries = copy.deepcopy(queries)
        self.metrics_observed |= any(result is not None and result["series"] for result in queries.values())
        if self.policy in METRIC_POLICIES:
            self.metric_cpu_memory_history_empty &= all(
                queries[key] is None or not queries[key]["series"] for key in ("cpu", "memory"))
            self.metric_health_history_neutral &= _public_health_packet_neutral(self)

    def update_failover(self):
        """group.go:286-341 per group; Healthy() = observed && not marked (router.go:160-165).
        failoverSince is set when a backend enters failover and kept while it stays marked
        (router.go:178-190); it is the logical clock of the consuming event."""
        marked_now = set()
        for value, members in self.groups.items():
            routeable = [bid for bid in members if self.backends[bid].observed_healthy]
            marked = {bid for bid in members if self.backends[bid].address in self.fail_list}
            # The real guard scores observed members once as healthy, then
            # with the proposed failover mask, before committing that mask.
            self.update_connection_status(value, {bid: True for bid in routeable})
            if routeable:
                self.update_connection_status(value, {bid: bid not in marked for bid in routeable})
            remaining = [bid for bid in routeable if bid not in marked]
            if routeable and not remaining:
                self.ignore_failover[value] = True
                continue
            self.ignore_failover[value] = False
            marked_now |= marked
        for bid, b in self.backends.items():
            if bid in marked_now:
                if b.failover_since is None:
                    b.failover_since = self.now
            else:
                b.failover_since = None
        self.failover = marked_now

    def connection_counts(self):
        counts, physical = Counter(), Counter()
        for session in self.sessions.values():
            if session.pending and len(session.pending) == 1:
                counts[next(iter(session.pending))] += 1
            if session.assigned and len(session.assigned) == 1:
                owner = next(iter(session.assigned))
                physical[owner] += 1
                counts[owner] += 1
                if session.inflight and len(session.inflight) == 1:
                    counts[owner] -= 1
                    counts[next(iter(session.inflight))] += 1
        return counts, physical

    def update_connection_status(self, group, health):
        """Public scoring calls determine status rate retention and strict expiry."""
        if not health or self.policy not in {"connection"} | METRIC_POLICIES:
            return
        self.status_calls.append({"group": self.group_epochs[group],
                                  "health": dict(sorted(health.items()))})
        snapshots = self.status_snapshots.setdefault(group, {})
        counts, _ = self.connection_counts()
        uncertain = set()
        for session in self.sessions.values():
            for owners in (session.pending, session.assigned, session.inflight):
                if owners and len(owners) != 1:
                    uncertain.update(owners)
        for bid, healthy in health.items():
            if healthy:
                snapshots.pop(bid, None)
                continue
            rate, _ = snapshots.get(bid, (0.0, 0))
            # FactorStatus retains a positive balance count. If the retained
            # value is zero it is recomputed from the current ConnScore; an
            # engine-relative owner therefore makes this snapshot unknowable
            # even after that session later closes.
            if rate is None or rate > 0.0001:
                next_rate = rate
            elif bid in uncertain:
                next_rate = None
            else:
                next_rate = float(counts[bid]) / 5.0
            snapshots[bid] = (next_rate, self.now)
        for bid, (_, accessed) in list(snapshots.items()):
            if accessed + 60_000_000_000 < self.now:
                del snapshots[bid]

    # --- derived sets ---------------------------------------------------------------------
    def routed_group(self, session):
        """router_score.go:201-215: the group for this client, or a port conflict."""
        if self.rule == "":
            return self.groups.get(""), None
        if self.rule == "port":
            owners = {}
            for value, members in self.groups.items():
                cluster, _, port = value.rpartition(":")
                if port == session.port:
                    owners[cluster] = members
            if len(owners) > 1:
                return None, "port_conflict"
            return (next(iter(owners.values())) if owners else None), None
        if self.rule in CIDR_RULES:
            ip = address_ip(session.client if self.rule == "client_cidr" else session.proxy)
            matches = [g for g, networks in self.cidr_networks.items() if ip is not None and any(ip in net for net in networks)]
            if len(matches) > 1:
                raise Refuse("CIDR route matches multiple groups; traversal order is not an expectation")
            return (self.groups[matches[0]] if matches else None), None
        raise Refuse(f"routing rule {self.rule!r} derivation not specified")

    def candidates(self, session):
        """Healthy members of the routed group (group.go:359-364), before exclusions."""
        members, conflict = self.routed_group(session)
        if conflict:
            return None, conflict
        if not members:
            return [], None
        return sorted(bid for bid in members if self.healthy(bid)), None

    def routable_ids(self):
        return [bid for bid in self.backends if self.healthy(bid)]

    def group_healthy(self, bid):
        b = self.backends.get(bid)
        if b is None or b.group is None:
            return set()
        return {m for m in self.groups.get(b.group, ()) if self.healthy(m)}

    def migration_targets(self, bid):
        """Necessary destinations, not the factor's chosen pair or advice."""
        source = self.backends.get(bid)
        if source is None:
            return set()
        # Balance refuses its whole chosen pair when the current public
        # keyspaces differ, including legacy empty versus a named keyspace.
        # A compatible alternative does not guarantee that Balance selects
        # it: retain migration-cadence whenever any legal pair is possible.
        return {target for target in self.group_healthy(bid) - {bid}
                if self.backends[target].keyspace == source.keyspace}


def key_effects(effects):
    return sorted((e["kind"], e["session"], e["operation"], e["from"], e["to"], bool(e["accepted"])) for e in effects)


def derive_connection_redirects(state, refused):
    """Predict connection-factor balance from exact active public ownership.

    None means the existing migration dependency is still required. In particular,
    a recorded choice or an unverified earlier migration must not select a pair or
    seed this clock. Closed ambiguous sessions do not poison a later exact active
    ledger. Resource/Location enter this path only when their complete metric-factor
    lifetime proves every higher-priority factor equal. Tied pairs are resolved only
    if every choice has the same observable effects; otherwise no observed Go effect
    is turned into an oracle.
    """
    if (state.policy not in {"connection"} | METRIC_POLICIES
            or "migration-cadence" in state.requires
            or state.ambiguous_group_clocks
            or state.recorded_connections.label_name
            or any(b.ambiguous for b in state.backends.values())):
        return None
    if any(len(owners) != 1 for s in state.sessions.values()
           for owners in (s.pending,s.assigned,s.inflight) if owners):
        return None
    counts, physical = state.connection_counts()
    out = []
    ratio, override = state.recorded_connections.ratio, state.recorded_connections.rate
    for group,members in sorted(state.groups.items()):
        if len(members) <= 1:
            continue
        if (state.policy in METRIC_POLICIES
                and not metric_factors_are_connection_only(state, sorted(members))):
            return None
        bits = {bid:(int(not state.healthy(bid)), min(counts[bid],65535)) for bid in members}
        minimum = min(bits.values())
        if minimum[0]:
            continue  # status forbids migration to an unhealthy target
        alternatives = []
        for target in sorted(bid for bid in members if bits[bid] == minimum):
            sources = []
            for source in members:
                if bits[source] <= minimum or physical[source] == 0 or counts[source] <= 0:
                    continue
                if not state.healthy(source):
                    snapshot = state.status_snapshots.get(group, {}).get(source)
                    if snapshot is None or snapshot[0] is None:
                        return None
                    rate = state.status_rate if state.status_rate > 0 else snapshot[0]
                else:
                    if float(counts[source]) <= float(counts[target] + 1) * ratio:
                        continue
                    rate = override if override > 0 else max(
                        0.0, (float(counts[source] + counts[target] + 1) / (1 + ratio) - float(counts[target] + 1)) / 120)
                if rate > 0.0001:
                    sources.append((source,rate))
            if not sources:
                alternatives.append([])
                continue
            busiest = max(bits[source] for source,_ in sources)
            for source,rate in sorted(sources):
                if bits[source] != busiest:
                    continue
                effects = []
                if state.backends[source].keyspace != state.backends[target].keyspace:
                    alternatives.append(effects)  # the whole pair is skipped, with no fallback
                    continue
                interval = int(1_000_000_000.0 / rate)  # Go float64 -> Duration truncation
                if interval <= 0:
                    return None  # the existing dependency covers unsupported arithmetic
                last = state.group_last_redirect.get(group)
                if interval < 20_000_000:
                    budget = (10_000_000 - 1) // interval + 1
                elif last is None or state.now - last >= interval:
                    budget = 1
                else:
                    alternatives.append(effects)
                    continue
                # Physical insertion order is observable through Finish,
                # Rehydrate and the successful completion of a redirect.
                for session in sorted(state.sessions.values(), key=lambda s:s.created):
                    if budget == 0:
                        break
                    if session.assigned != frozenset([source]) or session.force_closing or session.inflight:
                        continue
                    if (session.redirect_failed and session.last_redirect is not None
                            and state.now < session.last_redirect + 3_000_000_000):
                        continue
                    accepted = session.id not in refused
                    effects.append({"kind":"redirect", "session":session.id,
                                    "operation":f"{session.id}/{session.ordinal + 1}",
                                    "from":source, "to":target, "accepted":accepted})
                    budget -= int(accepted)
                alternatives.append(effects)
        if any(_RUNNER.causal(effects) != _RUNNER.causal(alternatives[0]) for effects in alternatives[1:]):
            return None
        out.extend(alternatives[0])
    return out


def connection_cadence_model(state):
    """Describe the bounded migration model without choosing engine owners.

    The common runner supplies each engine's public Next/Finish/callback ledger.
    This descriptor contributes only input-derived group membership, health,
    keyspace and the proof that every higher-priority factor is neutral.
    """
    if (state.policy not in {"connection"} | METRIC_POLICIES
            or state.ambiguous_group_clocks or state.recorded_connections.label_name
            or any(backend.ambiguous for backend in state.backends.values())):
        return None
    groups = []
    for group, members in sorted(state.groups.items()):
        members = sorted(members)
        if (state.policy in METRIC_POLICIES and len(members) > 1
                and not metric_factors_are_connection_only(state, members)):
            return None
        groups.append({
            "group": state.group_epochs[group],
            "members": [{"backend": bid, "healthy": state.healthy(bid),
                         "keyspace": state.backends[bid].keyspace} for bid in members],
        })
    return {"kind": "connection", "groups": groups}


def remember_redirect(state, effect, modeled):
    session = state.sessions[effect["session"]]
    session.ordinal += 1
    session.last_redirect = state.now
    session.redirect_failed = not effect["accepted"]
    if effect["accepted"]:
        legal = state.migration_targets(effect["from"])
        # Only an independently modeled redirect may turn the recorded target
        # into future state. Otherwise retain every input-legal destination;
        # the output being validated is evidence, not an oracle.
        session.inflight = (frozenset([effect["to"]]) if modeled and len(session.assigned) == 1
                            else frozenset(legal) or None)
        operation = effect["operation"]
        if operation in state.redirect_operations:
            raise Refuse(f"duplicate redirect operation {operation!r}")
        state.redirect_operations[operation] = (session.id, session.inflight, False)
        state.group_last_redirect[state.backends[effect["from"]].group] = state.now


def due_failover_backends(state):
    timeout_ns = int(state.failover_timeout * 1_000_000_000)
    return {bid for bid, b in state.backends.items() if b.failover_since is not None
            and (timeout_ns == 0 or state.now >= b.failover_since + timeout_ns)}


def derive_tick_effects(state, refused, refuse_next=0):
    """group.go:542-587 CloseTimedOutFailoverConnections at every rebalance: every listed
    connection on a backend whose failover has lasted >= failover-timeout (or immediately when
    the timeout is 0) receives ForceClose; accepted ones are not repeated, refused ones are
    retried on the next tick. Listed = the session's current assignment (its physical list
    owner, also while a redirect is in flight). A non-unique assignment cannot place the
    connection → the slot needs effects-v2 and nothing is emitted for it."""
    out = []
    due = due_failover_backends(state)
    if not due:
        return out, refuse_next
    for s in sorted(state.sessions.values(), key=lambda x: (x.created, x.id)):
        if not s.assigned or s.force_closing:
            continue
        if len(s.assigned) != 1:
            if s.assigned & due:
                state.requires.add("effects-v2")
            continue
        (bid,) = tuple(s.assigned)
        if bid not in due:
            continue
        s.ordinal += 1
        scripted = s.id in refused
        if not scripted and refuse_next:
            scripted, refuse_next = True, refuse_next - 1
        accepted = not scripted
        out.append({"kind": "force_close", "session": s.id, "operation": f"{s.id}/{s.ordinal}", "from": bid, "to": "", "accepted": accepted})
        if accepted:
            s.force_closing = True
    return out, refuse_next


def route_once(state, session, excluded):
    """One routeOnce with a concrete excluded identity set. Returns (legal, error)."""
    if state.observer_error is not None:
        return None, SOURCE_ERROR_MAP[state.observer_error]
    cands, conflict = state.candidates(session)
    if conflict:
        return None, conflict
    legal = [c for c in cands if c not in excluded]
    if not legal:
        return None, "no_backend"
    return legal, None


def prefer_local(state, legal):
    local = [bid for bid in legal if state.backends[bid].local]
    return local if local else legal


def _metric_samples_for_backend(result, backend):
    """Mirror QueryResult's first instance/optional-cluster match."""
    if not backend.ip or type(backend.status_port) is not int or backend.status_port <= 0:
        return None, None
    instance = f"{backend.ip}:{backend.status_port}"
    cluster = backend.cluster.strip() or "default"
    for index, series in enumerate(result["series"]):
        labels = series["labels"]
        if labels.get("instance") != instance:
            continue
        if "tiproxy_cluster" in labels and labels["tiproxy_cluster"] != cluster:
            continue
        return index, series["samples"]
    return None, None


def _public_health_packet_neutral(state):
    """Whether the current public packet can only produce health score zero.

    Missing rows are normal in FactorHealth. Duplicate instance ownership or
    malformed samples are not used to qualify a trace: those cases keep the
    policy constraint. This function is folded into a lifetime invariant by
    State so an earlier non-zero snapshot cannot be forgotten merely because a
    later routing call sees a different retry subset.
    """
    if state.metric_queries is None:
        return False
    pairs = (("failure_pd", "total_pd", 0.5),
             ("failure_tikv", "total_tikv", 0.3))
    for failure_key, total_key, threshold in pairs:
        failure = state.metric_queries[failure_key]
        total = state.metric_queries[total_key]
        if failure is None or not failure["series"] or total is None or not total["series"]:
            continue
        if failure["kind"] != "vector" or total["kind"] != "vector":
            return False
        claimed_failure, claimed_total = set(), set()
        for backend in state.backends.values():
            if not backend.observed_healthy:
                continue
            failure_index, failure_samples = _metric_samples_for_backend(failure, backend)
            total_index, total_samples = _metric_samples_for_backend(total, backend)
            # FactorHealth treats either missing sample as the normal range.
            if not failure_samples or not total_samples:
                continue
            if failure_index in claimed_failure or total_index in claimed_total:
                return False
            claimed_failure.add(failure_index)
            claimed_total.add(total_index)
            failure_values = _samples(failure_samples, True)
            total_values = _samples(total_samples, True)
            if (failure_values is None or total_values is None
                    or failure_values[0][1] < 0 or total_values[0][1] < 0
                    or _health_range(failure_values[0][1], total_values[0][1], threshold) != 0):
                return False
    return True


def metric_factors_are_connection_only(state, legal):
    """Prove a bounded metric-policy factor call reduces to ConnCount.

    The recording environment intentionally discloses CPU/memory no-data. If
    every health value throughout the current factor lifetime is also normal
    and every candidate has the same locality, location/health/memory/CPU scores
    are equal. Status is modeled separately from public health/failover inputs.
    """
    if (state.policy not in METRIC_POLICIES or not legal
            or state.metric_queries is None or state.recorded_connections.label_name):
        return False
    group = state.backends[legal[0]].group
    whole_group = state.group_healthy(legal[0])
    if (group is None or any(state.backends[bid].group != group for bid in legal)
            or len({state.backends[bid].local for bid in whole_group}) != 1):
        return False
    if not state.metric_cpu_memory_history_empty:
        return False
    state.metric_health_history_neutral &= _public_health_packet_neutral(state)
    return state.metric_health_history_neutral


def _metric_rows(state, result, legal, kind):
    """Resolve the exact public instance rows used by QueryResult helpers."""
    if result["kind"] != kind:
        return None
    rows, claimed = {}, set()
    for bid in legal:
        backend = state.backends[bid]
        index, samples = _metric_samples_for_backend(result, backend)
        if index is None or not samples:
            return None
        if index in claimed:
            return None  # one public metric row cannot prove two backend identities
        claimed.add(index)
        rows[bid] = samples
    return rows


def _samples(samples, single=False):
    if single and len(samples) != 1:
        return None
    out = []
    for sample in samples:
        timestamp = sample.get("timestamp_ms")
        if type(timestamp) is not int:
            return None
        try:
            value = float(sample["value"])
        except (KeyError, TypeError, ValueError):
            return None
        if not math.isfinite(value):
            return None
        out.append((timestamp, value))
    return out or None


def _cpu_scores(state, legal, counts):
    result = state.metric_queries["cpu"]
    if result is None or not result["series"]:
        return {bid: 0 for bid in legal}, {}
    updated = result["updated_nanos"]
    if updated is not None and type(updated) is not int:
        return None, None
    if updated != state.cpu_last_metric:
        rows = _metric_rows(state, result, legal, "matrix")
        if rows is None:
            return None, None
        snapshots = dict(state.cpu_snapshots)
        for bid, raw in rows.items():
            samples = _samples(raw)
            if samples is None or any(value < 0 for _, value in samples):
                return None, None
            sample_ms = samples[-1][0]
            previous = snapshots.get(bid)
            if previous is not None and sample_ms <= previous[0]:
                continue
            average = samples[0][1]
            for _, value in samples[1:]:
                average = average * 0.5 + value * 0.5
            snapshots[bid] = (sample_ms, min(average, 1.0), samples[-1][1], counts[bid])
        now = state.clock_origin + state.now
        snapshots = {bid: value for bid, value in snapshots.items()
                     if value[0] * 1_000_000 + 120_000_000_000 >= now}
        state.cpu_snapshots = snapshots
        state.cpu_last_metric = updated
        total_usage = sum(value[2] for value in snapshots.values()
                          if value[2] > 0 and value[3] > 0)
        total_connections = sum(value[3] for value in snapshots.values()
                                if value[2] > 0 and value[3] > 0)
        if total_connections > 0:
            per_connection = total_usage / total_connections
            if per_connection < 0.001 and total_usage / len(snapshots) <= 0.1:
                per_connection = state.cpu_usage_per_conn
            state.cpu_usage_per_conn = per_connection
        if state.cpu_usage_per_conn <= 0:
            state.cpu_usage_per_conn = 0.001
    if state.cpu_last_metric is None or state.clock_origin + state.now - state.cpu_last_metric > 120_000_000_000:
        return {bid: 0 for bid in legal}, {}
    usage = {}
    for bid in legal:
        snapshot = state.cpu_snapshots.get(bid)
        if snapshot is None:
            return None, None
        _, average, latest, snapshot_count = snapshot
        current = max(0.0, min(1.0, latest + (counts[bid] - snapshot_count) * state.cpu_usage_per_conn))
        usage[bid] = (average, current)
    return {bid: int(value[1] * 100) // 5 for bid, value in usage.items()}, usage


def _memory_risk(latest, time_to_oom):
    if time_to_oom < 45_000_000_000 or latest > 0.75:
        return 2
    if time_to_oom < 180_000_000_000 or latest > 0.6:
        return 1
    return 0


def _memory_scores(state, legal, counts):
    result = state.metric_queries["memory"]
    if result is None or not result["series"]:
        return {bid: 0 for bid in legal}
    updated = result["updated_nanos"]
    if updated is not None and type(updated) is not int:
        return None
    if updated != state.memory_last_metric:
        rows = _metric_rows(state, result, legal, "matrix")
        if rows is None:
            return None
        snapshots = dict(state.memory_snapshots)
        for bid, raw in rows.items():
            samples = _samples(raw)
            if samples is None or any(value < 0 for _, value in samples):
                return None
            sample_ms = samples[-1][0]
            previous = snapshots.get(bid)
            if previous is not None and sample_ms <= previous[0]:
                continue
            latest = min(samples[-1][1], 0.9)
            time_to_oom = math.inf
            for timestamp, value in reversed(samples[:-1]):
                elapsed = (sample_ms - timestamp) * 1_000_000
                if elapsed < 10_000_000_000:
                    continue
                increase = latest - value
                if increase > 0.0001 and latest > 0.0001:
                    time_to_oom = elapsed * (0.9 - latest) / increase / latest * 0.6
                break
            risk = _memory_risk(latest, time_to_oom)
            balance = 0.0
            if risk >= 2:
                seconds = 10.0 if time_to_oom < 45_000_000_000 else 60.0
                balance = float(counts[bid]) / seconds
                if previous is not None:
                    balance = max(balance, previous[4])
            snapshots[bid] = (sample_ms, latest, time_to_oom, risk, balance)
        now = state.clock_origin + state.now
        state.memory_snapshots = {bid: value for bid, value in snapshots.items()
                                  if value[0] * 1_000_000 + 60_000_000_000 >= now}
        state.memory_last_metric = updated
    if state.memory_last_metric is None or state.clock_origin + state.now - state.memory_last_metric > 60_000_000_000:
        return {bid: 0 for bid in legal}
    return {bid: state.memory_snapshots.get(bid, (0, 0, 0, 0, 0))[3] for bid in legal}


def _health_range(failure, total, fail_threshold):
    if failure == 0:
        return 0
    if total == 0:
        return 2
    ratio = failure / total
    if ratio <= 0.1:
        return 0
    if ratio >= fail_threshold:
        return 2
    return 1


def _health_scores(state, legal, counts):
    pairs = (("failure_pd", "total_pd", 0.5), ("failure_tikv", "total_tikv", 0.3))
    newest, changed = None, False
    for failure_key, total_key, threshold in pairs:
        failure, total = state.metric_queries[failure_key], state.metric_queries[total_key]
        if failure is None or not failure["series"]:
            continue
        if total is None or not total["series"]:
            continue
        failure_rows = _metric_rows(state, failure, legal, "vector")
        total_rows = _metric_rows(state, total, legal, "vector")
        if failure_rows is None or total_rows is None:
            return None
        decoded = {}
        for bid in legal:
            f_samples, t_samples = _samples(failure_rows[bid], True), _samples(total_rows[bid], True)
            if f_samples is None or t_samples is None or f_samples[0][1] < 0 or t_samples[0][1] < 0:
                return None
            decoded[bid] = (f_samples[0][1], t_samples[0][1])
        for key, result in ((failure_key, failure), (total_key, total)):
            updated = result["updated_nanos"]
            if updated is not None and type(updated) is not int:
                return None
            if state.health_query_updates[key] != updated:
                state.health_query_updates[key] = updated
                state.health_query_results[key] = (copy.deepcopy(result), decoded)
                changed = True
            if updated is not None and (newest is None or updated > newest):
                newest = updated
    if newest is None or state.clock_origin + state.now - newest > 60_000_000_000:
        return {bid: 0 for bid in legal}
    if changed:
        snapshots = dict(state.health_snapshots)
        for bid in legal:
            updated_time, risk = None, 0
            for failure_key, total_key, threshold in pairs:
                failure = state.health_query_results.get(failure_key)
                total = state.health_query_results.get(total_key)
                if failure is None or total is None:
                    continue
                failure_result, failure_values = failure
                total_result, total_values = total
                times = [value for value in (failure_result["updated_nanos"], total_result["updated_nanos"])
                         if value is not None]
                if not times:
                    continue
                timestamp = max(times)
                if timestamp + 60_000_000_000 < state.clock_origin + state.now:
                    continue
                if updated_time is None or timestamp > updated_time:
                    updated_time = timestamp
                risk = max(risk, _health_range(failure_values[bid][0], total_values[bid][1], threshold))
            if updated_time is None:
                continue
            previous = snapshots.get(bid)
            balance = (previous[2] if risk >= 2 and previous is not None and previous[2] > 0.0001
                       else float(counts[bid]) / 60.0 if risk >= 2 else 0.0)
            snapshots[bid] = (updated_time, risk, balance)
        now = state.clock_origin + state.now
        state.health_snapshots = {bid: value for bid, value in snapshots.items()
                                  if value[0] + 60_000_000_000 >= now}
    return {bid: state.health_snapshots.get(bid, (0, 0, 0))[1] for bid in legal}


def _resource_factor_scores(state, legal):
    counts, _ = state.connection_counts()
    health = _health_scores(state, legal, counts)
    memory = _memory_scores(state, legal, counts)
    cpu, cpu_usage = _cpu_scores(state, legal, counts)
    if health is None or memory is None or cpu is None:
        return None
    return counts, health, memory, cpu, cpu_usage


def _resource_advice(state, name, values, cpu_usage, source, target, counts):
    """Mirror one Resource factor's BalanceCount result as (advice, rate)."""
    if name == "health":
        snapshot = state.health_snapshots.get(source, (0, 0, 0))
        if values[source] - values[target] <= 1:
            return "neutral", 0.0
        rate = state.resource_rates["health"] or snapshot[2]
        return "positive", rate
    if name == "memory":
        snapshot = state.memory_snapshots.get(source, (0, 0, 0, 0, 0))
        if values[source] - values[target] <= 1:
            return "neutral", 0.0
        rate = state.resource_rates["memory"] or snapshot[4]
        return "positive", rate
    if name == "cpu":
        if source not in cpu_usage or target not in cpu_usage:
            return "neutral", 0.0
        from_average, from_latest = cpu_usage[source]
        to_average, to_latest = cpu_usage[target]
        per_connection = state.cpu_usage_per_conn
        negative = ((1.3 - (to_average + per_connection)) * 1.1
                    < 1.3 - (from_average - per_connection)
                    or (1.3 - (to_latest + per_connection)) * 1.1
                    < 1.3 - (from_latest - per_connection))
        if negative:
            return "negative", 0.0
        neutral = (1.3 - to_average < (1.3 - from_average) * 1.2
                   or 1.3 - to_latest < (1.3 - from_latest) * 1.2)
        if neutral:
            return "neutral", 0.0
        rate = state.resource_rates["cpu"] if state.resource_rates["cpu"] > 0 else 1 / per_connection / 600
        return "positive", rate
    if name == "location":
        return "positive", state.resource_rates["location"] or 1.0
    if name == "conn":
        ratio, rate = state.recorded_connections.ratio, state.recorded_connections.rate
        if float(counts[source]) <= float(counts[target] + 1) * ratio:
            return "neutral", 0.0
        if rate <= 0:
            rate = max(0.0, (float(counts[source] + counts[target] + 1) / (1 + ratio)
                             - float(counts[target] + 1)) / 120)
        return "positive", rate
    raise AssertionError(name)


def _prime_resource_scoring(state):
    """Consume a bounded factor call made by a failover-view refresh."""
    if (state.policy != "resource" or state.fail_list or not state.unique_history
            or any(len(owners) != 1 for session in state.sessions.values()
                   for owners in (session.pending, session.assigned, session.inflight) if owners)
            or len(state.groups) != 1):
        return not state.groups
    members = next(iter(state.groups.values()))
    legal = sorted(bid for bid in members if state.backends[bid].observed_healthy)
    if len(legal) <= 1:
        return True  # every metric factor returns before reading its query
    if (len(legal) != 2 or len({state.backends[bid].local for bid in legal}) != 1
            or any(state.backends[bid].cluster for bid in legal)):
        return False
    return _resource_factor_scores(state, legal) is not None


def _stable_resource_health_update(state, backends):
    """Whether a health delivery preserves the bounded Resource factor instance.

    Restrict this increment to an unchanged, fully healthy two-backend group.
    Identity, metric lookup and factor-order inputs must all remain public and
    stable; otherwise the existing dependency is safer than reconstructing a
    private group lifecycle or failover view.
    """
    if (state.policy != "resource" or not state.resource_metric_history_trusted
            or state.fail_list or not state.unique_history or len(state.groups) != 1
            or len(state.backends) != 2
            or any(not backend.observed_healthy for backend in state.backends.values())):
        return False
    members = next(iter(state.groups.values()))
    incoming = {}
    for raw in backends:
        bid = backend_id(raw)
        if bid in incoming:
            return False
        incoming[bid] = raw
    if set(incoming) != set(members) or set(members) != set(state.backends):
        return False
    for bid, raw in incoming.items():
        old = state.backends[bid]
        if (not raw.get("healthy", True)
                or raw.get("ip", "") != old.ip
                or raw.get("status_port", 0) != old.status_port
                or raw.get("keyspace", "") != old.keyspace
                or dict(raw.get("labels", {}) or {}) != old.labels
                or bool(raw.get("local", True)) != old.local):
            return False
    return True


def resource_metrics_preferred(state, session, legal):
    """Return candidates for the bounded, public-metric Resource case.

    The supported history has exactly two fully specified candidates in one
    group, unique public ownership, equal locality, and no health/tick scoring
    outside this model. It mirrors config-time scoring and the factor order, and
    only evicts a worse score when that factor's public advice is positive.
    """
    if (state.policy != "resource" or state.selection != "prefer-idle"
            or not state.resource_metric_history_trusted or state.metric_queries is None
            or state.recorded_connections.label_name or not state.unique_history
            or session.relative_history or session.cycle or len(legal) != 2
            or any(not state.healthy(bid) for bid in legal)
            or len({state.backends[bid].local for bid in legal}) != 1
            or any(state.backends[bid].cluster for bid in legal)
            or len(state.groups) != 1):
        return None
    group = state.backends[legal[0]].group
    if (group is None or any(state.backends[bid].group != group for bid in legal)
            or set(legal) != set(state.groups.get(group, set()))):
        return None
    if any(len(owners) != 1 for s in state.sessions.values()
           for owners in (s.pending, s.assigned, s.inflight) if owners):
        return None
    factors = _resource_factor_scores(state, legal)
    if factors is None:
        return None
    counts, health, memory, cpu, cpu_usage = factors
    conn_scores = {bid: min(counts[bid], 65535) for bid in legal}
    scores = {bid: (health[bid], memory[bid], cpu[bid], 0, conn_scores[bid]) for bid in legal}
    target = min(legal, key=lambda bid: scores[bid])
    source = next(bid for bid in legal if bid != target)
    if scores[source] == scores[target]:
        return sorted(legal)
    factors = (("health", health), ("memory", memory), ("cpu", cpu),
               ("location", {bid: int(not state.backends[bid].local) for bid in legal}),
               ("conn", conn_scores))
    for name, values in factors:
        if values[source] < values[target]:
            return sorted(legal)
        if values[source] == values[target]:
            continue
        advice, rate = _resource_advice(state, name, values, cpu_usage, source, target, counts)
        if advice == "positive" and rate > 0.0001:
            return [target]
    return sorted(legal)


def derive_resource_redirects(state, refused):
    """Predict one bounded two-backend Resource balance tick from public inputs."""
    if (state.policy != "resource" or not state.resource_metric_history_trusted
            or state.metric_queries is None or state.recorded_connections.label_name
            or not state.unique_history or "migration-cadence" in state.requires
            or state.ambiguous_group_clocks or state.fail_list or len(state.groups) != 1
            or any(b.ambiguous for b in state.backends.values())
            or any(len(owners) != 1 for session in state.sessions.values()
                   for owners in (session.pending, session.assigned, session.inflight) if owners)):
        return None
    group, members = next(iter(state.groups.items()))
    legal = sorted(members)
    if (len(legal) != 2 or any(not state.healthy(bid) for bid in legal)
            or any(state.backends[bid].cluster for bid in legal)):
        return None
    factors = _resource_factor_scores(state, legal)
    if factors is None:
        return None
    counts, health, memory, cpu, cpu_usage = factors
    location = {bid: int(not state.backends[bid].local) for bid in legal}
    conn_scores = {bid: min(counts[bid], 65535) for bid in legal}
    values = (("health", health), ("memory", memory), ("cpu", cpu),
              ("location", location), ("conn", conn_scores))
    scores = {bid: tuple(factor[bid] for _, factor in values) for bid in legal}
    target = min(legal, key=lambda bid: scores[bid])
    source = next(bid for bid in legal if bid != target)
    if scores[source] == scores[target]:
        return []
    _, physical = state.connection_counts()
    if counts[source] <= 0 or physical[source] <= 0:
        return []
    rate = 0.0
    for name, factor in values:
        if factor[source] < factor[target]:
            break
        advice, candidate_rate = _resource_advice(
            state, name, factor, cpu_usage, source, target, counts)
        if advice == "negative":
            break
        if factor[source] > factor[target] and advice == "positive" and candidate_rate > 0.0001:
            rate = candidate_rate
            break
    if rate <= 0.0001 or state.backends[source].keyspace != state.backends[target].keyspace:
        return []
    interval = int(1_000_000_000.0 / rate)
    if interval <= 0:
        return None
    last = state.group_last_redirect.get(group)
    if interval < 20_000_000:
        budget = (10_000_000 - 1) // interval + 1
    elif last is None or state.now - last >= interval:
        budget = 1
    else:
        return []
    effects = []
    for session in sorted(state.sessions.values(), key=lambda item: item.created):
        if budget == 0:
            break
        if (session.assigned != frozenset([source]) or session.force_closing
                or session.inflight):
            continue
        if (session.redirect_failed and session.last_redirect is not None
                and state.now < session.last_redirect + 3_000_000_000):
            continue
        accepted = session.id not in refused
        effects.append({"kind":"redirect", "session":session.id,
                        "operation":f"{session.id}/{session.ordinal + 1}",
                        "from":source, "to":target, "accepted":accepted})
        budget -= int(accepted)
    return effects


def derive_next(state, session, expect):
    """Engine-independent expectation for one Next, plus Go's own legal set for validation."""
    go_excluded = [b for b, _ in session.cycle]
    legal_go, err = route_once(state, session, set(go_excluded))
    if err == "no_backend" and go_excluded:
        session.cycle = []  # Go's real internal exhaustion/reset only
        legal_go, err = route_once(state, session, set())
    if err is not None:
        expect["outcome"] = err
        if err == "no_backend":
            session.relative_history = False
        return None
    state.update_connection_status(state.backends[legal_go[0]].group, {bid: True for bid in legal_go})
    if session.relative_history:
        # Publish candidates before exclusions; the comparator subtracts each
        # engine's complete cycle and resets only when its own set is exhausted.
        legal, _ = state.candidates(session)
        expect["exclude_history"] = True
    else:
        legal = legal_go
    if state.selection == "prefer-idle":
        connection_only = (state.policy in METRIC_POLICIES
                           and metric_factors_are_connection_only(state, legal_go))
        if connection_only:
            # The higher-priority metric factors are publicly proven equal.
            # Keep the full candidate set in the expectation so each engine
            # applies its own complete retry cycle and public connection
            # history; Go's row is checked with the same predicate here.
            legal, _ = state.candidates(session)
            expect["exclude_history"] = True
            expect["prefer_idle_conn"] = True
            legal_go = sorted(state.recorded_connections.prefer_idle(legal_go))
        # factor_balance.go:287-345 evicts a candidate when a higher-priority factor advises
        # migration. Under `location` the location factor precedes every metric factor, so a
        # remote candidate is evicted whenever a local one exists — deterministic from inputs.
        # Every other eviction (conn-count, health/memory/cpu) is not derivable: constraint.
        elif state.policy == "location":
            if session.relative_history:
                expect["prefer_local"] = sorted(b for b in legal if state.backends[b].local)
            else:
                legal = prefer_local(state, legal)
            legal_go = prefer_local(state, legal_go)
        if state.policy == "connection":
            # All candidates remain input-derived. Each engine applies its own
            # public reservation/assignment history after its own exclusions.
            legal, _ = state.candidates(session)
            expect["exclude_history"] = True
            expect["prefer_idle_conn"] = True
            legal_go = sorted(state.recorded_connections.prefer_idle(legal_go))
        elif state.policy == "resource" and not connection_only:
            modeled = resource_metrics_preferred(state, session, legal_go)
            if modeled is None:
                if len(legal) > 1:
                    state.requires.add("policy-constraint:resource/prefer-idle")
                    if state.metrics_observed:
                        state.requires.add("metrics-input")
            else:
                legal = legal_go = modeled
        elif not connection_only and len(legal) > 1:
            state.requires.add(f"policy-constraint:{state.policy}/prefer-idle")
            if state.policy in METRIC_POLICIES and state.metrics_observed:
                state.requires.add("metrics-input")
    if len(legal) == 1:
        expect["backend"] = legal[0]
    else:
        expect["legal_backends"] = sorted(legal)
    return legal_go


def derive(trace, rows, args):
    state = State(trace["config"], trace.get("provenance"))
    events = trace["events"]
    if len(rows) != len(events):
        raise Refuse(f"rows {len(rows)} != events {len(events)}")
    out_events = []
    for seq, (event, row) in enumerate(zip(events, rows)):
        op, sid = event["op"], event.get("session", "")
        state.now = event.get("at_nanos", state.now)
        state.status_calls = []
        connections_prepared = False
        expect = {"outcome": "ok"}
        if op == "health":
            state.apply_health(event.get("backends", []))
        elif op == "metrics":
            try:
                _RUNNER.validate_metrics(event.get("queries"))
            except _RUNNER.Difference as error:
                raise Refuse(f"seq {seq}: {error}") from error
            if row["outcome"] != "ok" or row.get("backend", "") or row.get("effects", []):
                raise Refuse(f"seq {seq}: metric publication cannot produce a routing result")
            state.apply_metrics(event["queries"])
            state.requires.add("metrics-input")
        elif op == "source_error":
            if event["error"] not in SOURCE_ERROR_MAP:
                raise Refuse(f"seq {seq}: unknown source error identity {event['error']!r}")
            state.observer_error = event["error"]
        elif op == "config":
            if row["outcome"] not in ("ok", "invalid_config"):
                raise Refuse(f"seq {seq}: config outcome {row['outcome']!r} not a public class")
            expect["outcome"] = row["outcome"]  # validator result at the validation entry (README §2)
            if row["outcome"] == "ok":
                state.apply_config(event.get("toml", ""))
        elif op == "open":
            state.sessions[sid] = Session(sid, event)
        elif op == "next":
            s = state.sessions[sid]
            legal_go = derive_next(state, s, expect)
            if expect["outcome"] == "no_backend" and state.observer_error == "no_backend" and s.cycle:
                s.cycle = []  # exact ErrNoBackend from the observer also resets (backend_selector.go:26-30)
            if expect["outcome"] != row["outcome"]:
                raise Refuse(f"seq {seq}: recorded outcome {row['outcome']!r} is not explained by inputs (derived {expect['outcome']!r})")
            if row["outcome"] == "ok":
                chosen = row.get("backend", "")
                if chosen not in legal_go:
                    raise Refuse(f"seq {seq}: recorded backend {chosen!r} is outside Go's own legal set {legal_go} (excluded {[b for b, _ in s.cycle]})")
                unique = "backend" in expect
                if not unique:
                    state.unique_history = False
                    s.relative_history = True
                s.cycle.append((chosen, unique))
                s.pending = frozenset([chosen]) if unique else frozenset(expect["legal_backends"])
        elif op == "finish":
            s = state.sessions[sid]
            if s.pending is None:
                raise Refuse(f"seq {seq}: finish without a pending Next")
            if event["success"]:
                s.assigned, s.cycle, s.created = s.pending, [], seq
            s.pending = None
        elif op == "close":
            state.sessions.pop(sid, None)
            for operation,(owner,targets,completed) in list(state.redirect_operations.items()):
                if owner == sid:
                    state.redirect_operations[operation] = (owner,targets,True)
        elif op == "lookup":
            name = event["backend"]
            b = state.backends.get(name)
            if b is not None and b.ambiguous:
                raise Refuse(f"seq {seq}: retention of {name!r} depends on an engine-relative assignment")
            expect["outcome"] = "ok" if b is not None else "unknown_backend"
            if b is not None:
                expect["backend"] = name
        elif op == "rehydrate":
            name = event["backend"]
            b = state.backends.get(name)
            if b is not None and b.ambiguous:
                raise Refuse(f"seq {seq}: retention of {name!r} depends on an engine-relative assignment")
            s = state.sessions.get(sid) or Session(sid, event)
            state.sessions[sid] = s
            if s.assigned or s.pending:
                raise Refuse(f"seq {seq}: rehydrate on a non-idle session")
            ok = b is not None and b.group is not None  # group ownership (group.go:514-520)
            expect["outcome"] = "ok" if ok else "unknown_backend"
            if ok:
                expect["backend"] = name
                s.assigned = frozenset([name])
                s.created = seq
        elif op == "tick":
            refused = set(event.get("refuse", []) or [])
            recorded = row.get("effects", [])
            # BackendsToBalance scores Status first on this tick. Its retained
            # unhealthy rate must therefore be available to every policy's
            # prediction below, including a first tick after health loss.
            if state.support_redirection:
                for group, members in state.groups.items():
                    if len(members) > 1:
                        state.update_connection_status(group, {bid: state.healthy(bid) for bid in members})
            if state.status_calls:
                expect["status_scoring"] = copy.deepcopy(state.status_calls)
            try:
                state.recorded_connections.prepare(event, expect, row, state.now)
            except _RUNNER.Difference as error:
                raise Refuse(f"seq {seq}: {error}") from error
            connections_prepared = True
            metric_predicted = None
            if (state.support_redirection and state.metric_queries is not None
                    and state.policy in METRIC_POLICIES):
                # Every enabled tick calls BackendsToBalance even when there is
                # no physical source connection. A lifetime with no CPU/memory,
                # normal health and equal locality reduces both metric policies
                # to the exact active connection ledger. Otherwise retain the
                # complete bounded Resource model or keep the history explicit.
                metric_predicted = derive_connection_redirects(state, refused)
                if metric_predicted is None and state.policy == "resource":
                    metric_predicted = derive_resource_redirects(state, refused)
            # Whether a migration could be due is a property of inputs and
            # session history. Deleting its observed output must not remove
            # this dependency. A whole health result can disable Balance,
            # while the independent failover-close pass still runs.
            migration_possible = state.support_redirection and any(
                s.assigned and not s.force_closing and not s.inflight
                and any(state.migration_targets(bid) for bid in s.assigned)
                for s in state.sessions.values()
            )
            relative_history = state.relative_history_active()
            # Recorded in-flight/close/callback state may differ after legal
            # engine-specific routing. A bounded relative model is therefore
            # needed even when Go has no eligible source on this exact tick.
            relative_migration_possible = relative_history and any(
                state.migration_targets(bid) for bid in state.backends
            )
            migration_may_differ = (
                migration_possible
                or (state.support_redirection and relative_migration_possible)
            )
            if not migration_possible:
                predicted = []
            elif state.policy == "connection":
                predicted = derive_connection_redirects(state, refused)
            elif state.policy in METRIC_POLICIES:
                predicted = metric_predicted
            else:
                predicted = None
            if relative_history:
                # Once ordinary routing has made a legal engine-specific
                # choice, even a later exact recorded ledger cannot name the
                # other engine's session selected for migration. Keep using
                # the public engine-relative cadence model for the rest of
                # that history rather than turning Go's owner into an oracle.
                predicted = None
            if event.get("refuse_next", 0):
                # A one-shot refusal belongs to the external client boundary,
                # so the concrete refused owner is resolved per engine.
                predicted = None
            relative_model = (
                connection_cadence_model(state)
                if migration_may_differ and predicted is None else None
            )
            modeled = predicted is not None or relative_model is not None
            if migration_may_differ and not modeled:
                state.requires.add("migration-cadence")
                if state.policy in METRIC_POLICIES:
                    state.resource_metric_history_trusted = False
            # Redirects (group.Balance) are issued before the failover close pass in the same
            # iteration (router_score.go:471-483), so their ordinals come first.
            # Check public ownership/destination/acceptance for all redirects.
            # Modeled timing is compared against its independent prediction;
            # other factor/history cases remain withheld, never copied.
            leftover = []
            refusal_budget = event.get("refuse_next", 0)
            for ef in recorded:
                if ef["kind"] == "force_close":
                    leftover.append(ef)
                    continue
                if not state.support_redirection:
                    raise Refuse(f"seq {seq}: redirect while the health input disables redirection")
                s = state.sessions.get(ef["session"])
                if s is None or not s.assigned:
                    raise Refuse(f"seq {seq}: effect {ef['operation']} on an unknown or idle session")
                if len(s.assigned) == 1 and ef["from"] not in s.assigned:
                    raise Refuse(f"seq {seq}: effect {ef['operation']} from {ef['from']!r} contradicts the derived assignment {sorted(s.assigned)}")
                scripted = ef["session"] in refused
                if not scripted and refusal_budget:
                    scripted, refusal_budget = True, refusal_budget - 1
                if ef["accepted"] == scripted:
                    raise Refuse(f"seq {seq}: effect {ef['operation']} acceptance contradicts the scripted refusal")
                legal_to = state.migration_targets(ef["from"])
                if ef["to"] not in legal_to:
                    raise Refuse(f"seq {seq}: redirect destination {ef['to']!r} not in the legal set {sorted(legal_to)}")
                remember_redirect(state, ef, predicted is not None)
                if not modeled:
                    state.requires.add("migration-cadence")
                if relative_history and not modeled:
                    state.requires.add("effects-v2")
            if (predicted is not None
                    and _RUNNER.causal([ef for ef in recorded if ef["kind"] == "redirect"])
                    != _RUNNER.causal(predicted)):
                raise Refuse(f"seq {seq}: redirect effects contradict the input-derived {state.policy} cadence: expected {predicted}")
            if relative_model is not None:
                expect["redirect_cadence"] = relative_model
            if relative_history and migration_may_differ and not modeled:
                # A possible migration after non-unique routing depends on
                # each engine's assignments. No session/destination means no
                # migration for every engine, including empty-health ticks.
                state.requires.add("effects-v2")
            relative_close = (relative_history
                              and (not migration_possible or relative_model is not None))
            if relative_close:
                # The due backend set is defined by public config/health/time.
                # Each engine resolves its own owners and accepted-close history;
                # only Go's own rows are used to validate this recording here.
                due = sorted(due_failover_backends(state))
                expect["force_close_due"] = due
                derived, remaining_refusal = state.recorded_connections._force_close_effects(
                    event, due, refusal_budget)
            else:
                derived, remaining_refusal = derive_tick_effects(state, refused, refusal_budget)
            if relative_model is not None:
                alternatives = state.recorded_connections.expected_effect_alternatives(event, expect, state.now)
                if not any(_RUNNER.causal(recorded) == _RUNNER.causal(candidate) for candidate in alternatives):
                    raise Refuse(f"seq {seq}: effects contradict the engine-relative connection cadence: recorded {recorded}, expected one of {alternatives[:4]}, counts {state.recorded_connections.counts()}, last {state.recorded_connections.group_last_redirect}")
            elif key_effects(leftover) != key_effects(derived):
                raise Refuse(f"seq {seq}: recorded force_close effects {leftover} differ from the failover-timeout derivation {derived}")
            if relative_model is None and remaining_refusal:
                raise Refuse(f"seq {seq}: one-shot refusal was not consumed by an eligible effect")
            if derived and not relative_close:
                expect["effects"] = derived
            if modeled and predicted:
                expect["effects"] = predicted + derived
            for effect in recorded:
                if effect["kind"] == "redirect" and effect["accepted"]:
                    state.accepted_redirects += 1
                    effect_ref = f"redirect/{state.accepted_redirects}"
                    state.operation_refs[effect["operation"]] = effect_ref
                    state.ref_operations[effect_ref] = effect["operation"]
            if state.policy in METRIC_POLICIES and state.metrics_observed:
                state.requires.add("metrics-input")  # migration advice consults metric factors
        elif op == "redirect_result":
            operation = event.get("operation") or state.ref_operations.get(event.get("effect_ref"))
            if operation is None:
                raise Refuse(f"seq {seq}: callback has no known engine-relative operation")
            accepted = state.redirect_operations.get(operation)
            if accepted is None or accepted[0] != sid:
                raise Refuse(f"seq {seq}: callback lacks a matching accepted redirect {operation!r}")
            owner, targets, completed = accepted
            s = state.sessions.get(sid)
            if not completed:
                if s is not None and s.inflight:
                    if event["success"]:
                        s.assigned, s.created = targets, seq
                    s.redirect_failed = not event["success"]
                    s.inflight = None
                state.redirect_operations[operation] = (owner, targets, True)
        elif op == "checkpoint":
            expect["healthy_backend_count"] = 0 if state.observer_error is not None else len(state.routable_ids())
            current = sorted({b.version for b in state.backends.values() if b.observed_healthy and b.version})
            expect["legal_server_versions"] = current if current else [state.retained_version]
        else:
            raise Refuse(f"seq {seq}: unsupported op {op!r}")
        if state.status_calls and "status_scoring" not in expect:
            expect["status_scoring"] = copy.deepcopy(state.status_calls)
        e = dict(event)
        if op == "close" and "effect_ref" not in e and seq + 1 < len(events):
            following = events[seq + 1]
            if (following.get("op") == "redirect_result"
                    and following.get("session") == sid):
                operation = (following.get("operation")
                             or state.ref_operations.get(following.get("effect_ref")))
                effect_ref = state.operation_refs.get(operation)
                if effect_ref is not None:
                    # Older traces recorded the close/result adjacency but not
                    # the close's operation. Preserve that public ordering as
                    # the same strict delayed-close reference new writers emit.
                    e["effect_ref"] = effect_ref
        if op == "redirect_result" and "operation" in e:
            effect_ref = state.operation_refs.get(e["operation"])
            if effect_ref is not None:
                e.pop("operation")
                e["effect_ref"] = effect_ref
        if (op == "redirect_result" and "effect_ref" in e
                and not (out_events and out_events[-1]["op"] == "close"
                         and out_events[-1].get("effect_ref") == e["effect_ref"])):
            # Ordinary asynchronous callbacks are engine-relative completion
            # opportunities. An engine with no outstanding accepted redirect
            # at this input emits no_effect; a delayed-close callback is strict.
            e["optional_effect"] = True
        e["expect"] = expect
        try:
            if not connections_prepared:
                state.recorded_connections.prepare(e, expect, row, state.now)
            public_sid = state.recorded_connections.resolve_event(e)
            public_operation = state.recorded_connections.resolve_operation(e)
            state.recorded_connections.apply(e, row, public_sid, public_operation, seq, prepared=True)
        except _RUNNER.Difference as error:
            raise Refuse(f"seq {seq}: {error}") from error
        out_events.append(e)
    result = copy.deepcopy(trace)
    result["events"] = out_events
    metric_inputs = [e for e in events if e["op"] == "metrics"]
    if metric_inputs:
        state.requires.discard("metrics-input")
    return result, sorted(state.requires)


def compare_with_reference(derived, reference, requires):
    """Strict regression against a hand-written trace: unique must be unique, sets equal,
    error classes / exclude_previous / counts / versions equal; effects equal unless the slot
    is marked effects-v2 (reported WITHHELD, never qualified)."""
    diffs, withheld = [], []
    for seq, (d, r) in enumerate(zip(derived["events"], reference["events"])):
        de, re_ = d["expect"], r["expect"]
        if de["outcome"] != re_["outcome"]:
            diffs.append((seq, "outcome", de["outcome"], re_["outcome"])); continue
        if "backend" in re_ and de.get("backend") != re_["backend"]:
            diffs.append((seq, "backend", de.get("backend", de.get("legal_backends")), re_["backend"]))
        if "legal_backends" in re_ and sorted(de.get("legal_backends", [])) != sorted(re_["legal_backends"]):
            diffs.append((seq, "legal", de.get("legal_backends", de.get("backend")), sorted(re_["legal_backends"])))
        for k in ("exclude_previous", "healthy_backend_count"):
            if k == "exclude_previous" and re_.get(k) and de.get("exclude_history"):
                continue
            if k in re_ and de.get(k) != re_[k]:
                diffs.append((seq, k, de.get(k), re_[k]))
            if k == "exclude_previous" and k not in re_ and de.get(k):
                diffs.append((seq, k, de.get(k), None))
        if "legal_server_versions" in re_ and sorted(re_["legal_server_versions"]) != sorted(de.get("legal_server_versions", [])):
            diffs.append((seq, "versions", de.get("legal_server_versions"), re_["legal_server_versions"]))
        if de.get("force_close_due", []) != re_.get("force_close_due", []):
            diffs.append((seq, "force_close_due", de.get("force_close_due"), re_.get("force_close_due")))
        if re_.get("effects", []) != de.get("effects", []):
            ref_effects, derived_effects = re_.get("effects", []), de.get("effects", [])
            if "effects-v2" in requires and not derived_effects:
                withheld.append(seq)  # nothing can be placed without per-engine assignments
            elif "migration-cadence" in requires and key_effects([e for e in ref_effects if e["kind"] != "redirect"]) == key_effects(derived_effects):
                withheld.append(seq)  # redirects withheld; the derived force_close set matches
            else:
                diffs.append((seq, "effects", derived_effects, ref_effects))
    return diffs, withheld


def self_check(stripped, rows, reference, requires):
    """Negative regression: corrupt the recorded rows one way at a time; each must be caught."""
    results = {}
    def next_index(pred):
        return next(i for i, e in enumerate(reference["events"]) if e["op"] == "next" and pred(e["expect"]))
    bad = copy.deepcopy(rows); i = next_index(lambda x: "backend" in x); bad[i]["backend"] = "default/wrong"
    try:
        derive(copy.deepcopy(stripped), bad, None); results["wrong_backend"] = "NOT CAUGHT"
    except Refuse as e:
        results["wrong_backend"] = f"refused: {e}"
    bad = copy.deepcopy(rows); i = next_index(lambda x: x["outcome"] != "ok"); bad[i]["outcome"] = "ok"; bad[i]["backend"] = "default/wrong"
    try:
        derive(copy.deepcopy(stripped), bad, None); results["wrong_error_class"] = "NOT CAUGHT"
    except Refuse as e:
        results["wrong_error_class"] = f"refused: {e}"
    try:
        j = next(i for i, e in enumerate(reference["events"]) if e["op"] == "tick" and e["expect"].get("effects"))
        bad = copy.deepcopy(rows); bad[j]["effects"] = []
        try:
            derived, req = derive(copy.deepcopy(stripped), bad, None)
            diffs, withheld = compare_with_reference(derived, reference, req)
            results["dropped_effect"] = "caught by regression" if any(d[0] == j and d[1] == "effects" for d in diffs) else ("withheld (effects-v2 required)" if j in withheld else "NOT CAUGHT")
        except Refuse as e:
            results["dropped_effect"] = f"refused by derivation: {e}"
    except StopIteration:
        results["dropped_effect"] = "no required effects in this trace"
    results.update(defect_checks())
    print(json.dumps({"self_check": results}, ensure_ascii=False))
    if any(str(v).startswith("NOT CAUGHT") for v in results.values()):
        sys.exit(3)


def hb(addr, healthy=True, local=True, port=None, cluster="default"):
    labels = {PORT_LABEL: port} if port else {}
    return {"address": addr, "labels": labels, "cluster": cluster, "ip": "127.0.0.1", "status_port": 10080,
            "healthy": healthy, "local": local, "server_version": "8.5.1", "support_redirection": True}


def rows_for(ev, **backends):
    rows = [{"op": e["op"], "outcome": "ok", "backend": "", "effects": []} for e in ev]
    for i, b in backends.items():
        rows[int(i[1:])]["backend"] = b
    return rows


def defect_checks():
    """Mini traces for reviewer-reported defects (msgs 3b98d666, 5fb72a0b, ba700a7d)."""
    out = {}
    cfg = {"policy": "connection", "selection": "random", "rule": ""}
    def attempt(name, cfg, ev, rows, want):
        try:
            d, req = derive({"config": cfg, "events": ev}, rows, None)
            out[name] = want(d, req)
        except Refuse as e:
            out[name] = want(None, str(e))
    # A fails, B fails, third Next returns the still-excluded A (C alive) -> refused
    ev = [{"op": "health", "backends": [hb("a"), hb("b"), hb("c")]}, {"op": "open", "session": "s"},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}]
    attempt("excluded_repeat_ABA", cfg, ev, rows_for(ev, e2="default/a", e4="default/b", e6="default/a"),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # A fails, B fails, health removes A (B/C remain), third returns B -> refused (C is the unique legal one)
    ev = [{"op": "health", "backends": [hb("a"), hb("b"), hb("c")]}, {"op": "open", "session": "s"},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "health", "backends": [hb("b"), hb("c")]},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}]
    attempt("excluded_repeat_after_removal", cfg, ev, rows_for(ev, e2="default/a", e4="default/b", e7="default/b"),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # the same inputs with Go returning C are legal; cross-engine the third attempt can only be
    # expressed as {b,c} minus the engine's complete history; Go's row is also validated
    attempt("reset_only_when_exhausted", cfg, ev, rows_for(ev, e2="default/a", e4="default/b", e7="default/c"),
            lambda d, r: ("ok: full engine-relative cycle over {b,c}") if d and d["events"][7]["expect"].get("legal_backends") == ["default/b", "default/c"] and d["events"][7]["expect"].get("exclude_history") and "exclusion-history" not in r else f"NOT CAUGHT ({r})")
    # per-group failover guard: list hits only the 6000 group's single backend -> ignored there
    ev = [{"op": "health", "backends": [hb("127.0.0.1:4001", port="6000"), hb("127.0.0.1:4002", port="6001")]},
          {"op": "config", "toml": '[proxy]\nfail-backend-list = ["127.0.0.1:4001"]\nfailover-timeout = 1\n'},
          {"op": "open", "session": "s", "port": "6000"}, {"op": "next", "session": "s"},
          {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}, {"op": "checkpoint"}]
    attempt("per_group_failover_guard", {"policy": "connection", "selection": "random", "rule": "port"}, ev,
            rows_for(ev, e3="default/127.0.0.1:4001"),
            lambda d, r: "ok: unique 4001" if d and d["events"][3]["expect"].get("backend") == "default/127.0.0.1:4001" and d["events"][6]["expect"]["healthy_backend_count"] == 2 else f"NOT CAUGHT ({r})")
    # location/random: A local fails, retry legally returns remote B
    ev = [{"op": "health", "backends": [hb("a", local=True), hb("b", local=False)]}, {"op": "open", "session": "s"},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False}, {"op": "close", "session": "s"}]
    attempt("location_random_retry", {"policy": "location", "selection": "random", "rule": ""}, ev,
            rows_for(ev, e2="default/a", e4="default/b"),
            lambda d, r: "ok: legal {a,b} minus each engine's complete cycle" if d and d["events"][2]["expect"].get("legal_backends") == ["default/a", "default/b"] and d["events"][4]["expect"].get("legal_backends") == ["default/a", "default/b"] and d["events"][4]["expect"].get("exclude_history") and not r else f"NOT CAUGHT ({r})")
    # never-healthy backend is unknown to Lookup
    ev = [{"op": "health", "backends": [hb("a"), hb("n", healthy=False)]}, {"op": "lookup", "backend": "default/n"}, {"op": "checkpoint"}]
    rows = rows_for(ev); rows[1]["outcome"] = "unknown_backend"
    attempt("never_healthy_lookup", cfg, ev, rows,
            lambda d, r: "ok: unknown_backend derived" if d and d["events"][1]["expect"]["outcome"] == "unknown_backend" else f"NOT CAUGHT ({r})")
    # pending reservation (Next ok, no Finish) keeps a removed backend retained
    ev = [{"op": "health", "backends": [hb("a")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
          {"op": "health", "backends": []}, {"op": "lookup", "backend": "default/a"},
          {"op": "finish", "session": "s", "success": False}, {"op": "health", "backends": []}, {"op": "lookup", "backend": "default/a"}, {"op": "close", "session": "s"}]
    rows = rows_for(ev, e2="default/a"); rows[4]["backend"] = "default/a"; rows[7]["outcome"] = "unknown_backend"
    attempt("pending_reservation_retains", cfg, ev, rows,
            lambda d, r: "ok: retained while pending, removed once idle" if d and d["events"][4]["expect"]["outcome"] == "ok" and d["events"][7]["expect"]["outcome"] == "unknown_backend" else f"NOT CAUGHT ({r})")
    # Random history + an effectless tick is now closed by the bounded
    # engine-relative Connection cadence predicate, without recorded ownership.
    ev = [{"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
          {"op": "finish", "session": "s", "success": True}, {"op": "tick"}, {"op": "close", "session": "s"}]
    attempt("relative_effectless_tick_derived", cfg, ev, rows_for(ev, e2="default/a"),
            lambda d, r: "ok: engine-relative empty tick" if d and not r and "redirect_cadence" in d["events"][4]["expect"] else f"NOT CAUGHT ({r})")
    # Prefer-idle with two candidates is a policy constraint. An older recorded
    # trace that claims metric observations without whole publications also
    # needs metrics-input; raw writer manifests never make this policy decision.
    ev = [{"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
          {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}]
    attempt("prefer_idle_policy_constraint", {"policy": "resource", "selection": "prefer-idle", "rule": ""}, ev, rows_for(ev, e2="default/a"),
            lambda d, r: "ok: requires " + str(r) if d and r == ["policy-constraint:resource/prefer-idle"] else f"NOT CAUGHT ({r})")
    try:
        _, req = derive({"config": {"policy": "resource", "selection": "prefer-idle", "rule": ""}, "provenance": {"kind": "recorded"}, "events": ev}, rows_for(ev, e2="default/a"), None)
        out["prefer_idle_recorded_metrics_input"] = "ok: requires " + str(req) if "metrics-input" in req else f"NOT CAUGHT ({req})"
    except Refuse as e:
        out["prefer_idle_recorded_metrics_input"] = f"NOT CAUGHT (refused: {e})"
    packet = dict.fromkeys(_RUNNER.METRIC_KEYS)
    observed = ev[:1] + [{"op":"metrics", "queries":packet}] + ev[1:]
    try:
        _, req = derive({"config":{"policy":"connection", "selection":"random", "rule":""},
                         "provenance":{"kind":"recorded", "metrics_observed":True},
                         "events":observed}, rows_for(observed, e3="default/a"), None)
        out["connection_recorded_metrics_not_required"] = "ok: whole input supplied and policy does not consume it" if not req else f"NOT CAUGHT ({req})"
    except Refuse as e:
        out["connection_recorded_metrics_not_required"] = f"NOT CAUGHT (refused: {e})"
    # Actual whole publications close the input dependency even at Go zero time;
    # they do not close the independent general policy constraint.
    for stamp in [None, 0]:
        packet = dict.fromkeys(_RUNNER.METRIC_KEYS)
        packet["cpu"] = {"kind":"matrix", "updated_nanos":stamp, "series":[
            {"labels":{"instance":"127.0.0.1:10080"}, "samples":[{"timestamp_ms":0, "value":"0.1"}]}]}
        observed = ev[:1] + [{"op":"metrics", "queries":packet}] + ev[1:]
        attempt(f"whole_metrics_time_{stamp}", {"policy":"resource", "selection":"prefer-idle", "rule":""}, observed,
                rows_for(observed, e3="default/a"),
                lambda d, r: "ok: policy remains, input supplied" if d and r == ["policy-constraint:resource/prefer-idle"] else f"NOT CAUGHT ({r})")
    # A complete fresh CPU-only packet determines Resource/prefer-idle without
    # consulting the recorded result: both backends are otherwise identical.
    resource_backends = [dict(hb("127.0.0.1:4000", cluster=""), status_port=10080),
                         dict(hb("127.0.0.1:4001", cluster=""), status_port=10081)]
    packet = dict.fromkeys(_RUNNER.METRIC_KEYS)
    packet["cpu"] = {"kind":"matrix", "updated_nanos":1_800_000_000_000_000_000, "series":[
        {"labels":{"instance":"127.0.0.1:10080"}, "samples":[{"timestamp_ms":1_800_000_000_000, "value":"0.1"}]},
        {"labels":{"instance":"127.0.0.1:10081"}, "samples":[{"timestamp_ms":1_800_000_000_000, "value":"0.9"}]}]}
    ev = [{"op":"health", "backends":resource_backends}, {"op":"metrics", "queries":packet},
          {"op":"open", "session":"s"}, {"op":"next", "session":"s"},
          {"op":"finish", "session":"s", "success":False}, {"op":"close", "session":"s"}]
    resource_cfg = {"policy":"resource", "selection":"prefer-idle", "rule":"",
                    "clock_origin_nanos":1_800_000_000_000_000_000}
    attempt("resource_cpu_public_packet", resource_cfg, ev, rows_for(ev, e3="127.0.0.1:4000"),
            lambda d, r: "ok: CPU selects 4000" if d and not r and d["events"][3]["expect"].get("backend") == "127.0.0.1:4000" else f"NOT CAUGHT ({r})")
    attempt("resource_cpu_wrong_result", resource_cfg, ev, rows_for(ev, e3="127.0.0.1:4001"),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # location/prefer-idle: one local and one remote → the local is unique; two locals → constraint
    ev = [{"op": "health", "backends": [hb("a", local=True), hb("b", local=False)]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
          {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}]
    attempt("location_prefer_idle_local_unique", {"policy": "location", "selection": "prefer-idle", "rule": ""}, ev, rows_for(ev, e2="default/a"),
            lambda d, r: "ok: unique local a" if d and d["events"][2]["expect"].get("backend") == "default/a" and not r else f"NOT CAUGHT ({r})")
    attempt("location_prefer_idle_remote_rejected", {"policy": "location", "selection": "prefer-idle", "rule": ""}, ev, rows_for(ev, e2="default/b"),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # full TOML: single-quoted strings and a multi-line array must be honoured
    ev = [{"op": "health", "backends": [hb("a"), hb("b")]},
          {"op": "config", "toml": "[proxy]\nfail-backend-list = [\n  'a', # comment with \"quotes\"\n]\nfailover-timeout = 1\n"},
          {"op": "open", "session": "s"}, {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}]
    attempt("toml_full_parser", cfg, ev, rows_for(ev, e3="default/b"),
            lambda d, r: "ok: unique b after failover" if d and d["events"][3]["expect"].get("backend") == "default/b" else f"NOT CAUGHT ({r})")
    ev2 = copy.deepcopy(ev); ev2[1]["toml"] = "[balance]\nlabel-name = 'zone'\n"
    attempt("toml_unsupported_key_refused", cfg, ev2, rows_for(ev2, e3="default/b"),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # failover-timeout force_close is derived from inputs and time: missing at the deadline
    # tick → refused; injected before the deadline → refused; exact at the deadline → derived.
    redirect = {"kind": "redirect", "session": "s", "operation": "s/1", "from": "default/a", "to": "default/b", "accepted": True}
    fc = {"kind": "force_close", "session": "s", "operation": "s/2", "from": "default/a", "to": "", "accepted": True}
    ev = [{"op": "health", "backends": [hb("a"), hb("b", healthy=False)], "at_nanos": 0}, {"op": "open", "session": "s", "at_nanos": 0}, {"op": "next", "session": "s", "at_nanos": 0},
          {"op": "finish", "session": "s", "success": True, "at_nanos": 0}, {"op": "health", "backends": [hb("a"), hb("b")], "at_nanos": 0},
          {"op": "config", "toml": '[proxy]\nfail-backend-list = ["a"]\nfailover-timeout = 1\n', "at_nanos": 500},
          {"op": "tick", "at_nanos": 1_000_000_499}, {"op": "tick", "at_nanos": 1_000_000_500}, {"op": "close", "session": "s", "at_nanos": 1_000_000_500}]
    # The pre-deadline tick already migrates this unhealthy source. The later
    # close still targets its physical source while that request is in flight.
    base = rows_for(ev, e2="default/a"); base[6]["effects"] = [redirect]; base[7]["effects"] = [fc]
    attempt("forceclose_derived_at_deadline", cfg, ev, copy.deepcopy(base),
            lambda d, r: "ok: redirect before deadline, force_close at deadline" if d and not r and d["events"][7]["expect"].get("effects") == [fc] and d["events"][6]["expect"].get("effects") == [redirect] else f"NOT CAUGHT ({r})")
    bad = copy.deepcopy(base); bad[7]["effects"] = []
    attempt("forceclose_dropped_refused", cfg, ev, bad, lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    bad = copy.deepcopy(base); bad[6]["effects"] = [redirect, fc]
    attempt("forceclose_early_refused", cfg, ev, bad, lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # retention recovery: random A/B, A unhealthy then healthy again → Lookup A is known
    ev = [{"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True},
          {"op": "health", "backends": [hb("a", healthy=False), hb("b")]}, {"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "lookup", "backend": "default/a"}, {"op": "close", "session": "s"}]
    rows = rows_for(ev, e2="default/a"); rows[6]["backend"] = "default/a"
    attempt("retention_recovery_lookup", cfg, ev, rows,
            lambda d, r: "ok: lookup a known after recovery" if d and d["events"][6]["expect"].get("backend") == "default/a" else f"NOT CAUGHT ({r})")
    # Refused redirects have no callback authority: deleting the row must still
    # leave migration-cadence unresolved, even when the initial choice was unique.
    ev = [{"op": "health", "backends": [hb("a")]}, {"op": "open", "session": "s"},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True},
          {"op": "health", "backends": [hb("a"), hb("b")]},
          {"op": "tick", "refuse": ["s"]}, {"op": "close", "session": "s"}]
    base = rows_for(ev, e2="default/a")
    effect = {"kind": "redirect", "session": "s", "operation": "s/1", "from": "default/a", "to": "default/b", "accepted": False}
    for present in (True, False):
        rows = copy.deepcopy(base)
        if present:
            rows[5]["effects"] = [effect]
        # A shared 1/0 connection count is neutral at ratio 1.2. The new
        # input-derived cadence rejects the fabricated redirect itself and
        # proves the empty tick instead of leaving either result withheld.
        if present:
            attempt("neutral_connection_redirect_refused", cfg, ev, rows,
                    lambda d, r: f"refused: {r}" if d is None else "NOT CAUGHT")
        else:
            attempt("neutral_connection_empty_tick_derived", cfg, ev, rows,
                    lambda d, r: "ok: neutral pair has no effect" if d and not r else f"NOT CAUGHT ({r})")
    # Go resets at the singleton-A update, while an engine that first chose B
    # need not reset. Keep the later A/B/C constraint relative for both histories.
    relative_ev = [{"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "open", "session": "s"},
                   {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
                   {"op": "health", "backends": [hb("a")]}, {"op": "next", "session": "s"},
                   {"op": "finish", "session": "s", "success": False},
                   {"op": "health", "backends": [hb("a"), hb("b"), hb("c")]}, {"op": "next", "session": "s"},
                   {"op": "finish", "session": "s", "success": False}, {"op": "close", "session": "s"}]
    attempt("relative_history_survives_one_engine_reset", cfg, relative_ev, rows_for(relative_ev, e2="default/a", e5="default/a", e8="default/b"),
            lambda d, r: "ok: full cycle retained after Go-only reset" if d and d["events"][8]["expect"].get("exclude_history") and d["events"][8]["expect"].get("legal_backends") == ["default/a", "default/b", "default/c"] and not r else f"NOT CAUGHT ({r})")
    # Every delivered entry participates in Go's support-redirection AND,
    # including an unhealthy never-retained entry.
    disabled = copy.deepcopy(ev)
    unsupported = hb("never", healthy=False); unsupported["support_redirection"] = False
    disabled[4]["backends"].append(unsupported)
    attempt("unsupported_entry_disables_balance", cfg, disabled, copy.deepcopy(base),
            lambda d, r: "ok: disabled by whole health input" if d and "migration-cadence" not in r else f"NOT CAUGHT ({r})")
    injected = copy.deepcopy(base); injected[5]["effects"] = [effect]
    attempt("redirect_while_disabled_refused", cfg, disabled, injected,
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    # Disabled migration + no failover deadline proves an empty tick for every
    # engine, even after non-unique selection. Turning capability back on or
    # marking a possibly-owned backend for failover must check each engine's owner.
    no_effect = [{"op": "health", "backends": [dict(hb("a"), support_redirection=False), hb("b")]},
                 {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
                 {"op": "finish", "session": "s", "success": True}, {"op": "tick"}, {"op": "close", "session": "s"}]
    attempt("disabled_nonunique_empty_tick", cfg, no_effect, rows_for(no_effect, e2="default/a"),
            lambda d, r: "ok: empty effect set proven from disabled input" if d and not r else f"NOT CAUGHT ({r})")
    due = copy.deepcopy(no_effect)
    due.insert(4, {"op": "config", "toml": '[proxy]\nfail-backend-list = ["a"]\nfailover-timeout = 0\n'})
    attempt("disabled_nonunique_due_missing_close_refused", cfg, due, rows_for(due, e2="default/a"),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    for mode in ("closed", "no_destination"):
        exhausted = copy.deepcopy(no_effect)
        exhausted[0]["backends"][0]["support_redirection"] = True
        if mode == "closed":
            exhausted[4:6] = [{"op": "close", "session": "s"}, {"op": "health", "backends": []}, {"op": "tick"}]
        else:
            exhausted.insert(4, {"op": "health", "backends": []})
        attempt("nonunique_empty_tick_" + mode, cfg, exhausted, rows_for(exhausted, e2="default/a"),
                lambda d, r: "ok: no connection/destination for migration" if d and not r else f"NOT CAUGHT ({r})")
    # Recorded preference must reject a busy result, not merely emit a flag.
    pref = [{"op": "health", "backends": [hb("a"), hb("b")]}]
    choices = {}
    for sid in ("s1", "s2", "s3"):
        pref += [{"op": "open", "session": sid}, {"op": "next", "session": sid}, {"op": "finish", "session": sid, "success": True}]
        choices[f"e{len(pref)-2}"] = "default/b" if sid == "s3" else "default/a"
    pref += [{"op": "close", "session": sid} for sid in ("s1", "s2", "s3")]
    pref_cfg = dict(cfg, selection="prefer-idle")
    attempt("connection_preference_from_own_public_history", pref_cfg, pref, rows_for(pref, **choices),
            lambda d, r: "ok: per-engine connection predicate" if d and not r and d["events"][8]["expect"].get("prefer_idle_conn") else f"NOT CAUGHT ({r})")
    choices["e8"] = "default/a"
    attempt("connection_busy_recorded_choice_refused", pref_cfg, pref, rows_for(pref, **choices),
            lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trace", type=Path, help="recorded trace (expect blocks ignored if present)")
    ap.add_argument("rows", type=Path, help="recorded Go rows (go.json) for the same events")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--check-against", type=Path, help="hand-written trace with expect blocks (regression)")
    ap.add_argument("--self-check", action="store_true", help="mutate the recorded rows and prove the deriver/regression reject wrong backend, wrong error class and a dropped effect; run the reviewer counterexamples")
    args = ap.parse_args()
    trace = json.loads(args.trace.read_text())
    stripped = copy.deepcopy(trace)
    for e in stripped["events"]:
        e.pop("expect", None)
    rows = json.loads(args.rows.read_text())
    if isinstance(rows, dict):
        rows = rows.get("rows", rows)
    try:
        derived, requires = derive(stripped, rows, args)
    except Refuse as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        sys.exit(2)
    derived["provenance"] = dict(trace.get("provenance", {}), derived_by="derive_expectations.py")
    if requires:
        derived["provenance"]["requires"] = requires
    if args.output:
        encoded = json.dumps(derived, indent=2) + "\n"
        if len(encoded.encode()) > _RUNNER.MAX_BYTES:
            encoded = json.dumps(derived, separators=(",", ":")) + "\n"
        if len(encoded.encode()) > _RUNNER.MAX_BYTES:
            print(f"REFUSED: derived trace exceeds {_RUNNER.MAX_BYTES} bytes", file=sys.stderr)
            sys.exit(2)
        args.output.write_text(encoded)
    print(json.dumps({"events": len(derived["events"]), "requires": requires}))
    if args.check_against:
        reference = json.loads(args.check_against.read_text())
        diffs, withheld = compare_with_reference(derived, reference, requires)
        for d in diffs:
            print("DIFF", *d)
        print(json.dumps({"reference_diffs": len(diffs), "withheld_effects": withheld}))
        if args.self_check:
            self_check(stripped, rows, reference, requires)
        sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
