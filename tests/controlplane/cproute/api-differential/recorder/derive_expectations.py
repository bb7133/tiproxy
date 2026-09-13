#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Derive trace v1 `expect` blocks from recorded public inputs (contract a9c497c3 §2).

Input : a recorded trace (events without `expect`) and the recorded Go rows for the same
        events (output evidence: per-event outcome/backend/effects).
Output: the trace with `expect` per event, plus a `requires` list naming every runner
        dependency the slot needs before it can count (effects-v2, metrics-input,
        policy-constraint:<pair>). Dependencies are decided from the
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
  Resource/Location metric advice remains a policy-constraint.
- failover guard is evaluated per group: the list is ignored for a group only when it would
  leave that group without a routeable backend (group.go:286-341); the timeout does not
  gate the marking (router.go:160-165, Healthy = observed && not in failover).
- retention: a backend enters `router.backends` when first consumed healthy; it leaves when
  consumed unhealthy/absent and idle — no listed connection, no pending reservation, no
  in-flight redirect score (router_score.go:264, 340-356, group.go:222-238). Rehydrate
  additionally needs group ownership (group.go:514-520).
- healthy Connection migration: shared constrained assignments determine the pair,
  rate, physical insertion order, accepted-request cadence and failure cooldown.
  Non-unique histories and distinguishable tied pairs remain migration dependencies.
"""

import argparse
import copy
from collections import Counter
import importlib.util
import ipaddress
import json
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
    __slots__ = ("id", "address", "cluster", "keyspace", "labels", "local", "observed_healthy", "version", "group", "ambiguous", "failover_since", "support_redirection")

    def __init__(self, bid, b):
        self.id = bid
        self.group = None
        self.ambiguous = False
        self.failover_since = None  # logical instant the backend entered failover (kept while marked)
        self.update(b)

    def update(self, b):
        self.address = b["address"]
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
        if self.rule not in {"", "port"} | CIDR_RULES:
            self.requires.add(f"policy-constraint:{self.rule}")

    # --- helpers -------------------------------------------------------------------------
    def held_possible(self, bid):
        return any(bid in s.possible() for s in self.sessions.values())

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

    # --- inputs (router_score.go updateBackendHealth / updateGroups / group.UpdateFailover) ---
    def apply_health(self, backends):
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
                    self.groups.setdefault(value, set()).add(bid)
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
                    self.groups[group] = set()
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

    def apply_config(self, toml):
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
        # balance.routing-rule at runtime is ignored by the router (matchType fixed at Init).
        self.update_failover()

    def update_failover(self):
        """group.go:286-341 per group; Healthy() = observed && not marked (router.go:160-165).
        failoverSince is set when a backend enters failover and kept while it stays marked
        (router.go:178-190); it is the logical clock of the consuming event."""
        marked_now = set()
        for value, members in self.groups.items():
            routeable = [bid for bid in members if self.backends[bid].observed_healthy]
            marked = {bid for bid in members if self.backends[bid].address in self.fail_list}
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
    """Predict healthy Connection balance from an already constrained public history.

    None means the existing migration dependency is still required. In particular,
    a recorded choice or an unverified earlier migration must not select a pair or
    seed this clock. Tied pairs are resolved only if every choice has the same
    observable effects; otherwise no observed Go effect is turned into an oracle.
    """
    if (state.policy != "connection" or not state.unique_history
            or "migration-cadence" in state.requires
            or state.ambiguous_group_clocks
            or state.recorded_connections.label_name
            or any(not state.healthy(bid) or b.ambiguous for bid,b in state.backends.items())):
        return None
    if any(len(owners) != 1 for s in state.sessions.values()
           for owners in (s.pending,s.assigned,s.inflight) if owners):
        return None
    counts, physical = Counter(), Counter()
    for session in state.sessions.values():
        if session.pending:
            counts[next(iter(session.pending))] += 1
        if session.assigned:
            owner = next(iter(session.assigned))
            physical[owner] += 1
            counts[owner] += 1
            if session.inflight:
                counts[owner] -= 1
                counts[next(iter(session.inflight))] += 1
    out = []
    ratio, override = state.recorded_connections.ratio, state.recorded_connections.rate
    for group,members in sorted(state.groups.items()):
        if len(members) <= 1:
            continue
        bits = {bid:min(counts[bid],65535) for bid in members}
        minimum = min(bits.values())
        alternatives = []
        for target in sorted(bid for bid in members if bits[bid] == minimum):
            sources = []
            for source in members:
                if bits[source] <= minimum or physical[source] == 0 or counts[source] <= 0:
                    continue
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


def remember_redirect(state, effect):
    session = state.sessions[effect["session"]]
    session.ordinal += 1
    session.last_redirect = state.now
    session.redirect_failed = not effect["accepted"]
    if effect["accepted"]:
        legal = state.migration_targets(effect["from"])
        session.inflight = (frozenset([effect["to"]]) if len(session.assigned) == 1 and state.unique_history
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


def derive_tick_effects(state, refused):
    """group.go:542-587 CloseTimedOutFailoverConnections at every rebalance: every listed
    connection on a backend whose failover has lasted >= failover-timeout (or immediately when
    the timeout is 0) receives ForceClose; accepted ones are not repeated, refused ones are
    retried on the next tick. Listed = the session's current assignment (its physical list
    owner, also while a redirect is in flight). A non-unique assignment cannot place the
    connection → the slot needs effects-v2 and nothing is emitted for it."""
    out = []
    due = due_failover_backends(state)
    if not due:
        return out
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
        accepted = s.id not in refused
        out.append({"kind": "force_close", "session": s.id, "operation": f"{s.id}/{s.ordinal}", "from": bid, "to": "", "accepted": accepted})
        if accepted:
            s.force_closing = True
    return out


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
    if session.relative_history:
        # Publish candidates before exclusions; the comparator subtracts each
        # engine's complete cycle and resets only when its own set is exhausted.
        legal, _ = state.candidates(session)
        expect["exclude_history"] = True
    else:
        legal = legal_go
    if state.selection == "prefer-idle":
        # factor_balance.go:287-345 evicts a candidate when a higher-priority factor advises
        # migration. Under `location` the location factor precedes every metric factor, so a
        # remote candidate is evicted whenever a local one exists — deterministic from inputs.
        # Every other eviction (conn-count, health/memory/cpu) is not derivable: constraint.
        if state.policy == "location":
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
        elif len(legal) > 1:
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
            state.metrics_observed |= any(result is not None and result["series"] for result in event["queries"].values())
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
            # Whether a migration could be due is a property of inputs and
            # session history. Deleting its observed output must not remove
            # this dependency. A whole health result can disable Balance,
            # while the independent failover-close pass still runs.
            migration_possible = state.support_redirection and any(
                s.assigned and not s.force_closing and not s.inflight
                and any(state.migration_targets(bid) for bid in s.assigned)
                for s in state.sessions.values()
            )
            predicted = derive_connection_redirects(state, refused) if migration_possible else []
            modeled = predicted is not None
            if migration_possible and not modeled:
                state.requires.add("migration-cadence")
            # Redirects (group.Balance) are issued before the failover close pass in the same
            # iteration (router_score.go:471-483), so their ordinals come first.
            # Check public ownership/destination/acceptance for all redirects.
            # Modeled timing is compared against its independent prediction;
            # other factor/history cases remain withheld, never copied.
            leftover = []
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
                if ef["accepted"] == (ef["session"] in refused):
                    raise Refuse(f"seq {seq}: effect {ef['operation']} acceptance contradicts the scripted refusal")
                legal_to = state.migration_targets(ef["from"])
                if ef["to"] not in legal_to:
                    raise Refuse(f"seq {seq}: redirect destination {ef['to']!r} not in the legal set {sorted(legal_to)}")
                remember_redirect(state, ef)
                if not modeled:
                    state.requires.add("migration-cadence")
                if not state.unique_history and not modeled:
                    state.requires.add("effects-v2")
            if modeled and _RUNNER.causal([ef for ef in recorded if ef["kind"] == "redirect"]) != _RUNNER.causal(predicted):
                raise Refuse(f"seq {seq}: redirect effects contradict the input-derived connection cadence: expected {predicted}")
            if not state.unique_history and migration_possible and not modeled:
                # A possible migration after non-unique routing depends on
                # each engine's assignments. No session/destination means no
                # migration for every engine, including empty-health ticks.
                state.requires.add("effects-v2")
            relative_close = not migration_possible and not state.unique_history
            if relative_close:
                # The due backend set is defined by public config/health/time.
                # Each engine resolves its own owners and accepted-close history;
                # only Go's own rows are used to validate this recording here.
                due = sorted(due_failover_backends(state))
                expect["force_close_due"] = due
                derived = state.recorded_connections.force_close_effects(event, due)
            else:
                derived = derive_tick_effects(state, refused)
            if key_effects(leftover) != key_effects(derived):
                raise Refuse(f"seq {seq}: recorded force_close effects {leftover} differ from the failover-timeout derivation {derived}")
            if derived and not relative_close:
                expect["effects"] = derived
            if modeled and predicted:
                expect["effects"] = predicted + derived
            if state.policy in METRIC_POLICIES and state.metrics_observed:
                state.requires.add("metrics-input")  # migration advice consults metric factors
        elif op == "redirect_result":
            operation = event["operation"]
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
        try:
            state.recorded_connections.apply(event, row)
        except _RUNNER.Difference as error:
            raise Refuse(f"seq {seq}: {error}") from error
        e = dict(event)
        e["expect"] = expect
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
    # random history + tick without effects still requires effects-v2 (input/history decides)
    ev = [{"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
          {"op": "finish", "session": "s", "success": True}, {"op": "tick"}, {"op": "close", "session": "s"}]
    attempt("effects_v2_without_effect", cfg, ev, rows_for(ev, e2="default/a"),
            lambda d, r: "ok: requires effects-v2" if d and "effects-v2" in r else f"NOT CAUGHT ({r})")
    # prefer-idle with two candidates is a policy constraint; resource adds metrics-input
    ev = [{"op": "health", "backends": [hb("a"), hb("b")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"},
          {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}]
    attempt("prefer_idle_policy_constraint", {"policy": "resource", "selection": "prefer-idle", "rule": ""}, ev, rows_for(ev, e2="default/a"),
            lambda d, r: "ok: requires " + str(r) if d and r == ["policy-constraint:resource/prefer-idle"] else f"NOT CAUGHT ({r})")
    try:
        _, req = derive({"config": {"policy": "resource", "selection": "prefer-idle", "rule": ""}, "provenance": {"kind": "recorded"}, "events": ev}, rows_for(ev, e2="default/a"), None)
        out["prefer_idle_recorded_metrics_input"] = "ok: requires " + str(req) if "metrics-input" in req else f"NOT CAUGHT ({req})"
    except Refuse as e:
        out["prefer_idle_recorded_metrics_input"] = f"NOT CAUGHT (refused: {e})"
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
    fc = {"kind": "force_close", "session": "s", "operation": "s/1", "from": "default/a", "to": "", "accepted": True}
    ev = [{"op": "health", "backends": [hb("a"), hb("b", healthy=False)], "at_nanos": 0}, {"op": "open", "session": "s", "at_nanos": 0}, {"op": "next", "session": "s", "at_nanos": 0},
          {"op": "finish", "session": "s", "success": True, "at_nanos": 0}, {"op": "health", "backends": [hb("a"), hb("b")], "at_nanos": 0},
          {"op": "config", "toml": '[proxy]\nfail-backend-list = ["a"]\nfailover-timeout = 1\n', "at_nanos": 500},
          {"op": "tick", "at_nanos": 1_000_000_499}, {"op": "tick", "at_nanos": 1_000_000_500}, {"op": "close", "session": "s", "at_nanos": 1_000_000_500}]
    base = rows_for(ev, e2="default/a"); base[7]["effects"] = [fc]
    attempt("forceclose_derived_at_deadline", cfg, ev, copy.deepcopy(base),
            lambda d, r: "ok: force_close expected at the deadline tick" if d and d["events"][7]["expect"].get("effects") == [fc] and not d["events"][6]["expect"].get("effects") else f"NOT CAUGHT ({r})")
    bad = copy.deepcopy(base); bad[7]["effects"] = []
    attempt("forceclose_dropped_refused", cfg, ev, bad, lambda d, r: "NOT CAUGHT" if d else f"refused: {r}")
    bad = copy.deepcopy(base); bad[6]["effects"] = [dict(fc, operation="s/injected")]
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
        args.output.write_text(json.dumps(derived, indent=2) + "\n")
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
