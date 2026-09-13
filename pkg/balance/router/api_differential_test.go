// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	replayclock "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/clock"
	replaymetrics "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/metrics"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type apiTraceConfig struct {
	ClockOriginNanos *int64 `json:"clock_origin_nanos,omitempty"`
	Policy           string `json:"policy"`
	Selection        string `json:"selection"`
	Rule             string `json:"rule"`
}

type apiTraceBackend struct {
	Address            string            `json:"address"`
	Labels             map[string]string `json:"labels"`
	Cluster            *string           `json:"cluster,omitempty"`
	Keyspace           string            `json:"keyspace,omitempty"`
	IP                 *string           `json:"ip,omitempty"`
	StatusPort         uint              `json:"status_port,omitempty"`
	Healthy            *bool             `json:"healthy,omitempty"`
	Local              *bool             `json:"local,omitempty"`
	ServerVersion      string            `json:"server_version,omitempty"`
	SupportRedirection *bool             `json:"support_redirection,omitempty"`
}

func apiBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
func apiString(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}

type apiTraceEvent struct {
	Queries    map[string]*replaymetrics.Result `json:"queries,omitempty"`
	Op         string                           `json:"op"`
	Session    string                           `json:"session,omitempty"`
	Client     string                           `json:"client,omitempty"`
	Proxy      string                           `json:"proxy,omitempty"`
	Port       string                           `json:"port,omitempty"`
	Backends   []apiTraceBackend                `json:"backends,omitempty"`
	Success    bool                             `json:"success,omitempty"`
	TOML       string                           `json:"toml,omitempty"`
	AtNanos    int64                            `json:"at_nanos,omitempty"`
	Backend    string                           `json:"backend,omitempty"`
	Operation  string                           `json:"operation,omitempty"`
	EffectRef  string                           `json:"effect_ref,omitempty"`
	Optional   bool                             `json:"optional_effect,omitempty"`
	Refuse     []string                         `json:"refuse,omitempty"`
	RefuseNext int                              `json:"refuse_next,omitempty"`
	Error      string                           `json:"error,omitempty"`
}

// The test overlays route/group/factor clocks to one public event timestamp.
//
//nolint:unused // Called by the generated test build overlay.
func apiReplayNow() time.Time { return replayclock.Now() }

type apiEffect struct {
	Kind      string `json:"kind"`
	Session   string `json:"session"`
	Operation string `json:"operation"`
	From      string `json:"from"`
	To        string `json:"to"`
	Accepted  bool   `json:"accepted"`
}
type apiOperation struct {
	effect    apiEffect
	conn      *apiConn
	from, to  BackendInst
	completed bool
}
type apiConn struct {
	*mockRedirectableConn
	id         string
	ordinal    int
	refuse     bool
	refuseNext *int
	effects    *[]apiEffect
	operations map[string]*apiOperation
}

func (c *apiConn) record(kind string, to BackendInst, accepted bool) {
	c.ordinal++
	effect := apiEffect{Kind: kind, Session: c.id, Operation: fmt.Sprintf("%s/%d", c.id, c.ordinal), From: c.from.ID(), Accepted: accepted}
	if to != nil {
		effect.To = to.ID()
	}
	*c.effects = append(*c.effects, effect)
	if accepted {
		c.operations[effect.Operation] = &apiOperation{effect: effect, conn: c, from: c.from, to: to}
	}
}
func (c *apiConn) Redirect(to BackendInst) bool {
	refused := c.refuse
	if !refused && *c.refuseNext > 0 {
		(*c.refuseNext)--
		refused = true
	}
	accepted := !refused && c.mockRedirectableConn.Redirect(to)
	c.record("redirect", to, accepted)
	return accepted
}
func (c *apiConn) ForceClose() bool {
	refused := c.refuse
	if !refused && *c.refuseNext > 0 {
		(*c.refuseNext)--
		refused = true
	}
	accepted := !refused && c.mockRedirectableConn.ForceClose()
	c.record("force_close", nil, accepted)
	return accepted
}

type apiMetrics struct {
	current map[string]metricsreader.QueryResult
}

func (*apiMetrics) AddQueryExpr(string, metricsreader.QueryExpr, metricsreader.QueryRule) {}
func (*apiMetrics) RemoveQueryExpr(string)                                                {}
func (m *apiMetrics) GetQueryResult(key string) metricsreader.QueryResult {
	return m.current[key]
}
func (*apiMetrics) GetBackendMetrics() []byte { return nil }

type apiAddress string

func (a apiAddress) Network() string { return "tcp" }
func (a apiAddress) String() string  { return string(a) }

func apiClientAddress(value string) net.Addr {
	if value == "" {
		return nil
	}
	// Like real connection addresses, this must be nil-capable for NetAddr2IP.
	// Keep the literal string so malformed-address cases still reach the parser.
	address := apiAddress(value)
	return &address
}

func apiError(err error) string {
	switch {
	case err == nil:
		return "ok"
	case err == ErrNoBackend:
		return "no_backend"
	case errors.Is(err, ErrNoBackend):
		return "wrapped_no_backend"
	case errors.Is(err, ErrPortConflict):
		return "port_conflict"
	case errors.Is(err, context.Canceled):
		return "source_error:cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "source_error:deadline_exceeded"
	case errors.Is(err, apiTopologyUnavailable):
		return "source_error:topology_unavailable"
	default:
		return "unclassified_source_error"
	}
}

var apiTopologyUnavailable = errors.New("topology unavailable")

func apiSourceError(name string) error {
	switch name {
	case "no_backend":
		return ErrNoBackend
	case "wrapped_no_backend":
		return fmt.Errorf("observer: %w", ErrNoBackend)
	case "port_conflict":
		return ErrPortConflict
	case "cancelled":
		return context.Canceled
	case "deadline_exceeded":
		return context.DeadlineExceeded
	case "topology_unavailable":
		return apiTopologyUnavailable
	default:
		panic("unsupported observer error input")
	}
}

// TestRouterAPIDifferential invokes the real router, selector and factor policy.
// Replay owns input delivery/ticks: after Init the background loop is drained,
// then the same health/config handlers used by that loop receive each input
// synchronously. No selected groups, scores or private ledger state are seeded.
// The separately recorded live run keeps the real loop and external sources.
func TestRouterAPIDifferential(t *testing.T) {
	path := os.Getenv("CPROUTE_API_INPUT")
	if path == "" {
		t.Skip("run tests/controlplane/cproute/api-differential/run.py")
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var trace struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		Config  apiTraceConfig  `json:"config"`
		Events  []apiTraceEvent `json:"events"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&trace))
	require.Equal(t, 1, trace.Version)
	origin := replayclock.DefaultOrigin
	if trace.Config.ClockOriginNanos != nil {
		origin = *trace.Config.ClockOriginNanos
	}
	replayclock.Reset(origin)
	manager := configmgr.NewConfigManager()
	initial := fmt.Sprintf("[balance]\npolicy=%q\nrouting-policy=%q\nrouting-rule=%q\n", trace.Config.Policy, trace.Config.Selection, trace.Config.Rule)
	require.NoError(t, manager.SetTOMLConfig([]byte(initial)))
	metricInputs := &apiMetrics{}
	r := NewScoreBasedRouter(zap.NewNop())
	ob := newMockBackendObserver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Init(ctx, ob, func(lg *zap.Logger) policy.BalancePolicy {
		return factor.NewFactorBasedBalance(lg, metricInputs)
	}, manager, nil)
	r.wg.Wait()
	t.Cleanup(r.Close)
	type slot struct {
		selector BackendSelector
		conn     *apiConn
		current  BackendInst
		active   bool
	}
	sessions := make(map[string]*slot)
	logicalSessions := make(map[string]string)
	output := make([]map[string]any, 0, len(trace.Events))
	effects := []apiEffect{}
	operations := make(map[string]*apiOperation)
	effectRefs := make(map[string]*apiOperation)
	effectRefSessions := make(map[string]string)
	skippedEffectRefs := make(map[string]struct{})
	unboundRedirects := []*apiOperation{}
	refuseNext := 0
	t.Cleanup(func() {
		if len(output) > 0 {
			output[len(output)-1]["effects"] = effects
		}
		encoded, err := json.Marshal(output)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_API_OUTPUT"), encoded, 0o600))
	})
	for index, event := range trace.Events {
		replayclock.Advance(event.AtNanos)
		effects = []apiEffect{}
		actualSession := logicalSessions[event.Session]
		if actualSession == "" {
			actualSession = event.Session
		}
		logicalActual := actualSession
		var referenced *apiOperation
		skippedEffect := false
		if event.EffectRef != "" {
			referenced = effectRefs[event.EffectRef]
			_, alreadySkipped := skippedEffectRefs[event.EffectRef]
			if referenced != nil || alreadySkipped {
				require.Equal(t, effectRefSessions[event.EffectRef], event.Session,
					"relative callback crossed sessions")
			}
			position := -1
			for i, candidate := range unboundRedirects {
				if candidate.effect.Session == logicalActual {
					position = i
					break
				}
			}
			if position < 0 && event.Op == "close" && len(unboundRedirects) > 0 {
				require.Len(t, unboundRedirects, 1, "ambiguous strict relative effect at seq=%d effect_ref=%s", index, event.EffectRef)
				position = 0
			}
			if referenced == nil && !alreadySkipped && position >= 0 {
				referenced = unboundRedirects[position]
				unboundRedirects = append(unboundRedirects[:position], unboundRedirects[position+1:]...)
				effectRefs[event.EffectRef] = referenced
				effectRefSessions[event.EffectRef] = event.Session
			}
			if referenced == nil {
				for _, candidate := range operations {
					if candidate.effect.Kind == "redirect" && candidate.effect.Session == logicalActual &&
						!candidate.completed && sessions[candidate.effect.Session] != nil {
						require.Failf(t, "same-session redirect", "seq=%d effect_ref=%s", index, event.EffectRef)
					}
				}
				require.True(t, event.Optional, "seq=%d effect_ref=%s", index, event.EffectRef)
				skippedEffectRefs[event.EffectRef] = struct{}{}
				effectRefSessions[event.EffectRef] = event.Session
				actualSession = ""
				skippedEffect = true
			} else if event.Op == "close" {
				actualSession = referenced.effect.Session
				var other string
				for logical, actual := range logicalSessions {
					if actual == actualSession {
						other = logical
						break
					}
				}
				require.NotEmpty(t, other, "relative close target")
				displaced := logicalSessions[event.Session]
				require.NotEmpty(t, displaced, "relative close logical handle")
				logicalSessions[event.Session], logicalSessions[other] = actualSession, displaced
			} else {
				actualSession = referenced.effect.Session
			}
		}
		row := map[string]any{"seq": index, "op": event.Op, "session": actualSession, "outcome": "ok", "backend": "", "effects": []any{}}
		output = append(output, row)
		s := sessions[actualSession]
		switch event.Op {
		case "metrics":
			next, err := replaymetrics.Decode(event.Queries)
			require.NoError(t, err)
			metricInputs.current = next
		case "source_error":
			r.updateBackendHealth(observer.NewHealthResult(nil, apiSourceError(event.Error)))
		case "health":
			backends := make(map[string]*observer.BackendHealth)
			for _, b := range event.Backends {
				cluster := apiString(b.Cluster, "default")
				id := b.Address
				if cluster != "" {
					id = cluster + "/" + id
				}
				backends[id] = &observer.BackendHealth{BackendInfo: observer.BackendInfo{
					Addr: b.Address, ClusterName: cluster, IP: apiString(b.IP, "127.0.0.1"), Labels: b.Labels,
					Keyspace: b.Keyspace, StatusPort: b.StatusPort,
				}, Healthy: apiBool(b.Healthy, true), Local: apiBool(b.Local, true),
					ServerVersion: b.ServerVersion, SupportRedirection: apiBool(b.SupportRedirection, true)}
			}
			r.updateBackendHealth(observer.NewHealthResult(backends, nil))
		case "config":
			if event.RefuseNext > 0 {
				require.Equal(t, 1, event.RefuseNext, "one-shot refusal input at seq=%d", index)
				require.Zero(t, refuseNext, "one-shot refusal armed while one is pending at seq=%d", index)
				refuseNext = event.RefuseNext
			}
			if err := manager.SetTOMLConfig([]byte(event.TOML)); err != nil {
				row["outcome"] = "invalid_config"
			} else {
				cfg := manager.GetConfig()
				r.setConfig(cfg)
				if len(cfg.Proxy.FailBackendList) == 0 {
					require.Zero(t, refuseNext, "one-shot refusal was not consumed before failover clear at seq=%d", index)
				}
			}
		case "open":
			require.Nil(t, s, "duplicate logical session")
			logicalSessions[event.Session] = event.Session
			sessions[event.Session] = &slot{selector: r.GetBackendSelector(ClientInfo{
				ClientAddr: apiClientAddress(event.Client), ProxyAddr: apiClientAddress(event.Proxy), ListenerPort: event.Port,
			}), conn: &apiConn{mockRedirectableConn: newMockRedirectableConn(t, uint64(index+1)), id: event.Session, refuseNext: &refuseNext, effects: &effects, operations: operations}}
		case "lookup":
			backend, ok := r.LookupBackend(event.Backend)
			if !ok {
				row["outcome"] = "unknown_backend"
			} else {
				row["backend"] = backend.ID()
			}
		case "rehydrate":
			require.NotNil(t, s)
			require.False(t, s.active)
			backend, ok := r.RehydrateConn(event.Backend, s.conn)
			if !ok {
				row["outcome"] = "unknown_backend"
			} else {
				row["backend"] = backend.ID()
				s.conn.from = backend
				s.active = true
			}
		case "tick":
			if event.RefuseNext > 0 {
				require.Equal(t, 1, event.RefuseNext, "one-shot refusal input at seq=%d", index)
				require.Zero(t, refuseNext, "one-shot refusal armed while one is pending at seq=%d", index)
				refuseNext = event.RefuseNext
			}
			for id, live := range sessions {
				live.conn.refuse = false
				for _, refused := range event.Refuse {
					if id == logicalSessions[refused] {
						live.conn.refuse = true
					}
				}
			}
			r.rebalance(context.Background())
			for i := range effects {
				if effects[i].Kind == "redirect" && effects[i].Accepted {
					unboundRedirects = append(unboundRedirects, operations[effects[i].Operation])
				}
			}
		case "redirect_result":
			if skippedEffect {
				row["outcome"] = "no_effect"
				break
			}
			operation := referenced
			if operation == nil {
				operation = operations[event.Operation]
			}
			require.NotNil(t, operation, "seq=%d operation=%s", index, event.Operation)
			for i, candidate := range unboundRedirects {
				if candidate == operation {
					unboundRedirects = append(unboundRedirects[:i], unboundRedirects[i+1:]...)
					break
				}
			}
			require.Equal(t, "redirect", operation.effect.Kind)
			if event.Success {
				require.NoError(t, operation.conn.receiver.OnRedirectSucceed(operation.from.ID(), operation.to.ID(), operation.conn))
			} else {
				require.NoError(t, operation.conn.receiver.OnRedirectFail(operation.from.ID(), operation.to.ID(), operation.conn))
			}
			if !operation.completed && sessions[operation.effect.Session] != nil {
				if event.Success {
					operation.conn.from = operation.to
				}
				operation.conn.to = nil
			}
			operation.completed = true
		case "next":
			require.NotNil(t, s)
			backend, routeErr := s.selector.Next()
			row["outcome"] = apiError(routeErr)
			if backend != nil {
				row["backend"] = backend.ID()
			}
			if routeErr == nil {
				s.current = backend
			}
		case "finish":
			require.NotNil(t, s)
			require.NotNil(t, s.current)
			s.conn.from = s.current
			s.selector.Finish(s.conn, event.Success)
			s.active = event.Success
			s.current = nil
		case "close":
			require.NotNil(t, s)
			require.Nil(t, s.current, "pending creation requires its Finish callback")
			if s.active {
				require.NoError(t, s.conn.receiver.OnConnClosed(s.conn.from.ID(), s.conn))
			}
			s.selector.CloseObservation()
			kept := unboundRedirects[:0]
			for _, operation := range unboundRedirects {
				if operation.effect.Session != actualSession {
					kept = append(kept, operation)
				}
			}
			unboundRedirects = kept
			delete(sessions, actualSession)
			delete(logicalSessions, event.Session)
		case "checkpoint":
			assignments := make(map[string]string)
			for id, live := range sessions {
				if live.active {
					assignments[id] = live.conn.from.ID()
				}
			}
			row["assignments"] = assignments
			row["conn_count"] = r.ConnCount()
			row["healthy_backend_count"] = r.HealthyBackendCount()
			row["server_version"] = r.ServerVersion()
		default:
			t.Fatalf("unsupported API input %q", event.Op)
		}
		row["effects"] = effects
	}
	require.Empty(t, sessions, "trace must settle and close all logical sessions")
	require.Empty(t, logicalSessions, "trace must close every logical handle")
	require.Empty(t, unboundRedirects, "trace must close or bind every accepted redirect")
	require.Zero(t, refuseNext, "trace ended with an unconsumed one-shot refusal")
	require.Zero(t, r.ConnCount())
}
