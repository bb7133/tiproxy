// Copyright 2025 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"net"
	"reflect"
	"slices"
	"sync"
	"time"

	glist "github.com/bahlo/generic-list-go"
	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/manager/backendcluster"
	"github.com/pingcap/tiproxy/pkg/metrics"
	"github.com/pingcap/tiproxy/pkg/util/netutil"
	"go.uber.org/zap"
)

type MatchType int

const (
	// Match all connections, used when there is only one backend group.
	MatchAll MatchType = iota
	// Match connections based on the client CIDR.
	MatchClientCIDR
	// Match connections based on proxy CIDR. If proxy-protocol is disabled, route by the client CIDR.
	MatchProxyCIDR
	// Match connections based on the local SQL listener port.
	MatchPort
)

var _ ConnEventReceiver = (*Group)(nil)

type routeCheckBackend struct {
	*backendWrapper
	healthy bool
}

func (b routeCheckBackend) Healthy() bool {
	return b.healthy
}

// Group is used for one backend group that can be matched by CIDR, username, database, or resource group list.
type Group struct {
	sync.Mutex
	matchType MatchType
	lg        *zap.Logger
	policy    policy.BalancePolicy
	// The values that this group is matched by. E.g. for MatchCIDR, the value is the CIDR list.
	values []string
	// parsed CIDR list for faster match
	cidrList []*net.IPNet
	backends map[string]*backendWrapper
	// failoverTargets contains backend pod names or addresses configured in fail-backend-list.
	failoverTargets map[string]struct{}
	failoverTimeout time.Duration
	ignoreFailover  bool
	// To limit the speed of redirection.
	lastRedirectTime time.Time
	// Cross-keyspace guard evidence: attempts are counted per skip
	// decision (one per Balance round for a refused pair, never one
	// per connection) and the structured record is rate-limited per
	// group.
	crossKeyspaceSkipCount uint64
	lastCrossKeyspaceWarn  time.Time
	observation            *observation.Owner
	observationID          uint64
	balanceCapture         bool                // Fixed by the private factory; grants no scheduler capability.
	balanceCaller          *observation.Caller // Accessed only under this Group lock.
	routeCapture           bool                // Private construction only; outer selector binding remains separate.
	routeCaller            *observation.Caller // Accessed only under this Group lock.
}

func NewGroup(values []string, bpCreator func(lg *zap.Logger) policy.BalancePolicy, matchType MatchType, lg *zap.Logger) (*Group, error) {
	return newGroupObserved(values, bpCreator, matchType, lg, nil)
}

func newGroupObserved(values []string, bpCreator func(lg *zap.Logger) policy.BalancePolicy, matchType MatchType, lg *zap.Logger, owner *observation.Owner) (*Group, error) {
	return newGroupCaptured(values, bpCreator, matchType, lg, owner, nil)
}

func newGroupCaptured(values []string, bpCreator func(lg *zap.Logger) policy.BalancePolicy, matchType MatchType, lg *zap.Logger, owner *observation.Owner, native NativePolicyCreator) (*Group, error) {
	return newGroupCapture(values, bpCreator, matchType, lg, owner, native, false)
}

func newGroupBalanceCaptured(values []string, bpCreator func(lg *zap.Logger) policy.BalancePolicy, matchType MatchType, lg *zap.Logger, owner *observation.Owner, native NativePolicyCreator) (*Group, error) {
	return newGroupCapture(values, bpCreator, matchType, lg, owner, native, true)
}

// This private factory fixes both Group hooks before exposing the new Group.
// It does not install router metadata, selector retries or caller capabilities.
func newGroupRouteCaptured(values []string, bpCreator func(lg *zap.Logger) policy.BalancePolicy, matchType MatchType, lg *zap.Logger, owner *observation.Owner, native NativePolicyCreator) (*Group, error) {
	g, err := newGroupCapture(values, bpCreator, matchType, lg, owner, native, true)
	g.routeCapture = true
	return g, err
}

func newGroupCapture(values []string, bpCreator func(lg *zap.Logger) policy.BalancePolicy, matchType MatchType, lg *zap.Logger, owner *observation.Owner, native NativePolicyCreator, balanceCapture bool) (*Group, error) {
	var observationID uint64
	if owner.Enabled() {
		observationID = owner.NextIdentity()
		owner.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.GroupCreated, Group: observationID}}})
	}
	if len(values) > 0 {
		lg = lg.With(zap.Strings("values", values))
	}
	lg.Info("new group created")

	var balancePolicy policy.BalancePolicy
	if native != nil && owner.Enabled() {
		balancePolicy = native(lg.Named("policy"), owner, observationID)
	} else {
		balancePolicy = bpCreator(lg.Named("policy"))
	}
	if _, ok := balancePolicy.(*factor.FactorBasedBalance); balanceCapture && (!ok || native == nil || !owner.Native()) {
		owner.Invalidate(observation.Malformed)
	}
	group := &Group{
		balanceCapture: balanceCapture,
		observation:    owner, observationID: observationID,
		matchType:       matchType,
		lg:              lg,
		values:          values,
		backends:        make(map[string]*backendWrapper),
		failoverTargets: make(map[string]struct{}),
		policy:          balancePolicy,
	}
	group.publishPolicyObservationLocked() // construction is still private, before group publication
	err := group.parseValues()
	if err != nil {
		if owner.Enabled() {
			owner.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.GroupRemoved, Group: observationID}}})
		}
		err = errors.Wrapf(err, "failed to parse values")
	}
	return group, err
}

func (g *Group) parseValues() error {
	switch g.matchType {
	case MatchClientCIDR, MatchProxyCIDR:
		cidrList, parseErr := netutil.ParseCIDRList(g.values)
		if parseErr != nil {
			return parseErr
		}
		g.cidrList = cidrList
	}
	return nil
}

func (g *Group) Match(clientInfo ClientInfo) bool {
	return g.matchObserved(clientInfo, nil)
}

func (g *Group) matchObserved(clientInfo ClientInfo, caller *observation.Caller) bool {
	if caller != nil {
		caller.BeginRouterMatch(g.observationID)
	}
	finish := func(value bool) bool {
		if caller != nil {
			caller.EndRouterMatch(value)
		}
		return value
	}
	switch g.matchType {
	case MatchClientCIDR, MatchProxyCIDR:
		addr := clientInfo.ProxyAddr
		if g.matchType == MatchClientCIDR {
			addr = clientInfo.ClientAddr
		}
		var read func(string)
		if caller != nil {
			read = func(value string) { caller.CaptureRouterAddress(value) }
		}
		ip, err := netutil.NetAddr2IPObserved(addr, read)
		if err != nil {
			g.lg.Error("checking CIDR failed", zap.Stringer("addr", addr), zap.Error(err))
			return finish(false)
		}
		contains, err := netutil.CIDRContainsIP(g.cidrList, ip)
		if err != nil {
			g.lg.Error("checking CIDR failed", zap.Stringer("addr", addr), zap.Error(err))
		}
		return finish(contains)
	}
	return finish(true)
}

func (g *Group) EqualValues(values []string) bool {
	switch g.matchType {
	case MatchClientCIDR, MatchProxyCIDR, MatchPort:
		if len(g.values) != len(values) {
			return false
		}
		for _, v := range g.values {
			if !slices.Contains(values, v) {
				return false
			}
		}
		return true
	}
	return false
}

// Intersect returns if any cidrs are the same.
// In next-gen, backend cidrs may increase or decrease but they stay in the same group.
// E.g. enable public endpoint (3 cidrs) -> enable private endpoint (6 cidrs) -> disable public endpoint (3 cidrs).
func (g *Group) Intersect(values []string) bool {
	switch g.matchType {
	case MatchClientCIDR, MatchProxyCIDR, MatchPort:
		for _, v := range g.values {
			if slices.Contains(values, v) {
				return true
			}
		}
		return false
	}
	return false
}

// Backend CIDRs may change anytime.
// RefreshCidr recomputes CIDR values from members. It reports whether the
// refreshed values parsed; on failure the previously parsed networks stay in
// effect while g.values already holds the new raw values.
func (g *Group) RefreshCidr() bool {
	return g.refreshCidrObserved(nil)
}

// refreshCidrObserved is RefreshCidr with a metadata witness taken inside the
// Group lock: the frame is leased before the first member read, every actual
// Cidr() read is copied where it happens, and the stored result closes it.
func (g *Group) refreshCidrObserved(observe *refreshObserver) (parsed bool) {
	g.Lock()
	defer g.Unlock()
	parsed = true
	switch g.matchType {
	case MatchClientCIDR, MatchProxyCIDR:
		observe.begin(g, true)
		defer observe.cleanup()
		valueMap := make(map[string]struct{}, len(g.values))
		for _, b := range g.backends {
			cidrs := b.Cidr()
			observe.member(b.observationID, cidrs)
			for _, cidr := range cidrs {
				valueMap[cidr] = struct{}{}
			}
		}
		values := make([]string, 0, len(valueMap))
		for k := range valueMap {
			values = append(values, k)
		}
		g.values = values
		if err := g.parseValues(); err != nil {
			g.lg.Error("failed to parse values", zap.Error(err))
			parsed = false
		}
		observe.result(values, parsed)
		return parsed
	}
	observe.begin(g, false)
	defer observe.cleanup()
	observe.result(nil, true)
	return parsed
}

func (g *Group) AddBackend(backendID string, backend *backendWrapper) {
	g.addBackendObserved(backendID, backend, nil)
}

// addBackendObserved runs observe while the Group lock is still held, so a
// metadata witness for this decision is sequenced before any later callback.
func (g *Group) addBackendObserved(backendID string, backend *backendWrapper, observe func()) {
	g.Lock()
	defer g.Unlock()
	g.backends[backendID] = backend
	backend.group = g
	g.observeAccount(backend)
	if observe != nil {
		observe()
	}
}

// removeBackendIfIdle removes the backend from the group only if it has no connections and no
// pending incoming/outgoing scores. observe(removed, empty), when set, runs
// before the Group lock is released: the idle decision and its witness share
// one critical section, so a connection callback cannot slip between them.
func (g *Group) removeBackendIfIdle(backendID string, backend *backendWrapper, observe func(removed, empty bool)) (removed, empty bool) {
	g.Lock()
	defer g.Unlock()
	if observe != nil {
		defer func() { observe(removed, empty) }()
	}
	if backend.connList.Len() != 0 || backend.connScore > 0 {
		return false, false
	}
	delete(g.backends, backendID)
	if g.observation.Enabled() {
		batch := observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.RemoveAccount, Account: backend.observationID}}}
		if len(g.backends) == 0 {
			batch.Events[1] = observation.Event{Kind: observation.GroupRemoved, Group: g.observationID}
			batch.EventCount++
		}
		g.capture(batch, nil, observation.ConnectionState{}, backend)
	}
	return true, len(g.backends) == 0
}

func getConnWrapper(conn RedirectableConn) *glist.Element[*connWrapper] {
	return conn.Value(_routerKey).(*glist.Element[*connWrapper])
}

func setConnWrapper(conn RedirectableConn, ce *glist.Element[*connWrapper]) {
	conn.SetValue(_routerKey, ce)
}

func (g *Group) routeableObservedBackendsLocked(failoverBackendIDs map[string]struct{}) []policy.BackendCtx {
	backends := make([]policy.BackendCtx, 0, len(g.backends))
	for _, backend := range g.backends {
		if !backend.ObservedHealthy() {
			continue
		}
		healthy := true
		if failoverBackendIDs != nil {
			_, healthy = failoverBackendIDs[backend.ID()]
			healthy = !healthy
		}
		backends = append(backends, routeCheckBackend{
			backendWrapper: backend,
			healthy:        healthy,
		})
	}
	result := g.policy.RouteableBackends(backends)
	g.publishPolicyObservationLocked()
	return result
}

func (g *Group) backendInFailoverListLocked(backend *backendWrapper) bool {
	_, active := g.failoverTargets[backend.PodName()]
	if !active {
		_, active = g.failoverTargets[backend.Addr()]
	}
	return active
}

func (g *Group) setFailoverConfigLocked(cfg *config.Config) {
	targets := make(map[string]struct{}, len(cfg.Proxy.FailBackendList))
	for _, backend := range cfg.Proxy.FailBackendList {
		targets[backend] = struct{}{}
	}
	g.failoverTargets = targets
	g.failoverTimeout = time.Duration(cfg.Proxy.FailoverTimeout) * time.Second
}

func (g *Group) updateFailoverLocked(now time.Time) {
	failoverBackendIDs := make(map[string]struct{}, len(g.backends))
	for _, backend := range g.backends {
		if g.backendInFailoverListLocked(backend) {
			failoverBackendIDs[backend.ID()] = struct{}{}
		}
	}

	routeable := g.routeableObservedBackendsLocked(nil)
	if len(routeable) > 0 {
		remaining := g.routeableObservedBackendsLocked(failoverBackendIDs)
		if len(remaining) == 0 {
			matched := 0
			for _, backend := range routeable {
				if _, ok := failoverBackendIDs[backend.ID()]; ok {
					matched++
				}
			}
			if !g.ignoreFailover {
				g.lg.Warn("fail-backend-list would leave no routeable backend in group, ignore the list for this group",
					zap.Int("routeable_backend_count", len(routeable)),
					zap.Int("matched_routeable_backend_count", matched))
			}
			g.ignoreFailover = true
			clear(failoverBackendIDs)
		} else {
			g.ignoreFailover = false
		}
	} else {
		g.ignoreFailover = false
	}

	for _, backend := range g.backends {
		_, active := failoverBackendIDs[backend.ID()]
		since := time.Time{}
		if active {
			since = now
		}
		changed, since := backend.setFailover(since)
		if !changed {
			continue
		}
		fields := []zap.Field{
			zap.String("backend_addr", backend.Addr()),
			zap.String("backend_pod", backend.PodName()),
			zap.Duration("failover_timeout", g.failoverTimeout),
		}
		if active {
			fields = append(fields, zap.Time("failover_since", since))
			g.lg.Warn("backend enters failover", fields...)
			continue
		}
		g.lg.Info("backend exits failover", fields...)
	}
}

func (g *Group) UpdateFailover(now time.Time) {
	g.Lock()
	defer g.Unlock()
	g.updateFailoverLocked(now)
}

func (g *Group) Route(excluded []BackendInst) (policy.BackendCtx, error) {
	return g.routeObserved(excluded, nil)
}

func (g *Group) routeObserved(excluded []BackendInst, selection *selectionObservation) (policy.BackendCtx, error) {
	return g.routeWithParent(excluded, selection, nil)
}

func (g *Group) routeWithParent(excluded []BackendInst, selection *selectionObservation, parent *observation.Caller) (policy.BackendCtx, error) {
	g.Lock()
	defer g.Unlock()
	caller := parent
	if caller == nil {
		caller = g.beginRouteObservation()
	} else {
		g.routeCaller = caller
	}
	defer g.endRouteObservation(caller)
	g.captureRouteHeader(caller, selection, len(excluded))

	if len(g.backends) == 0 {
		g.observeNoRoute(selection)
		g.publishRouteObservation(caller, selection, nil)
		return nil, ErrNoBackend
	}
	backends := make([]policy.BackendCtx, 0, len(g.backends))
	for _, backend := range g.backends {
		if caller != nil {
			caller.CaptureRouteMember(backend.observationID)
		}
		healthy := backend.Healthy()
		if caller != nil {
			caller.CaptureRouteHealthy(backend.observationID, healthy)
		}
		if !healthy {
			continue
		}
		// Exclude the backends that are already tried.
		found := false
		for index, e := range excluded {
			backendID := backend.ID()
			if caller != nil {
				caller.CaptureRouteBackendID(backend.observationID, backendID)
			}
			excludedID := e.ID()
			if caller != nil {
				caller.CaptureRouteExcludedID(uint16(index), excludedID)
			}
			if backendID == excludedID {
				found = true
				break
			}
		}
		if found {
			continue
		}
		backends = append(backends, backend)
	}

	idlestBackend := g.routePolicy(backends, caller)
	g.publishPolicyObservationLocked()
	if idlestBackend == nil || reflect.ValueOf(idlestBackend).IsNil() {
		g.observeNoRoute(selection)
		g.publishRouteObservation(caller, selection, nil)
		return nil, ErrNoBackend
	}
	backend := idlestBackend.(*backendWrapper)
	backend.connScore++
	g.observeReserved(selection, backend)
	g.publishRouteObservation(caller, selection, backend)
	return backend, nil
}

// crossKeyspaceWarnInterval bounds the guard's structured evidence to
// one record per group per interval, independent of connection count.
const crossKeyspaceWarnInterval = 10 * time.Second

// logCrossKeyspaceSkip counts one refused migration attempt and emits
// the bounded structured evidence record. Callers hold the group lock.
func (g *Group) logCrossKeyspaceSkip(fromBackend, toBackend *backendWrapper,
	fromKeyspace, toKeyspace, reason string, curTime time.Time) {
	g.crossKeyspaceSkipCount++
	if curTime.Sub(g.lastCrossKeyspaceWarn) < crossKeyspaceWarnInterval {
		return
	}
	g.lastCrossKeyspaceWarn = curTime
	fields := []zap.Field{
		zap.String("from", fromBackend.addr),
		zap.String("to", toBackend.addr),
		zap.String("from_keyspace", fromKeyspace),
		zap.String("to_keyspace", toKeyspace),
		zap.String("reason", reason),
		zap.Int("blocked_conn_count", fromBackend.connList.Len()),
		zap.Uint64("skip_count", g.crossKeyspaceSkipCount),
	}
	if ele := fromBackend.connList.Front(); ele != nil {
		fields = append(fields, zap.Uint64("sample_conn_id", ele.Value.ConnectionID()))
	}
	g.lg.Warn("skip cross-keyspace redirect", fields...)
}

func (g *Group) Balance(ctx context.Context) {
	g.Lock()
	defer g.Unlock()
	caller := g.beginBalanceObservation()
	defer g.endBalanceObservation(caller)
	backends := make([]policy.BackendCtx, 0, len(g.backends))
	for _, backend := range g.backends {
		backends = append(backends, backend)
	}

	g.captureBalanceMembers(caller, backends)
	busiestBackend, idlestBackend, balanceCount, reason, logFields := g.balancePolicy(backends, caller)
	g.publishPolicyObservationLocked()
	if balanceCount == 0 {
		g.publishBalanceObservation(caller, 0)
		return
	}
	fromBackend, toBackend := busiestBackend.(*backendWrapper), idlestBackend.(*backendWrapper)

	// Control the speed of migration.
	curTime := time.Now()
	// Cross-keyspace fast path (DPL-07 #41): the WHOLE pair is refused
	// for this round before the per-connection loop runs — one counted
	// attempt and one rate-limited record, never a warning per
	// connection. The redirectConn backstop below remains for any
	// future caller that bypasses Balance.
	fromKeyspace, toKeyspace := fromBackend.Keyspace(), toBackend.Keyspace()
	g.captureBalanceClock(caller, curTime, fromKeyspace, toKeyspace)
	if fromKeyspace != toKeyspace {
		g.logCrossKeyspaceSkip(fromBackend, toBackend, fromKeyspace, toKeyspace, reason, curTime)
		g.publishBalanceObservation(caller, 0)
		return
	}
	migrationInterval := time.Duration(float64(time.Second) / balanceCount)
	count := 0
	if migrationInterval < rebalanceInterval*2 {
		// If we need to migrate multiple connections in each round, calculate the connection count for each round.
		count = int((rebalanceInterval-1)/migrationInterval) + 1
	} else {
		// If we need to wait for multiple rounds to migrate a connection, calculate the interval for each connection.
		if curTime.Sub(g.lastRedirectTime) >= migrationInterval {
			count = 1
		} else {
			g.publishBalanceObservation(caller, 0)
			return
		}
	}
	// Migrate balanceCount connections.
	i := 0
	for ele := fromBackend.connList.Front(); ele != nil && g.captureBalanceContext(ctx.Err()) && i < count; ele = ele.Next() {
		conn := ele.Value
		if caller != nil {
			caller.CaptureBalanceVisit(conn.observationID)
		}
		if conn.forceClosing {
			continue
		}
		switch conn.phase {
		case phaseRedirectNotify:
			// A connection cannot be redirected again when it has not finished redirecting.
			continue
		case phaseRedirectFail:
			// If it failed recently, it will probably fail this time.
			if conn.lastRedirect.Add(redirectFailMinInterval).After(curTime) {
				continue
			}
		}
		if g.redirectConn(conn, fromBackend, toBackend, reason, logFields, curTime) {
			g.lastRedirectTime = curTime
			i++
		}
	}
	g.publishBalanceObservation(caller, i)
}

func (g *Group) onCreateConn(backendInst BackendInst, conn RedirectableConn, succeed bool) {
	g.onCreateConnObserved(backendInst, conn, succeed, nil)
}

func (g *Group) onCreateConnObserved(backendInst BackendInst, conn RedirectableConn, succeed bool, selection *selectionObservation) {
	g.Lock()
	defer g.Unlock()
	caller := g.beginFinishObservation(selection)
	defer g.endFinishObservation(caller)
	g.captureFinishHeader(caller, selection, backendInst, succeed)
	backend := g.ensureBackend(backendInst.ID())
	if succeed {
		connWrapper := &connWrapper{
			RedirectableConn: conn,
			scoreOwner:       backend,
			createTime:       time.Now(),
			phase:            phaseNotRedirected,
			forceClosing:     false,
		}
		if selection != nil {
			connWrapper.observationID = selection.session
		}
		g.addConn(backend, connWrapper)
		conn.SetEventReceiver(g)
	} else {
		backend.connScore--
	}
	g.observeCreated(selection, backend, conn, succeed)
	if caller != nil && caller.CaptureFinishResult() && caller.Seal() {
		g.observation.PublishCaller(caller)
	}
}

// RehydrateConn implements the group half of AssignmentRehydrator: the
// connection attaches to the named backend exactly as if its original
// assignment had succeeded (score, connection list, event receiver),
// without running selection. False means this group does not own the
// backend.
func (g *Group) RehydrateConn(backendID string, conn RedirectableConn) (BackendInst, bool) {
	g.Lock()
	defer g.Unlock()
	backend, ok := g.backends[backendID]
	if !ok {
		return nil, false
	}
	// Selection would have incremented connScore before onCreateConn;
	// mirror the successful-assignment total effect here.
	backend.connScore++
	connWrapper := &connWrapper{
		RedirectableConn: conn,
		scoreOwner:       backend,
		createTime:       time.Now(),
		phase:            phaseNotRedirected,
		forceClosing:     false,
	}
	if g.observation.Enabled() {
		connWrapper.observationID = g.observation.NextIdentity()
	}
	g.addConn(backend, connWrapper)
	conn.SetEventReceiver(g)
	if g.observation.Enabled() {
		g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Rehydrate, Session: connWrapper.observationID, Account: backend.observationID}}}, connWrapper, observation.ConnectionState{}, backend)
	}
	return backend, true
}

func (g *Group) CloseTimedOutFailoverConnections(now time.Time) {
	g.Lock()
	defer g.Unlock()
	for _, backend := range g.backends {
		since := backend.FailoverSince()
		if since.IsZero() {
			continue
		}
		if g.failoverTimeout > 0 && since.Add(g.failoverTimeout).After(now) {
			continue
		}
		for ele := backend.connList.Front(); ele != nil; ele = ele.Next() {
			conn := ele.Value
			if conn.phase == phaseClosed || conn.forceClosing {
				continue
			}
			fields := []zap.Field{
				zap.Uint64("connID", conn.ConnectionID()),
				zap.String("backend_addr", backend.addr),
				zap.String("backend_pod", backend.PodName()),
				zap.Duration("failover_timeout", g.failoverTimeout),
				zap.Duration("failover_elapsed", now.Sub(since)),
			}
			before := g.beforeObservation(conn)
			accepted := conn.ForceClose()
			if accepted {
				conn.forceClosing = true
				g.lg.Info("force close connection on failover backend", fields...)
			}
			if g.observation.Enabled() {
				kind := observation.Rejected
				op := g.observation.NextIdentity()
				if accepted {
					kind = observation.Closing
					conn.observationClose = op
				}
				g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: kind, Session: conn.observationID, Operation: op}}}, conn, before, conn.physicalOwner, conn.scoreOwner)
			}
		}
	}
}

// removeConn removes the connection from the connList that actually contains it.
// Always remove by `physicalOwner` instead of by the backend that the connection is physically on:
// they differ when a redirect result has not been processed yet, and glist.Remove silently
// does nothing if the element is not in the given list, which leaks the connection forever.
func (g *Group) removeConn(ce *glist.Element[*connWrapper]) {
	backend := ce.Value.physicalOwner
	if backend == nil {
		g.lg.Warn("unexpected nil physical owner for connection")
		return
	}
	oldLen := backend.connList.Len()
	backend.connList.Remove(ce)
	newLen := backend.connList.Len()
	if newLen != oldLen-1 {
		g.lg.Warn("the connection is not in the list", zap.String("backend", backend.id))
	}
	ce.Value.physicalOwner = nil
	setBackendConnMetrics(backend.addr, newLen)
}

func (g *Group) addConn(backend *backendWrapper, conn *connWrapper) {
	if conn.physicalOwner != nil {
		g.lg.Warn("unexpected non-nil physical owner for connection")
	}
	conn.physicalOwner = backend
	ce := backend.connList.PushBack(conn)
	setBackendConnMetrics(backend.addr, backend.connList.Len())
	setConnWrapper(conn, ce)
}

// RedirectConnections implements Router.RedirectConnections interface.
// It redirects all connections compulsively. It's only used for testing.
func (g *Group) RedirectConnections() error {
	g.Lock()
	defer g.Unlock()
	for _, backend := range g.backends {
		for ce := backend.connList.Front(); ce != nil; ce = ce.Next() {
			// This is only for test, so we allow it to reconnect to the same backend.
			connWrapper := ce.Value
			if connWrapper.phase != phaseRedirectNotify {
				before := g.beforeObservation(connWrapper)
				connWrapper.phase = phaseRedirectNotify
				connWrapper.redirectReason = "test"
				accepted := connWrapper.Redirect(backend)
				if accepted {
					metrics.PendingMigrateGuage.WithLabelValues(backend.addr, backend.addr, connWrapper.redirectReason).Inc()
				}
				if g.observation.Enabled() {
					connWrapper.observationRedirect = g.observation.NextIdentity()
					g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Reconnect, Session: connWrapper.observationID, Operation: connWrapper.observationRedirect, Account: backend.observationID, Success: accepted}}}, connWrapper, before, backend)
				}
			}
		}
	}
	return nil
}

func (g *Group) ensureBackend(backendID string) *backendWrapper {
	backend, ok := g.backends[backendID]
	if ok {
		return backend
	}
	// The backend should always exist if it will be needed. Add a warning and add it back.
	g.lg.Warn("backend is not found in the router", zap.String("backend_id", backendID), zap.Stack("stack"))
	// Try to parse the IP from the backendID. It's generally not suggested to parse it, but in this
	// strange case we tried our best to recover and make the backend ip valid.
	// For the formats of backendID, ref `backend_id.go`. It's generated and recorded in `GetTiDBTopology`
	// for the first time.
	_, addr := backendcluster.ParseBackendID(backendID)
	ip, _, _ := net.SplitHostPort(addr)
	backend = newBackendWrapper(backendID, observer.BackendHealth{
		BackendInfo: observer.BackendInfo{
			Addr:       addr,
			IP:         ip,
			StatusPort: 10080, // impossible anyway
		},
		SupportRedirection: true,
		Healthy:            false,
	})
	g.backends[backendID] = backend
	g.observeAccount(backend)
	return backend
}

// OnRedirectSucceed implements ConnEventReceiver.OnRedirectSucceed interface.
func (g *Group) OnRedirectSucceed(from, to string, conn RedirectableConn) error {
	g.onRedirectFinished(from, to, conn, true)
	return nil
}

// OnRedirectFail implements ConnEventReceiver.OnRedirectFail interface.
func (g *Group) OnRedirectFail(from, to string, conn RedirectableConn) error {
	g.onRedirectFinished(from, to, conn, false)
	return nil
}

func (g *Group) onRedirectFinished(from, to string, conn RedirectableConn, succeed bool) {
	g.Lock()
	defer g.Unlock()
	fromBackend := g.ensureBackend(from)
	toBackend := g.ensureBackend(to)
	connWrapper := getConnWrapper(conn).Value
	before := g.beforeObservation(connWrapper)
	// The connection may be closed when this function is waiting for the lock.
	if connWrapper.phase == phaseClosed {
		g.observeRedirected(connWrapper, before, fromBackend, toBackend, succeed)
		return
	}

	addMigrateMetrics(fromBackend.addr, toBackend.addr, connWrapper.redirectReason, succeed, connWrapper.lastRedirect)
	if succeed {
		g.removeConn(getConnWrapper(conn))
		g.addConn(toBackend, connWrapper)
		connWrapper.phase = phaseRedirectEnd
	} else {
		connWrapper.transferScore(fromBackend)
		connWrapper.phase = phaseRedirectFail
	}
	g.observeRedirected(connWrapper, before, fromBackend, toBackend, succeed)
}

// OnConnClosed implements ConnEventReceiver.OnConnClosed interface.
func (g *Group) OnConnClosed(backendID string, conn RedirectableConn) error {
	g.Lock()
	defer g.Unlock()
	connWrapper := getConnWrapper(conn)
	cw := connWrapper.Value
	before := g.beforeObservation(cw)
	physical, score := cw.physicalOwner, cw.scoreOwner
	// If the physical owner mismatches the score owner, it means the redirect result has not been processed yet.
	if cw.physicalOwner != cw.scoreOwner && cw.physicalOwner != nil && cw.scoreOwner != nil {
		addMigrateMetrics(cw.physicalOwner.addr, cw.scoreOwner.addr, cw.redirectReason, false, cw.lastRedirect)
	}
	cw.transferScore(nil)
	// A redirect result may have not been processed yet, in which case the connection is still
	// in the old backend's connList while `backendID` is the new backend, so remove the connection
	// by its physicalOwner. onRedirectFinished won't touch the list once the phase is phaseClosed.
	g.removeConn(connWrapper)
	cw.phase = phaseClosed
	if g.observation.Enabled() {
		g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Closed, Session: cw.observationID}}}, cw, before, physical, score)
	}
	return nil
}

func (g *Group) redirectConn(conn *connWrapper, fromBackend *backendWrapper, toBackend *backendWrapper,
	reason string, logFields []zap.Field, curTime time.Time) bool {
	before := g.beforeObservation(conn)
	// Cross-keyspace guard (DPL-07 #41): a dynamic change may never
	// migrate an existing session to another keyspace. This is the
	// FINAL issuance boundary - Go's BackendConnManager and the Rust
	// dataplane's projected sessions both receive their redirects from
	// here, so one strict-equality invariant constrains both seams.
	// Legacy ""=="" is allowed; any mismatch, including empty vs
	// non-empty, fails closed: the connection is safely skipped for
	// this round (never rerouted to the foreign keyspace; a failed
	// backend's remaining sessions force-close on failover-timeout).
	// Per-keyspace candidate selection is a recorded follow-up
	// availability/balance boundary.
	fromKeyspace := fromBackend.Keyspace()
	toKeyspace := toBackend.Keyspace()
	if fromKeyspace != toKeyspace {
		// Backstop only: Balance's pair-level fast path normally
		// refuses first. The evidence goes through the same
		// group-level limiter/counter — never an unbounded per-
		// connection warning — and the redirect timestamps advance
		// exactly as a failed redirect would.
		g.logCrossKeyspaceSkip(fromBackend, toBackend, fromKeyspace, toKeyspace, reason, curTime)
		conn.phase = phaseRedirectFail
		conn.lastRedirect = curTime
		g.observeRedirect(conn, before, fromBackend, toBackend, fromKeyspace, toKeyspace, observation.BalanceCallbackSkipped)
		return false
	}
	// Skip the connection if it's closing.
	fields := []zap.Field{
		zap.Uint64("connID", conn.ConnectionID()),
		zap.String("from", fromBackend.addr),
		zap.String("to", toBackend.addr),
	}
	if !conn.lastRedirect.IsZero() {
		fields = append(fields, zap.Duration("since_last_redirect", curTime.Sub(conn.lastRedirect)))
	}
	fields = append(fields, logFields...)
	succeed := conn.Redirect(toBackend)
	if succeed {
		g.lg.Debug("begin redirect connection", fields...)
		conn.transferScore(toBackend)
		conn.phase = phaseRedirectNotify
		conn.redirectReason = reason
		metrics.PendingMigrateGuage.WithLabelValues(fromBackend.addr, toBackend.addr, reason).Inc()
	} else {
		// Avoid it to be redirected again immediately.
		conn.phase = phaseRedirectFail
		g.lg.Debug("skip redirecting because it's closing", fields...)
	}
	conn.lastRedirect = curTime
	callback := observation.BalanceCallbackRefused
	if succeed {
		callback = observation.BalanceCallbackAccepted
	}
	g.observeRedirect(conn, before, fromBackend, toBackend, fromKeyspace, toKeyspace, callback)
	return succeed
}

func (g *Group) ConnCount() int {
	g.Lock()
	defer g.Unlock()
	j := 0
	for _, backend := range g.backends {
		j += backend.connList.Len()
	}
	return j
}

func (g *Group) SetConfig(cfg *config.Config) {
	g.Lock()
	defer g.Unlock()
	g.policy.SetConfig(cfg)
	g.publishPolicyObservationLocked()
	g.setFailoverConfigLocked(cfg)
	g.updateFailoverLocked(time.Now())
}

// The actual call has returned; its Group critical section still protects both
// the lifecycle ledger and input accounts until the complete record is queued.
func (g *Group) publishPolicyObservationLocked() {
	if native, ok := g.policy.(*factor.FactorBasedBalance); ok {
		if evaluation := native.TakeObservation(); evaluation != nil {
			if g.routeCaller != nil {
				g.routeCaller.CompleteEvaluation(evaluation)
			} else if g.balanceCaller != nil {
				g.balanceCaller.CompleteEvaluation(evaluation)
			} else {
				g.observation.PublishEvaluation(evaluation)
			}
		}
	}
}
