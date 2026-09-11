// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"math"
	"reflect"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/prometheus/common/model"
	"go.uber.org/zap"
)

// nativeCapture is factory-bound before Init. Only the native policy's mutex
// accesses current; Group takes the completed loan AFTER the policy returns.
// No query/backend is retained here and no recorder callback enters production.
type nativeCapture struct {
	owner                                 *observation.Owner
	time                                  *observation.TimeProjection
	group, policy, config, resource, next uint64
	balance                               string
	current                               *observation.Evaluation
	complete                              bool
}

// NewFactorBasedBalanceObserved binds a concrete native policy before Init.
// Custom policy constructors remain lifecycle-only.
func NewFactorBasedBalanceObserved(lg *zap.Logger, mr metricsreader.MetricsQuerier, owner *observation.Owner, group uint64) *FactorBasedBalance {
	fbb := NewFactorBasedBalance(lg, mr)
	if !owner.Enabled() {
		return fbb
	}
	if group == 0 || !owner.Native() {
		owner.Invalidate(observation.Malformed)
		return fbb
	}
	binder, ok := mr.(interface{ BindObservationOwner(*observation.Owner) })
	if !ok {
		owner.Invalidate(observation.Malformed)
		return fbb
	}
	binder.BindObservationOwner(owner)
	fbb.capture = &nativeCapture{owner: owner, time: owner.TimeProjection(), group: group, policy: owner.NextIdentity()}
	return fbb
}

func (c *nativeCapture) enabled() bool { return c != nil && c.owner.Enabled() }

// TakeObservation is called by Group before releasing the same critical section
// that called the native policy. This method does not publish from a policy defer.
func (fbb *FactorBasedBalance) TakeObservation() *observation.Evaluation {
	if fbb.capture == nil {
		return nil
	}
	fbb.Lock()
	defer fbb.Unlock()
	c := fbb.capture
	e := c.current
	c.current = nil
	if e == nil {
		return nil
	}
	if !c.complete || !e.Seal() {
		e.Release()
		return nil
	}
	c.complete = false
	return e
}

// DiscardObservation drops the policy's diagnostic reference during the
// enclosing Group's unconditional cleanup. A parent-owned lease stays with its
// parent, including a child interrupted before TakeObservation could seal it.
func (fbb *FactorBasedBalance) DiscardObservation() {
	fbb.Lock()
	defer fbb.Unlock()
	if c := fbb.capture; c != nil && c.current != nil {
		e := c.current
		c.current, c.complete = nil, false
		e.Release()
	}
}

func (fbb *FactorBasedBalance) beginObservation(entry observation.EntryPoint, backends []policy.BackendCtx) {
	fbb.beginCallerObservation(entry, backends, nil)
}

func (fbb *FactorBasedBalance) beginCallerObservation(entry observation.EntryPoint, backends []policy.BackendCtx, caller *observation.Caller) {
	c := fbb.capture
	if c == nil {
		return
	}
	if c.current != nil {
		c.current.Release() // omitted publication cannot be backfilled
		c.current = nil
	}
	if !c.enabled() {
		return
	}
	var e *observation.Evaluation
	if caller != nil {
		e = caller.BeginEvaluation()
	} else {
		e = c.owner.BeginEvaluation()
	}
	if e == nil {
		return
	}
	c.current, c.complete = e, false
	if c.next == math.MaxUint64 {
		e.Fail(observation.SequenceExhausted)
		return
	}
	c.next++
	n := e.Native()
	n.Group, n.Policy, n.Config, n.Resource, n.ID = c.group, c.policy, c.config, c.resource, c.next
	n.Entry = entry
	if len(backends) > observation.MaxEvaluationAccounts {
		e.Fail(observation.Capacity)
		return
	}
	n.BackendCount = uint16(len(backends))
	for i, backend := range backends {
		account := nativeAccount(backend)
		if account == 0 {
			e.Fail(observation.Malformed)
			return
		}
		for j := 0; j < i; j++ {
			if n.Backends[j].Account == account {
				e.Fail(observation.Malformed)
				return
			}
		}
		n.Backends[i].Account = account
	}
	fbb.captureConfiguration(e)
}

func nativeAccount(backend policy.BackendCtx) uint64 {
	if backend == nil {
		return 0
	}
	if account, ok := backend.(interface{ ObservationAccount() uint64 }); ok {
		return account.ObservationAccount()
	}
	return 0
}

func (fbb *FactorBasedBalance) captureConfiguration(e *observation.Evaluation) {
	n := e.Native()
	n.Configuration.BalancePolicy = e.CopyText(fbb.capture.balance)
	n.Configuration.RoutingPolicy = e.CopyText(fbb.routePolicy)
	if fbb.factorLabel != nil {
		n.Configuration.LabelName = e.CopyText(fbb.factorLabel.labelName)
		n.Configuration.SelfLabel = e.CopyText(fbb.factorLabel.selfLabelVal)
	}
	if fbb.factorStatus != nil {
		n.Configuration.Rates[0] = math.Float64bits(fbb.factorStatus.migrationsPerSecond)
	}
	if fbb.factorHealth != nil {
		n.Configuration.Rates[1] = math.Float64bits(fbb.factorHealth.migrationsPerSecond)
	}
	if fbb.factorMemory != nil {
		n.Configuration.Rates[2] = math.Float64bits(fbb.factorMemory.migrationsPerSecond)
	}
	if fbb.factorCPU != nil {
		n.Configuration.Rates[3] = math.Float64bits(fbb.factorCPU.migrationsPerSecond)
	}
	if fbb.factorLocation != nil {
		n.Configuration.Rates[4] = math.Float64bits(fbb.factorLocation.migrationsPerSecond)
	}
	if fbb.factorConnCount != nil {
		n.Configuration.Rates[5] = math.Float64bits(fbb.factorConnCount.migrationsPerSecond)
		n.Configuration.CountRatio = math.Float64bits(fbb.factorConnCount.countRatioThreshold)
	}
	for i, factor := range fbb.factors {
		if i == observation.MaxEvaluationFactors {
			e.Fail(observation.Capacity)
			return
		}
		n.Factors[i], n.Widths[i] = nativeFactor(factor), uint8(factor.ScoreBitNum())
		n.FactorCount++
	}
}

func nativeFactor(f Factor) observation.FactorKind {
	switch f.(type) {
	case *FactorLabel:
		return observation.FactorLabel
	case *FactorStatus:
		return observation.FactorStatus
	case *FactorHealth:
		return observation.FactorHealth
	case *FactorMemory:
		return observation.FactorMemory
	case *FactorCPU:
		return observation.FactorCPU
	case *FactorLocation:
		return observation.FactorLocation
	case *FactorConnCount:
		return observation.FactorConnection
	default:
		return 0
	}
}

func (fbb *FactorBasedBalance) appliedObservationConfig(cfg *config.Config) {
	c := fbb.capture
	if !c.enabled() {
		return
	}
	c.config = c.owner.NextIdentity()
	c.balance = cfg.Balance.Policy
	if fbb.factorCPU == nil {
		c.resource = 0
	} else if c.resource == 0 {
		c.resource = c.owner.NextIdentity()
	}
	fbb.factorStatus.capture = c
	if fbb.factorHealth != nil {
		fbb.factorHealth.capture = c
	}
	if fbb.factorMemory != nil {
		fbb.factorMemory.capture = c
	}
	if fbb.factorCPU != nil {
		fbb.factorCPU.capture = c
	}
}

func (c *nativeCapture) finish() {
	if c != nil {
		c.complete = true
	}
}

func (c *nativeCapture) clock(site observation.ClockSite, value time.Time) {
	if !c.enabled() || c.current == nil {
		return
	}
	projected, ok := c.time.Project(value)
	if ok {
		c.current.AddRead(observation.NativeRead{Kind: observation.ReadClock, Site: site, Time: projected})
	}
}

func (c *nativeCapture) query(kind observation.QueryKind, qr metricsreader.QueryResult) {
	if !c.enabled() || c.current == nil {
		return
	}
	e := c.current
	p := qr.Provenance
	if p.Invalid != observation.Valid {
		e.Fail(p.Invalid)
		return
	}
	// Missing results may lack a publication/registration; a real read still
	// identifies its producer and the coherently selected cluster/source.
	if p.Cluster == 0 || p.Source < 0 || p.Source > 2 ||
		(p.Source != 0 && (p.SourceGeneration == 0 || p.Producer == 0)) ||
		(p.Source == 0 && (p.Producer != 0 || p.Publication != 0 || qr.Value != nil)) ||
		(p.Publication != 0 && p.Registration == 0) {
		e.Fail(observation.Malformed)
		return
	}
	timestamp, ok := c.time.Project(qr.UpdateTime)
	if !ok {
		return
	}
	r := observation.NativeRead{Kind: observation.ReadQuery, Query: kind, Time: timestamp,
		Provenance: observation.NativeProvenance{Cluster: p.Cluster, SourceGeneration: p.SourceGeneration, Source: p.Source, Producer: p.Producer, Registration: p.Registration, Publication: p.Publication, ReadRegistration: p.ReadRegistration}}
	if qr.Value == nil {
		r.ValueKind = observation.ValueNil
	} else {
		r.TypedNil = reflect.ValueOf(qr.Value).IsNil()
		switch qr.Value.Type() {
		case model.ValNone:
			r.ValueKind = observation.ValueNone
		case model.ValMatrix:
			r.ValueKind = observation.ValueMatrix
		case model.ValVector:
			r.ValueKind = observation.ValueVector
		case model.ValScalar:
			r.ValueKind = observation.ValueScalar
		case model.ValString:
			r.ValueKind = observation.ValueString
		default:
			e.Fail(observation.Malformed)
			return
		}
	}
	r.Empty = qr.Empty()
	start := e.Position()
	e.Append([]byte{'['})
	if !r.TypedNil {
		switch value := qr.Value.(type) {
		case model.Matrix:
			for i, series := range value {
				if !c.enabled() {
					return
				}
				if series == nil {
					e.Fail(observation.Malformed)
					return
				}
				if i > 0 {
					e.Append([]byte{','})
				}
				if !e.AddSamples(len(series.Values)) {
					return
				}
				captureSeriesLabels(e, series.Metric)
				e.Append([]byte{',', '['})
				for j, sample := range series.Values {
					if j > 0 {
						e.Append([]byte{','})
					}
					captureSample(e, sample.Timestamp, sample.Value)
				}
				e.Append([]byte{']', ']'})
			}
		case model.Vector:
			if !e.AddSamples(len(value)) {
				return
			}
			for i, sample := range value {
				if !c.enabled() {
					return
				}
				if sample == nil {
					e.Fail(observation.Malformed)
					return
				}
				if i > 0 {
					e.Append([]byte{','})
				}
				captureSeriesLabels(e, sample.Metric)
				e.Append([]byte{',', '['})
				captureSample(e, sample.Timestamp, sample.Value)
				e.Append([]byte{']', ']'})
			}
		}
	}
	e.Append([]byte{']'})
	r.Series = observation.DataRef{Offset: start, Length: e.Position() - start}
	e.AddRead(r)
}

// Each series is [instance-present,instance,cluster-present,cluster,samples].
// This retains absent-vs-empty and original first-match order, never PromQL or
// arbitrary labels. No producer-owned slice survives the copying call.
func captureSeriesLabels(e *observation.Evaluation, metric model.Metric) {
	e.Append([]byte{'['})
	for i, key := range [...]model.LabelName{metricsreader.LabelNameInstance, metricsreader.LabelNameCluster} {
		if i > 0 {
			e.Append([]byte{','})
		}
		value, present := metric[key]
		if present {
			e.Append([]byte("true,"))
		} else {
			e.Append([]byte("false,"))
		}
		e.JSONText(string(value))
	}
}

func captureSample(e *observation.Evaluation, timestamp model.Time, value model.SampleValue) {
	e.Append([]byte{'['})
	e.JSONInt(int64(timestamp))
	e.Append([]byte{','})
	e.JSONUint(math.Float64bits(float64(value)))
	e.Append([]byte{']'})
}

func (c *nativeCapture) score(factorIndex int, backends []scoredBackend, width int) {
	if !c.enabled() || c.current == nil {
		return
	}
	n := c.current.Native()
	for _, backend := range backends {
		n.Backends[backend.captureIndex].Parts[factorIndex] = uint64(backend.factorScore(width))
		n.Backends[backend.captureIndex].Packed = backend.scoreBits
	}
}

func (c *nativeCapture) sorted(backends []scoredBackend) {
	if !c.enabled() || c.current == nil {
		return
	}
	n := c.current.Native()
	n.SortedCount = uint16(len(backends))
	for i, backend := range backends {
		n.Sorted[i] = uint8(backend.captureIndex)
	}
}

func (c *nativeCapture) advice(factor Factor, from, to scoredBackend, advice BalanceAdvice, count float64) {
	if !c.enabled() || c.current == nil {
		return
	}
	n := c.current.Native()
	if n.AdviceCount == observation.MaxEvaluationAdvice {
		c.current.Fail(observation.Capacity)
		return
	}
	n.Advice[n.AdviceCount] = observation.NativeAdvice{Factor: nativeFactor(factor), From: uint8(from.captureIndex), To: uint8(to.captureIndex), Advice: int8(advice), Count: math.Float64bits(count)}
	n.AdviceCount++
}

func (c *nativeCapture) returned(backend policy.BackendCtx) int16 {
	if !c.enabled() || c.current == nil || backend == nil {
		return -1
	}
	n := c.current.Native()
	account := nativeAccount(backend)
	for i := range n.Backends[:n.BackendCount] {
		if n.Backends[i].Account == account {
			return int16(i)
		}
	}
	c.current.Fail(observation.Malformed)
	return -1
}

func (c *nativeCapture) routeResult(backends []policy.BackendCtx) {
	if !c.enabled() || c.current == nil {
		return
	}
	n := c.current.Native()
	for _, backend := range backends {
		index := c.returned(backend)
		if index < 0 {
			continue
		}
		if n.ReturnedCount == observation.MaxEvaluationAccounts {
			c.current.Fail(observation.Capacity)
			return
		}
		n.Returned[n.ReturnedCount] = uint8(index)
		n.ReturnedCount++
	}
}

func (fbb *FactorBasedBalance) canBeRoutedBackend(backend scoredBackend) bool {
	value := fbb.canBeRouted(backend.scoreBits)
	if e, n := backend.observationBackend(); n != nil {
		if n.RouteabilitySeen && n.Routeable != value {
			e.Fail(observation.Malformed)
		}
		n.Routeable, n.RouteabilitySeen = value, true
	}
	return value
}
