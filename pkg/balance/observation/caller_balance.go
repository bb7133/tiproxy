// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"math"
	"unicode/utf8"
)

const (
	MaxBalanceVisits   = 64
	MaxBalanceContexts = MaxBalanceVisits + 1
)

// BalanceCallback distinguishes a skipped callback from an actual false result.
type BalanceCallback uint8

const (
	BalanceCallbackSkipped BalanceCallback = iota
	BalanceCallbackRefused
	BalanceCallbackAccepted
)

// BalanceVisit is a physical visit, including one skipped before redirectConn.
// Child indexes the complete original batch retained by this parent.
type BalanceVisit struct {
	Session  uint64
	From, To DataRef
	Callback BalanceCallback
	Child    uint8
	Redirect bool
}

// GroupBalance is a bounded copy of values read within one Group lock. Actual
// router hooks and pass binding remain uninstalled; this type grants no coverage.
type GroupBalance struct {
	ID, Group                           uint64
	Members                             [MaxCallerGroups]uint64
	MemberCount                         uint16
	Now                                 GoTimeValue
	From, To                            DataRef
	Contexts                            [MaxBalanceContexts]bool
	Visits                              [MaxBalanceVisits]BalanceVisit
	ContextCount, VisitCount, ReadCount uint16
	Accepted                            uint16
	StringBytes                         uint32
	ClockSet, ResultSet                 bool
}

func (c *Caller) CaptureGroupBalance(id, group uint64, members []uint64) bool {
	if !c.writable() {
		return false
	}
	if id == 0 || group == 0 || c.length != 0 || c.evaluations != 0 || c.batches != 0 || c.storage.pass.Kind != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 {
		c.Fail(Malformed)
		return false
	}
	if len(members) > MaxCallerGroups {
		c.Fail(Capacity)
		return false
	}
	for i, member := range members {
		if member == 0 {
			c.Fail(Malformed)
			return false
		}
		for _, previous := range members[:i] {
			if previous == member {
				c.Fail(Malformed)
				return false
			}
		}
	}
	b := &c.storage.balance
	b.ID, b.Group, b.MemberCount = id, group, uint16(len(members))
	copy(b.Members[:], members)
	return true
}

func (c *Caller) balanceWritable() bool {
	if !c.writable() {
		return false
	}
	if c.storage.balance.ID == 0 || c.storage.balance.ResultSet || c.evaluations != 1 || c.children == 0 || c.storage.children[0].Evaluation == nil {
		c.Fail(Malformed)
		return false
	}
	return true
}

// CaptureBalanceClock accepts the already projected, original time.Now value
// and the two actual whole-pair keyspace reads. It performs no production reads.
func (c *Caller) CaptureBalanceClock(now GoTimeValue, from, to string) bool {
	if !c.balanceWritable() {
		return false
	}
	b := &c.storage.balance
	n := c.storage.children[0].Evaluation.Native()
	if b.ClockSet || n == nil || math.Float64frombits(n.BalanceCount) == 0 || now.Domain != GoTimeDomain || now.Nanoseconds >= 1_000_000_000 || now.Location == 0 || !now.HasMonotonic && now.Monotonic != 0 {
		c.Fail(Malformed)
		return false
	}
	f, t, ok := c.balanceStrings(from, to, 2)
	if !ok {
		return false
	}
	b.Now, b.From, b.To, b.ClockSet = now, f, t, true
	return true
}

// CaptureBalanceContext records the original nil/context/quota short circuit.
// A quota stop with an element reads context once; nil never reads context.
func (c *Caller) CaptureBalanceContext(cancelled bool) bool {
	if !c.balanceWritable() {
		return false
	}
	b := &c.storage.balance
	if b.ContextCount == MaxBalanceContexts || b.ReadCount == MaxCallerReads {
		c.Fail(Capacity)
		return false
	}
	if !b.ClockSet || b.ContextCount != b.VisitCount {
		c.Fail(Malformed)
		return false
	}
	b.Contexts[b.ContextCount] = cancelled
	b.ContextCount++
	b.ReadCount++
	return true
}

// CaptureBalanceVisit runs before all forceClosing/phase/cooldown skips. A
// cohort exceeding 64 visited sessions invalidates observation with Capacity;
// it never truncates the scan or changes the production loop's behavior.
func (c *Caller) CaptureBalanceVisit(session uint64) bool {
	if !c.balanceWritable() {
		return false
	}
	b := &c.storage.balance
	if b.VisitCount == MaxBalanceVisits {
		c.Fail(Capacity)
		return false
	}
	if session == 0 || !b.ClockSet || b.ContextCount != b.VisitCount+1 || b.Contexts[b.ContextCount-1] {
		c.Fail(Malformed)
		return false
	}
	for _, old := range b.Visits[:b.VisitCount] {
		if old.Session == session {
			c.Fail(Malformed)
			return false
		}
	}
	b.Visits[b.VisitCount].Session = session
	b.VisitCount++
	return true
}

// CaptureBalanceRedirect appends the already completed lifecycle batch and
// binds it to the direct backstop reads at the current physical visit. It never
// calls Redirect; callback is the actual result or Skipped for keyspace refusal.
func (c *Caller) CaptureBalanceRedirect(from, to string, callback BalanceCallback, batch Batch) bool {
	if !c.balanceWritable() {
		return false
	}
	b := &c.storage.balance
	if b.VisitCount == 0 || b.ContextCount != b.VisitCount || callback > BalanceCallbackAccepted || (from == to) == (callback == BalanceCallbackSkipped) || batch.EventCount != 1 || batch.Witness.AccountCount > MaxWitnesses {
		c.Fail(Malformed)
		return false
	}
	v := &b.Visits[b.VisitCount-1]
	if v.Redirect || batch.Events[0].Session != v.Session || batch.Events[0].Account == 0 || batch.Events[0].Target == 0 || batch.Events[0].Account == batch.Events[0].Target {
		c.Fail(Malformed)
		return false
	}
	kind := Rejected
	if callback == BalanceCallbackAccepted {
		kind = Redirect
	}
	if batch.Events[0].Kind != kind {
		c.Fail(Malformed)
		return false
	}
	reads := uint16(2)
	if callback != BalanceCallbackSkipped {
		reads++
	}
	f, t, ok := c.balanceStrings(from, to, reads)
	if !ok {
		return false
	}
	child := c.children
	if !c.appendBatch(batch) {
		return false
	}
	v.From, v.To, v.Callback, v.Child, v.Redirect = f, t, callback, uint8(child), true
	return true
}

func (c *Caller) balanceStrings(from, to string, reads uint16) (DataRef, DataRef, bool) {
	b := &c.storage.balance
	if len(from) > MaxEvaluationStringBytes || len(to) > MaxEvaluationStringBytes || len(from)+len(to) > MaxEvaluationStringsBytes-int(b.StringBytes) || int(b.ReadCount)+int(reads) > MaxCallerReads {
		c.Fail(Capacity)
		return DataRef{}, DataRef{}, false
	}
	if !utf8.ValidString(from) || !utf8.ValidString(to) {
		c.Fail(Malformed)
		return DataRef{}, DataRef{}, false
	}
	f := DataRef{Offset: uint32(c.length), Length: uint32(len(from))}
	if !c.appendBytes([]byte(from)) {
		return DataRef{}, DataRef{}, false
	}
	t := DataRef{Offset: uint32(c.length), Length: uint32(len(to))}
	if !c.appendBytes([]byte(to)) {
		return DataRef{}, DataRef{}, false
	}
	b.StringBytes += uint32(len(from) + len(to))
	b.ReadCount += reads
	return f, t, true
}

func (c *Caller) CaptureBalanceResult(accepted uint16) bool {
	if !c.balanceWritable() {
		return false
	}
	b := &c.storage.balance
	if accepted > MaxBalanceVisits {
		c.Fail(Capacity)
		return false
	}
	n := c.storage.children[0].Evaluation.Native()
	if n == nil || (math.Float64frombits(n.BalanceCount) == 0) == b.ClockSet {
		c.Fail(Malformed)
		return false
	}
	b.Accepted, b.ResultSet = accepted, true
	return true
}

// Balance borrows the sealed immutable capture until final writer release.
func (c *Caller) Balance() *GroupBalance {
	if c == nil || !c.sealed || c.released.Load() || c.storage.balance.ID == 0 {
		return nil
	}
	return &c.storage.balance
}
