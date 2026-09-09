// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"bytes"
	"math"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
)

func (w *nativeEncoder) groupBalance(record observation.Record) bool {
	c, b := record.Caller, record.Caller.Balance()
	children := c.Children()
	if b == nil || b.ID == 0 || b.Group == 0 || b.MemberCount > observation.MaxCallerGroups || b.VisitCount > observation.MaxBalanceVisits || b.ContextCount > observation.MaxBalanceContexts || b.ReadCount > observation.MaxCallerReads || b.StringBytes > observation.MaxEvaluationStringsBytes || b.Accepted > observation.MaxBalanceVisits || !b.ResultSet || len(children) == 0 {
		return false
	}
	first := children[0]
	if first.Evaluation == nil || first.Batch != (observation.Batch{}) {
		return false
	}
	n := first.Evaluation.Native()
	if n == nil || n.Group != b.Group || n.Entry != observation.EntryBalance || (math.Float64frombits(n.BalanceCount) == 0) == b.ClockSet {
		return false
	}
	w.literal(`"group_balance":{"caller":`)
	w.uint(b.ID)
	w.literal(`,"group":`)
	w.uint(b.Group)
	w.literal(`,"members":[`)
	for i, member := range b.Members {
		if i >= int(b.MemberCount) {
			if member != 0 {
				return false
			}
			continue
		}
		if member == 0 {
			return false
		}
		for _, previous := range b.Members[:i] {
			if previous == member {
				return false
			}
		}
		if i != 0 {
			w.literal(",")
		}
		w.uint(member)
	}
	w.literal(`],"evaluation":`)
	native, err := EncodeEvaluation(observation.Record{Epoch: record.Epoch, Sequence: record.Sequence, Native: true, Evaluation: first.Evaluation})
	if err != nil {
		return false
	}
	w.raw(native[4:])
	w.literal(`,"clock":`)
	var strings uint32
	reads := int(b.ContextCount)
	if b.ClockSet {
		reads += 2
		w.literal(`{"now":`)
		w.clock(b.Now)
		w.literal(`,"from_keyspace":`)
		if !w.balanceText(c, b.From, &strings) {
			return false
		}
		w.literal(`,"to_keyspace":`)
		if !w.balanceText(c, b.To, &strings) {
			return false
		}
		w.literal(`}`)
	} else {
		if b.Now != (observation.GoTimeValue{}) || b.From != (observation.DataRef{}) || b.To != (observation.DataRef{}) || b.ContextCount != 0 || b.VisitCount != 0 || b.Accepted != 0 {
			return false
		}
		w.literal(`null`)
	}
	w.literal(`,"contexts":[`)
	for i, cancelled := range b.Contexts {
		if i >= int(b.ContextCount) {
			if cancelled {
				return false
			}
			continue
		}
		if i != 0 {
			w.literal(",")
		}
		w.boolean(cancelled)
	}
	w.literal(`],"visits":[`)
	childIndex := 1
	for i, visit := range b.Visits {
		if i >= int(b.VisitCount) {
			if visit != (observation.BalanceVisit{}) {
				return false
			}
			continue
		}
		if visit.Session == 0 {
			return false
		}
		for _, previous := range b.Visits[:i] {
			if previous.Session == visit.Session {
				return false
			}
		}
		if i != 0 {
			w.literal(",")
		}
		w.literal(`{"session":`)
		w.uint(visit.Session)
		w.literal(`,"redirect":`)
		if !visit.Redirect {
			if visit.From != (observation.DataRef{}) || visit.To != (observation.DataRef{}) || visit.Callback != observation.BalanceCallbackSkipped || visit.Child != 0 {
				return false
			}
			w.literal(`null}`)
			continue
		}
		if int(visit.Child) != childIndex || childIndex >= len(children) || children[childIndex].Evaluation != nil {
			return false
		}
		batch := children[childIndex].Batch
		if batch.EventCount != 1 || batch.Events[0].Session != visit.Session || batch.Events[0].Account == 0 || batch.Events[0].Target == 0 || batch.Events[0].Account == batch.Events[0].Target || (batch.Events[0].Kind != observation.Redirect && batch.Events[0].Kind != observation.Rejected) {
			return false
		}
		reads += 2
		w.literal(`{"from_keyspace":`)
		if !w.balanceText(c, visit.From, &strings) {
			return false
		}
		w.literal(`,"to_keyspace":`)
		if !w.balanceText(c, visit.To, &strings) {
			return false
		}
		w.literal(`,"callback":`)
		equal := bytes.Equal(c.Range(visit.From), c.Range(visit.To))
		switch visit.Callback {
		case observation.BalanceCallbackSkipped:
			if equal || batch.Events[0].Kind != observation.Rejected {
				return false
			}
			w.literal(`null`)
		case observation.BalanceCallbackRefused, observation.BalanceCallbackAccepted:
			if !equal || (visit.Callback == observation.BalanceCallbackAccepted) != (batch.Events[0].Kind == observation.Redirect) {
				return false
			}
			reads++
			w.boolean(visit.Callback == observation.BalanceCallbackAccepted)
		default:
			return false
		}
		w.literal(`,"batch":`)
		sequence := record.Sequence + uint64(childIndex)
		if sequence < record.Sequence || !w.callerBatch(observation.Record{Epoch: record.Epoch, Sequence: sequence, Native: true, Batch: batch}) {
			return false
		}
		childIndex++
		w.literal(`}}`)
	}
	if childIndex != len(children) || c.Span() != uint64(childIndex+1) || record.Sequence > math.MaxUint64-c.Span()+1 || reads != int(b.ReadCount) || reads > observation.MaxCallerReads || strings != b.StringBytes {
		return false
	}
	w.literal(`],"accepted":`)
	w.small(int64(b.Accepted))
	w.literal(`}`)
	return !w.failed
}

func (w *nativeEncoder) balanceText(c *observation.Caller, ref observation.DataRef, total *uint32) bool {
	if ref.Length > observation.MaxEvaluationStringBytes || uint64(ref.Offset)+uint64(ref.Length) > uint64(len(c.Bytes())) {
		return false
	}
	value := c.Range(ref)
	if len(value) != int(ref.Length) {
		return false
	}
	*total += ref.Length
	if *total > observation.MaxEvaluationStringsBytes {
		return false
	}
	w.text(string(value))
	return !w.failed
}
