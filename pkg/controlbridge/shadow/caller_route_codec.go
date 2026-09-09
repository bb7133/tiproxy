// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import "github.com/pingcap/tiproxy/pkg/balance/observation"

func (w *nativeEncoder) groupRoute(record observation.Record) bool {
	c, r := record.Caller, record.Caller.Route()
	if r == nil || r.ID == 0 || r.Group == 0 || r.Session == 0 || r.MemberCount > observation.MaxCallerGroups || r.ExcludedCount > observation.MaxCallerGroups ||
		r.ReadCount > observation.MaxCallerReads || r.StringBytes > observation.MaxEvaluationStringsBytes || !r.ResultSet || (r.Account == 0) != (r.Operation == 0) || int(r.ResultCompleted) != len(c.Children()) {
		return false
	}
	w.literal(`"group_route":{"caller":`)
	w.uint(r.ID)
	w.literal(`,"group":`)
	w.uint(r.Group)
	w.literal(`,"session":`)
	w.uint(r.Session)
	w.literal(`,"excluded_count":`)
	w.small(int64(r.ExcludedCount))
	w.literal(`,"members":[`)
	for i, member := range r.Members {
		if i >= int(r.MemberCount) {
			if member != 0 {
				return false
			}
			continue
		}
		if member == 0 {
			return false
		}
		for _, earlier := range r.Members[:i] {
			if earlier == member {
				return false
			}
		}
		if i > 0 {
			w.literal(",")
		}
		w.uint(member)
	}
	w.literal(`],"reads":[`)
	var strings uint32
	for i, read := range r.Reads[:r.ReadCount] {
		if i > 0 {
			w.literal(",")
		}
		if int(read.Completed) > len(c.Children()) {
			return false
		}
		w.literal(`{`)
		switch read.Kind {
		case observation.RouteHealthy:
			if read.Account == 0 || read.Index != 0 || read.Text != (observation.DataRef{}) {
				return false
			}
			w.literal(`"healthy":{"completed":`)
			w.small(int64(read.Completed))
			w.literal(`,"account":`)
			w.uint(read.Account)
			w.literal(`,"value":`)
			w.boolean(read.Healthy)
		case observation.RouteBackendID, observation.RouteExcludedID:
			if read.Healthy || read.Text.Length > observation.MaxEvaluationStringBytes || uint64(read.Text.Offset)+uint64(read.Text.Length) > uint64(len(c.Bytes())) {
				return false
			}
			value := c.Range(read.Text)
			if len(value) != int(read.Text.Length) {
				return false
			}
			strings += read.Text.Length
			if read.Kind == observation.RouteBackendID {
				if read.Account == 0 || read.Index != 0 {
					return false
				}
				w.literal(`"backend_id":{"completed":`)
				w.small(int64(read.Completed))
				w.literal(`,"account":`)
				w.uint(read.Account)
			} else {
				if read.Account != 0 || read.Index >= r.ExcludedCount {
					return false
				}
				w.literal(`"excluded_id":{"completed":`)
				w.small(int64(read.Completed))
				w.literal(`,"index":`)
				w.small(int64(read.Index))
			}
			w.literal(`,"value":`)
			w.text(string(value))
		default:
			return false
		}
		w.literal(`}}`)
	}
	if strings != r.StringBytes {
		return false
	}
	for _, unused := range r.Reads[r.ReadCount:] {
		if unused != (observation.RouteRead{}) {
			return false
		}
	}
	w.literal(`],"result":{"account":`)
	w.uint(r.Account)
	w.literal(`,"operation":`)
	w.uint(r.Operation)
	w.literal(`,"completed":`)
	w.small(int64(r.ResultCompleted))
	w.literal(`},"children":[`)
	sequence := record.Sequence
	evaluations, batches := 0, 0
	for i, child := range c.Children() {
		if i > 0 {
			w.literal(",")
		}
		next := observation.Record{Epoch: record.Epoch, Sequence: sequence, Native: true}
		if child.Evaluation != nil {
			if child.Batch != (observation.Batch{}) {
				return false
			}
			next.Evaluation = child.Evaluation
			n := child.Evaluation.Native()
			if n == nil || n.Group != r.Group {
				return false
			}
			frame, err := EncodeEvaluation(next)
			if err != nil {
				return false
			}
			w.literal(`{"evaluation":`)
			w.raw(frame[4:])
			w.literal(`}`)
			evaluations++
			sequence++
		} else {
			next.Batch = child.Batch
			w.literal(`{"batch":`)
			if !w.callerBatch(next) {
				return false
			}
			w.literal(`}`)
			batches++
			sequence += uint64(child.Batch.EventCount)
		}
		if evaluations > observation.MaxCallerEvaluations || batches > observation.MaxCallerBatches || sequence < record.Sequence {
			return false
		}
	}
	if sequence-record.Sequence+1 != c.Span() {
		return false
	}
	w.literal(`]}`)
	return !w.failed
}

// callerBatch writes the complete existing v2 schema into the parent's arena.
// The original batch charge remains retained; no JSON marshal/copy is added.
func (w *nativeEncoder) callerBatch(record observation.Record) bool {
	b := &record.Batch
	if b.EventCount == 0 || b.EventCount > observation.MaxEvents || b.Witness.AccountCount > observation.MaxWitnesses {
		return false
	}
	w.literal(`{"version":2,"kind":"batch","process":`)
	w.uint(record.Epoch.Process)
	w.literal(`,"owner":`)
	w.uint(record.Epoch.Owner)
	w.literal(`,"nonce":`)
	w.uint(record.Epoch.Nonce)
	w.literal(`,"lifecycle_only":true,"factors":false,"selection":false,"scheduler":false,"sequence":`)
	w.uint(record.Sequence)
	w.literal(`,"events":[`)
	for i, event := range b.Events[:b.EventCount] {
		if i > 0 {
			w.literal(",")
		}
		e, err := eventValue(event)
		if err != nil {
			return false
		}
		w.literal(`{"kind":`)
		w.text(e.Kind)
		w.literal(`,"id":`)
		w.uint(uint64(e.ID))
		w.literal(`,"group":`)
		w.uint(uint64(e.Group))
		w.literal(`,"session":`)
		w.uint(uint64(e.Session))
		w.literal(`,"operation":`)
		w.uint(uint64(e.Operation))
		w.literal(`,"account":`)
		w.uint(uint64(e.Account))
		w.literal(`,"target":`)
		w.uint(uint64(e.Target))
		w.literal(`,"success":`)
		w.boolean(e.Success)
		w.literal(`}`)
	}
	witness := &b.Witness
	w.literal(`],"witness":{"accounts":[`)
	for i, account := range witness.Accounts[:witness.AccountCount] {
		if i > 0 {
			w.literal(",")
		}
		w.literal(`{"id":`)
		w.uint(account.ID)
		w.literal(`,"score":`)
		w.signed(account.Score)
		w.literal(`,"physical":`)
		w.uint(account.Physical)
		w.literal(`,"head":`)
		w.uint(account.Head)
		w.literal(`,"tail":`)
		w.uint(account.Tail)
		w.literal(`}`)
	}
	w.literal(`],"session":`)
	w.uint(witness.Session)
	w.literal(`,"predecessor":`)
	w.uint(witness.Predecessor)
	w.literal(`,"before":`)
	w.callerConnection(witness.Before)
	w.literal(`,"after":`)
	w.callerConnection(witness.After)
	w.literal(`}}`)
	return !w.failed
}
func (w *nativeEncoder) callerConnection(c observation.ConnectionState) {
	w.literal(`{"present":`)
	w.boolean(c.Present)
	w.literal(`,"physical":`)
	w.uint(c.Physical)
	w.literal(`,"score_owner":`)
	w.uint(c.ScoreOwner)
	w.literal(`,"redirect_pending":`)
	w.boolean(c.RedirectPending)
	w.literal(`,"closing":`)
	w.boolean(c.Closing)
	w.literal(`,"closed":`)
	w.boolean(c.Closed)
	w.literal(`}`)
}
