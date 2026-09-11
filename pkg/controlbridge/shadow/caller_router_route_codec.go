// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import "github.com/pingcap/tiproxy/pkg/balance/observation"

func (w *nativeEncoder) routerRoute(record observation.Record) bool {
	c, r := record.Caller, record.Caller.RouterRoute()
	if r == nil || r.ID == 0 || r.Generation == 0 || r.Session == 0 || r.Next == 0 || r.Attempt < 1 || r.Attempt > 2 || !r.ResultSet || r.GroupCount > observation.MaxCallerGroups || r.ExcludedCount > observation.MaxCallerGroups || r.ReadCount > r.GroupCount || r.Rule < observation.MetadataRuleAll || r.Rule > observation.MetadataRulePort || r.ObserverError < observation.SelectorNoError || r.ObserverError > observation.SelectorOtherError || r.Error < observation.SelectorNoError || r.Error > observation.SelectorOtherError || (r.Backend == 0) != (r.Error != observation.SelectorNoError) {
		return false
	}
	w.literal(`"router_route":{"caller":`)
	w.uint(r.ID)
	w.literal(`,"generation":`)
	w.uint(r.Generation)
	w.literal(`,"session":`)
	w.uint(r.Session)
	w.literal(`,"next":`)
	w.uint(r.Next)
	w.literal(`,"attempt":`)
	w.small(int64(r.Attempt))
	w.literal(`,"rule":`)
	w.small(int64(r.Rule))
	w.literal(`,"observer_error":`)
	w.small(int64(r.ObserverError))
	w.literal(`,"groups":`)
	if !w.routerIdentities(r.Groups[:], int(r.GroupCount)) {
		return false
	}
	w.literal(`,"excluded":`)
	if !w.routerIdentities(r.Excluded[:], int(r.ExcludedCount)) {
		return false
	}
	w.literal(`,"port_visited":`)
	w.boolean(r.PortVisited)
	w.literal(`,"detector_present":`)
	w.boolean(r.DetectorPresent)
	w.literal(`,"listener":`)
	var strings uint32
	if r.DetectorPresent {
		if !r.PortVisited || !w.routerText(c, r.Listener, &strings) {
			return false
		}
	} else {
		if r.Listener != (observation.DataRef{}) {
			return false
		}
		w.literal(`""`)
	}
	w.literal(`,"reads":[`)
	for i, read := range r.Reads {
		if i >= int(r.ReadCount) {
			if read != (observation.RouterMatch{}) {
				return false
			}
			continue
		}
		if !read.Complete || read.Group != r.Groups[i] {
			return false
		}
		if i > 0 {
			w.literal(`,`)
		}
		w.literal(`{"group":`)
		w.uint(read.Group)
		w.literal(`,"address_read":`)
		w.boolean(read.AddressRead)
		w.literal(`,"address":`)
		if read.AddressRead {
			if !w.routerText(c, read.Address, &strings) {
				return false
			}
		} else {
			if read.Address != (observation.DataRef{}) {
				return false
			}
			w.literal(`""`)
		}
		w.literal(`,"matched":`)
		w.boolean(read.Matched)
		w.literal(`}`)
	}
	if strings != r.StringBytes || strings > observation.MaxEvaluationStringsBytes {
		return false
	}
	w.literal(`],"target":`)
	w.uint(r.Target)
	w.literal(`,"backend":`)
	w.uint(r.Backend)
	w.literal(`,"error":`)
	w.small(int64(r.Error))
	w.literal(`,"path":{`)
	if r.Target != 0 {
		inner := c.Route()
		if inner == nil || inner.ID != r.ID || inner.Session != r.Session || inner.Group != r.Target || inner.Account != r.Backend || inner.ExcludedCount != r.ExcludedCount || inner.StringBytes+r.StringBytes > observation.MaxEvaluationStringsBytes || !w.groupRoute(record) {
			return false
		}
	} else {
		if c.Route() != nil || r.Backend != 0 || c.Span() != 2 || len(c.Children()) != 1 {
			return false
		}
		child := c.Children()[0]
		if child.Evaluation != nil || child.Batch.EventCount != 1 || child.Batch.Events[0] != (observation.Event{Kind: observation.RouteRejected, Session: r.Session}) {
			return false
		}
		w.literal(`"rejected":`)
		if !w.callerBatch(observation.Record{Epoch: record.Epoch, Sequence: record.Sequence, Native: true, Batch: child.Batch}) {
			return false
		}
	}
	w.literal(`}}`)
	return !w.failed
}

func (w *nativeEncoder) routerIdentities(ids []uint64, count int) bool {
	w.literal(`[`)
	for i, id := range ids {
		if i >= count {
			if id != 0 {
				return false
			}
			continue
		}
		if id == 0 {
			return false
		}
		for _, old := range ids[:i] {
			if old == id {
				return false
			}
		}
		if i > 0 {
			w.literal(`,`)
		}
		w.uint(id)
	}
	w.literal(`]`)
	return true
}

func (w *nativeEncoder) routerText(c *observation.Caller, ref observation.DataRef, count *uint32) bool {
	if ref.Length > observation.MaxEvaluationStringBytes || uint64(ref.Offset)+uint64(ref.Length) > uint64(len(c.Bytes())) {
		return false
	}
	value := c.Range(ref)
	if len(value) != int(ref.Length) {
		return false
	}
	*count += ref.Length
	w.text(string(value))
	return true
}
