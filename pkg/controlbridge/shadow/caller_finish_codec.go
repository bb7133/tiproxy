// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import "github.com/pingcap/tiproxy/pkg/balance/observation"

func (w *nativeEncoder) groupFinish(record observation.Record) bool {
	c, f := record.Caller, record.Caller.Finish()
	if f == nil || !f.ResultSet || f.ID == 0 || f.Group == 0 || f.Session == 0 || f.Backend == 0 || f.Operation == 0 || c.Span() != 2 || len(c.Children()) != 1 {
		return false
	}
	child := c.Children()[0]
	if child.Evaluation != nil || child.Batch.EventCount != 1 {
		return false
	}
	w.literal(`"group_finish":{"caller":`)
	w.uint(f.ID)
	w.literal(`,"group":`)
	w.uint(f.Group)
	w.literal(`,"session":`)
	w.uint(f.Session)
	w.literal(`,"backend":`)
	w.uint(f.Backend)
	w.literal(`,"operation":`)
	w.uint(f.Operation)
	w.literal(`,"success":`)
	w.boolean(f.Success)
	w.literal(`,"created":`)
	if !w.callerBatch(observation.Record{Epoch: record.Epoch, Sequence: record.Sequence, Batch: child.Batch}) {
		return false
	}
	w.literal(`}`)
	return !w.failed
}
