// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"encoding/binary"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
)

// EncodeCaller currently accepts typed router pass, Group route and Group Balance boundaries. It does not
// install a v4 transport or grant selection/scheduler coverage. The returned
// bytes borrow the parent's charged arena until the final writer releases it.
func EncodeCaller(record observation.Record) (frame []byte, err error) {
	c := record.Caller
	defer func() {
		if err != nil && c != nil {
			c.Fail(observation.Malformed)
		}
	}()
	if !record.Native || c == nil || record.Evaluation != nil || record.Batch.EventCount != 0 ||
		record.Sequence == 0 || record.Epoch.Process == 0 || record.Epoch.Owner == 0 || record.Epoch.Nonce == 0 || c.Span() == 0 {
		return nil, errSchema
	}
	p, buffer := c.Pass(), c.EncodingBuffer()
	if len(buffer) != observation.MaxCallerFrameBytes || p != nil && (c.Span() != 1 || len(c.Children()) != 0 || !validPass(p)) || p == nil && c.Route() == nil && c.Balance() == nil && c.Selector() == nil {
		return nil, errSchema
	}
	w := nativeEncoder{buffer: buffer, used: 4}
	w.literal(`{"version":4,"kind":"caller","process":`)
	w.uint(record.Epoch.Process)
	w.literal(`,"owner":`)
	w.uint(record.Epoch.Owner)
	w.literal(`,"nonce":`)
	w.uint(record.Epoch.Nonce)
	w.literal(`,"sequence":`)
	w.uint(record.Sequence)
	w.literal(`,"span":`)
	w.uint(c.Span())
	w.literal(`,"payload":{`)
	if c.Selector() != nil {
		if p != nil || c.Route() != nil || c.Balance() != nil || !w.selectorBoundary(c) {
			return nil, errSchema
		}
	} else if c.Balance() != nil {
		if p != nil || c.Route() != nil || !w.groupBalance(record) {
			return nil, errSchema
		}
	} else if p == nil {
		if !w.groupRoute(record) {
			return nil, errSchema
		}
	} else {
		if p.Kind == observation.RouterPassBegin {
			w.literal(`"pass_begin":{"pass":`)
			w.uint(p.ID)
			w.literal(`,"support_redirection":`)
			w.boolean(p.SupportRedirection)
			w.literal(`,"groups":[`)
			for i, group := range p.Groups[:p.GroupCount] {
				if i > 0 {
					w.literal(",")
				}
				w.uint(group)
			}
			w.literal(`]`)
		} else {
			w.literal(`"pass_end":{"pass":`)
			w.uint(p.ID)
			w.literal(`,"balanced":`)
			w.small(int64(p.Balanced))
			w.literal(`,"closed":`)
			w.small(int64(p.Closed))
		}
		w.literal(`}`)
	}
	w.literal(`}}`)
	if w.failed {
		c.Fail(observation.Capacity)
		return nil, errSchema
	}
	binary.BigEndian.PutUint32(buffer[:4], uint32(w.used-4))
	return buffer[:w.used:w.used], nil
}

func validPass(p *observation.RouterPass) bool {
	if p.ID == 0 || p.GroupCount > observation.MaxCallerGroups || p.Balanced > observation.MaxCallerGroups || p.Closed > observation.MaxCallerGroups {
		return false
	}
	switch p.Kind {
	case observation.RouterPassBegin:
		if p.Balanced != 0 || p.Closed != 0 {
			return false
		}
	case observation.RouterPassEnd:
		if p.SupportRedirection || p.GroupCount != 0 {
			return false
		}
	default:
		return false
	}
	for i, group := range p.Groups {
		if i >= int(p.GroupCount) {
			if group != 0 {
				return false
			}
			continue
		}
		if group == 0 {
			return false
		}
		for _, previous := range p.Groups[:i] {
			if previous == group {
				return false
			}
		}
	}
	return true
}
