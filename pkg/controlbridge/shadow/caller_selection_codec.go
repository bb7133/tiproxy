// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import "github.com/pingcap/tiproxy/pkg/balance/observation"

func (w *nativeEncoder) selectorBoundary(c *observation.Caller) bool {
	s := c.Selector()
	if s == nil || s.Session == 0 || c.Span() != 1 || len(c.Children()) != 0 || s.ExcludedCount > observation.MaxCallerGroups {
		return false
	}
	switch s.Kind {
	case observation.SelectorBegin:
		if s.Next == 0 || s.Backend != 0 || s.Error != 0 {
			return false
		}
		w.literal(`"selector_begin":{`)
	case observation.SelectorEnd:
		if s.Next == 0 || s.Error < observation.SelectorNoError || s.Error > observation.SelectorOtherError {
			return false
		}
		w.literal(`"selector_end":{`)
	case observation.SelectorClose:
		if s.Backend != 0 || s.Error != 0 {
			return false
		}
		w.literal(`"selector_close":{`)
	default:
		return false
	}
	w.literal(`"session":`)
	w.uint(s.Session)
	w.literal(`,"next":`)
	w.uint(s.Next)
	w.literal(`,"current":`)
	w.uint(s.Current)
	w.literal(`,"excluded":[`)
	for i, id := range s.Excluded {
		if i >= int(s.ExcludedCount) {
			if id != 0 {
				return false
			}
			continue
		}
		if id == 0 {
			return false
		}
		if i > 0 {
			w.literal(",")
		}
		w.uint(id)
	}
	w.literal(`]`)
	if s.Kind == observation.SelectorEnd {
		w.literal(`,"backend":`)
		w.uint(s.Backend)
		w.literal(`,"error":`)
		w.small(int64(s.Error))
	}
	w.literal(`}`)
	return true
}
