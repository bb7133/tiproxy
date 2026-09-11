// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

const MaxCallerGroups = 64

type RouterPassKind uint8

const (
	RouterPassBegin RouterPassKind = iota + 1
	RouterPassEnd
)

// RouterPass contains only values already read under the router lock. Group
// envelopes are separate deliveries and retain their own Group lock boundary.
// The group list is a witness; the consumer must compare it to its independently
// retained metadata order before it can accept any pass completion.
type RouterPass struct {
	Kind               RouterPassKind
	ID                 uint64
	SupportRedirection bool
	Groups             [MaxCallerGroups]uint64
	GroupCount         uint16
	Balanced           uint16
	Closed             uint16
}

// CapturePassBegin copies the actual router group iteration order and gate.
// It cannot be combined with opaque bytes or any Group children.
func (c *Caller) CapturePassBegin(id uint64, supportRedirection bool, groups []uint64) bool {
	if !c.passWritable(id) {
		return false
	}
	if len(groups) > MaxCallerGroups {
		c.owner.Invalidate(Capacity)
		return false
	}
	for i, group := range groups {
		if group == 0 {
			c.owner.Invalidate(Malformed)
			return false
		}
		for _, previous := range groups[:i] {
			if previous == group {
				c.owner.Invalidate(Malformed)
				return false
			}
		}
	}
	p := &c.storage.pass
	p.Kind, p.ID, p.SupportRedirection, p.GroupCount = RouterPassBegin, id, supportRedirection, uint16(len(groups))
	copy(p.Groups[:], groups)
	return true
}

// CapturePassEnd records the actual completed call counts, not intended counts.
func (c *Caller) CapturePassEnd(id uint64, balanced, closed uint16) bool {
	if !c.passWritable(id) {
		return false
	}
	if balanced > MaxCallerGroups || closed > MaxCallerGroups {
		c.owner.Invalidate(Capacity)
		return false
	}
	c.storage.pass = RouterPass{Kind: RouterPassEnd, ID: id, Balanced: balanced, Closed: closed}
	return true
}

func (c *Caller) passWritable(id uint64) bool {
	if !c.writable() {
		return false
	}
	if id == 0 || c.storage.finish.ID != 0 || c.storage.selector.Kind != 0 || c.storage.pass.Kind != 0 || c.storage.route.ID != 0 || c.storage.routerRoute.ID != 0 || c.storage.balance.ID != 0 || c.storage.metadata.Kind != 0 || c.length != 0 || c.evaluations != 0 || c.batches != 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	return true
}

// Pass returns a borrowed immutable view after sealing. It grants no scheduling
// coverage and remains valid only until the final parent delivery releases it.
func (c *Caller) Pass() *RouterPass {
	if c == nil || !c.sealed || c.released.Load() || c.storage.pass.Kind == 0 {
		return nil
	}
	return &c.storage.pass
}

// Fail invalidates the owner when a writer cannot encode the entire delivery.
func (c *Caller) Fail(reason InvalidReason) {
	if c != nil && c.owner != nil {
		c.owner.Invalidate(reason)
	}
}
