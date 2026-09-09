// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import "unicode/utf8"

const MaxCallerReads = 128

type RouteReadKind uint8

const (
	RouteHealthy RouteReadKind = iota + 1
	RouteBackendID
	RouteExcludedID
)

// RouteRead is a value captured at the actual getter site. Completed counts
// complete children at that instant; no getter is called by the observer.
type RouteRead struct {
	Kind      RouteReadKind
	Completed uint8
	Account   uint64
	Index     uint16
	Healthy   bool
	Text      DataRef
}

// GroupRoute holds the Group-local portion of a routeOnce caller. Router match
// metadata and selector retry state must be independently bound by the eventual
// installed factory; this preparatory value does not qualify either capability.
type GroupRoute struct {
	ID, Group, Session         uint64
	Members                    [MaxCallerGroups]uint64
	MemberCount, ExcludedCount uint16
	Reads                      [MaxCallerReads]RouteRead
	ReadCount                  uint16
	StringBytes                uint32
	ResultSet                  bool
	ResultCompleted            uint8
	Account, Operation         uint64 // Both zero is the exact Group ErrNoBackend result.
}

func (c *Caller) CaptureGroupRoute(id, group, session uint64, excludedCount uint16, members []uint64) bool {
	if !c.writable() {
		return false
	}
	if id == 0 || group == 0 || session == 0 || c.length != 0 || c.evaluations != 0 || c.batches != 0 || c.storage.pass.Kind != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 {
		c.Fail(Malformed)
		return false
	}
	if len(members) > MaxCallerGroups || excludedCount > MaxCallerGroups {
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
	r := &c.storage.route
	r.ID, r.Group, r.Session, r.ExcludedCount, r.MemberCount = id, group, session, excludedCount, uint16(len(members))
	copy(r.Members[:], members)
	return true
}

func (c *Caller) routeWritable() bool {
	if !c.writable() {
		return false
	}
	if c.storage.route.ID == 0 || c.storage.route.ResultSet {
		c.Fail(Malformed)
		return false
	}
	return true
}

func (c *Caller) CaptureRouteHealthy(account uint64, healthy bool) bool {
	if !c.routeWritable() {
		return false
	}
	if account == 0 {
		c.Fail(Malformed)
		return false
	}
	return c.appendRouteRead(RouteRead{Kind: RouteHealthy, Account: account, Healthy: healthy})
}

func (c *Caller) CaptureRouteBackendID(account uint64, value string) bool {
	if !c.routeWritable() {
		return false
	}
	if account == 0 {
		c.Fail(Malformed)
		return false
	}
	return c.captureRouteText(RouteRead{Kind: RouteBackendID, Account: account}, value)
}

func (c *Caller) CaptureRouteExcludedID(index uint16, value string) bool {
	if !c.routeWritable() {
		return false
	}
	if index >= c.storage.route.ExcludedCount {
		c.Fail(Malformed)
		return false
	}
	return c.captureRouteText(RouteRead{Kind: RouteExcludedID, Index: index}, value)
}

func (c *Caller) captureRouteText(read RouteRead, value string) bool {
	r := &c.storage.route
	if len(value) > MaxEvaluationStringBytes || len(value) > MaxEvaluationStringsBytes-int(r.StringBytes) {
		c.Fail(Capacity)
		return false
	}
	if !utf8.ValidString(value) {
		c.Fail(Malformed)
		return false
	}
	if r.ReadCount == MaxCallerReads {
		c.Fail(Capacity)
		return false
	}
	read.Text = DataRef{Offset: uint32(c.length), Length: uint32(len(value))}
	if !c.appendBytes([]byte(value)) {
		return false
	}
	r.StringBytes += uint32(len(value))
	return c.appendRouteRead(read)
}

func (c *Caller) appendRouteRead(read RouteRead) bool {
	r := &c.storage.route
	if r.ReadCount == MaxCallerReads {
		c.Fail(Capacity)
		return false
	}
	read.Completed = uint8(c.children)
	r.Reads[r.ReadCount] = read
	r.ReadCount++
	return true
}

func (c *Caller) CaptureRouteResult(account, operation uint64) bool {
	if !c.routeWritable() {
		return false
	}
	if (account == 0) != (operation == 0) {
		c.Fail(Malformed)
		return false
	}
	r := &c.storage.route
	r.Account, r.Operation, r.ResultSet = account, operation, true
	r.ResultCompleted = uint8(c.children)
	return true
}

// Route returns a borrowed immutable view after sealing, until final release.
func (c *Caller) Route() *GroupRoute {
	if c == nil || !c.sealed || c.released.Load() || c.storage.route.ID == 0 {
		return nil
	}
	return &c.storage.route
}

// Range is a bounded view of copied text, never a live backend value.
func (c *Caller) Range(ref DataRef) []byte {
	if c == nil || c.released.Load() || uint64(ref.Offset)+uint64(ref.Length) > uint64(c.length) {
		return nil
	}
	return c.storage.input[ref.Offset : ref.Offset+ref.Length]
}
