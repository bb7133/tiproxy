// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

// SelectorErrorClass preserves the exact equality used by BackendSelector.Next.
// A wrapped ErrNoBackend is OtherError even if errors.Is would match it.
// The router metadata and selector codecs share these wire discriminants.
type SelectorErrorClass uint8

const (
	SelectorNoError SelectorErrorClass = iota + 1
	SelectorExactNoBackend
	SelectorOtherError
)

// SelectorBoundaryKind distinguishes actual Next entry/return and selection end.
type SelectorBoundaryKind uint8

const (
	SelectorBegin SelectorBoundaryKind = iota + 1
	SelectorEnd
	SelectorClose
)

// SelectorBoundary contains witnesses only. The consumer derives each attempt
// before it accepts the return or retains the next exclusion/current state.
// All fields fit in the parent's precharged fixed header allowance.
type SelectorBoundary struct {
	Kind                            SelectorBoundaryKind
	Session, Next, Current, Backend uint64
	Error                           SelectorErrorClass
	Excluded                        [MaxCallerGroups]uint64
	ExcludedCount                   uint16
}

// CaptureSelector copies a completed value into an empty, precharged parent.
// It never truncates the production selector's exclusion history.
func (c *Caller) CaptureSelector(value *SelectorBoundary) bool {
	if !c.writable() {
		return false
	}
	if c.storage.finish.ID != 0 || value == nil || value.Session == 0 || c.length != 0 || c.children != 0 ||
		c.storage.pass.Kind != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 || c.storage.selector.Kind != 0 || c.storage.metadata.Kind != 0 {
		c.Fail(Malformed)
		return false
	}
	if value.ExcludedCount > MaxCallerGroups {
		c.Fail(Capacity)
		return false
	}
	for i, id := range value.Excluded {
		if i < int(value.ExcludedCount) && id == 0 || i >= int(value.ExcludedCount) && id != 0 {
			c.Fail(Malformed)
			return false
		}
	}
	switch value.Kind {
	case SelectorBegin:
		if value.Next == 0 || value.Backend != 0 || value.Error != 0 {
			c.Fail(Malformed)
			return false
		}
	case SelectorEnd:
		if value.Next == 0 || value.Error < SelectorNoError || value.Error > SelectorOtherError {
			c.Fail(Malformed)
			return false
		}
	case SelectorClose:
		if value.Backend != 0 || value.Error != 0 {
			c.Fail(Malformed)
			return false
		}
	default:
		c.Fail(Malformed)
		return false
	}
	c.storage.selector = *value
	return true
}

// Selector is immutable after sealing and valid until final delivery release.
func (c *Caller) Selector() *SelectorBoundary {
	if c == nil || !c.sealed || c.released.Load() || c.storage.selector.Kind == 0 {
		return nil
	}
	return &c.storage.selector
}

// GroupFinish binds the actual creation callback to its original reservation.
// The complete Created batch is retained in the same Group critical section.
type GroupFinish struct {
	ID, Group, Session, Backend, Operation uint64
	Success, ResultSet                     bool
}

func (c *Caller) CaptureGroupFinish(id, group, session, backend, operation uint64, success bool) bool {
	if !c.writable() {
		return false
	}
	if id == 0 || group == 0 || session == 0 || backend == 0 || operation == 0 ||
		c.length != 0 || c.children != 0 || c.evaluations != 0 || c.storage.pass.Kind != 0 ||
		c.storage.selector.Kind != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 || c.storage.finish.ID != 0 || c.storage.metadata.Kind != 0 {
		c.Fail(Malformed)
		return false
	}
	c.storage.finish = GroupFinish{ID: id, Group: group, Session: session, Backend: backend, Operation: operation, Success: success}
	return true
}

func (c *Caller) CaptureFinishResult() bool {
	if !c.writable() {
		return false
	}
	if c.storage.finish.ID == 0 || c.storage.finish.ResultSet || c.children != 1 || c.batches != 1 || c.evaluations != 0 {
		c.Fail(Malformed)
		return false
	}
	c.storage.finish.ResultSet = true
	return true
}

func (c *Caller) Finish() *GroupFinish {
	if c == nil || !c.sealed || c.released.Load() || c.storage.finish.ID == 0 {
		return nil
	}
	return &c.storage.finish
}
