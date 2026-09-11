// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// Router metadata frames are header-only callers (span 1, no children), like
// RouterPass. One health refresh produces exactly one Begin, then one Assign
// per backend decision published immediately after that backend's actual Group
// action, one Refresh per Group CIDR recomputation published inside that
// Group's lock, then one End. Group lock sections keep their own batches, so
// the interleaving with connection callbacks stays real.
//
// Every value is copied at the production read site: Begin inputs are written
// from inside the health loop, Assign values are the slice the grouping code
// actually obtained, Refresh values are the recomputed list the Group actually
// stored. The observer calls no getter and changes no decision. The parent is
// leased before any copy; every bound violation invalidates the owner instead
// of truncating.

const (
	MaxMetadataBackends = 64
	// MaxMetadataValues bounds the values carried by one refresh in aggregate
	// (across all Assign and Refresh frames of one generation), per contract.
	MaxMetadataValues = 256
	// MetadataScratchCharge is the leased, bounded scratch one refresh keeps
	// across its frames (generation, counters, aggregate value accounting and
	// the producer-side handle). It is reserved before that handle exists.
	MetadataScratchCharge = 4 << 10
)

// MetadataScratch is the per-refresh scratch lease. It holds the counters the
// producer needs between frames and enforces the per-refresh aggregate value
// bound with the same accounting the frames use. Its sole owner releases it
// after End, or on any earlier exit.
type MetadataScratch struct {
	once       sync.Once
	owner      *Owner
	released   atomic.Bool
	Generation uint64
	Index      uint16
	Created    uint16
	Removed    uint16
	valueCount int
	valueBytes int
	// dropped records the held backends the fresh list no longer contains,
	// by identity, in the fixed capacity the lease charges.
	dropped      [MaxMetadataBackends]uint64
	droppedCount int
}

// LeaseMetadataScratch reserves the refresh scratch before any producer-side
// allocation. Capacity failure invalidates evidence only.
func (o *Owner) LeaseMetadataScratch(generation uint64) *MetadataScratch {
	if !o.Enabled() || generation == 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		return nil
	}
	if !o.native {
		o.Invalidate(Malformed)
		return nil
	}
	if !o.recorder.reserve(MetadataScratchCharge) {
		o.Invalidate(Capacity)
		return nil
	}
	return &MetadataScratch{owner: o, Generation: generation}
}

// Release returns the scratch charge at most once.
func (s *MetadataScratch) Release() {
	if s != nil {
		s.once.Do(func() {
			s.released.Store(true)
			s.owner.recorder.release(MetadataScratchCharge)
		})
	}
}

// Dropped records one held backend the fresh list no longer contains. A 65th
// entry is a capacity violation of the owner, never a cut.
func (s *MetadataScratch) Dropped(account uint64) bool {
	if s == nil || s.released.Load() || account == 0 {
		return false
	}
	if s.droppedCount >= MaxMetadataBackends {
		s.owner.Invalidate(Capacity)
		return false
	}
	s.dropped[s.droppedCount] = account
	s.droppedCount++
	return true
}

// IsDropped reports whether Dropped recorded account.
func (s *MetadataScratch) IsDropped(account uint64) bool {
	if s == nil {
		return false
	}
	for _, dropped := range s.dropped[:s.droppedCount] {
		if dropped == account {
			return true
		}
	}
	return false
}

// NextIndex hands out the next decision index; a 65th decision is a capacity
// violation of the owner, never a cut.
func (s *MetadataScratch) NextIndex() (uint16, bool) {
	if s == nil || s.released.Load() {
		return 0, false
	}
	if int(s.Index) >= MaxMetadataBackends {
		s.owner.Invalidate(Capacity)
		return 0, false
	}
	index := s.Index
	s.Index++
	return index, true
}

// Account charges values against the per-refresh aggregate before they are
// copied into a frame; overflow invalidates the owner.
func (s *MetadataScratch) Account(values []string) bool {
	if s == nil || s.released.Load() {
		return false
	}
	s.valueCount += len(values)
	for _, value := range values {
		s.valueBytes += len(value)
	}
	if s.valueCount > MaxMetadataValues || s.valueBytes > MaxEvaluationStringsBytes {
		s.owner.Invalidate(Capacity)
		return false
	}
	return true
}

type MetadataKind uint8

const (
	MetadataBegin MetadataKind = iota + 1
	MetadataAssign
	MetadataRefresh
	MetadataEnd
)

// MetadataRule mirrors the router's fixed match type.
type MetadataRule uint8

const (
	MetadataRuleAll MetadataRule = iota + 1
	MetadataRuleClientCIDR
	MetadataRuleProxyCIDR
	MetadataRulePort
)

// MetadataInput is one backend exactly as the health loop read it. The router
// holds a wrapper for it after that iteration exactly when Account is nonzero
// (an unhealthy backend the router never held is not identified). Present is
// false for a backend the fresh list dropped but the router still holds.
type MetadataInput struct {
	Account            uint64
	Healthy            bool
	SupportRedirection bool
	Present            bool
}

// MetadataMember is one member's `Cidr()` read inside RefreshCidr, in the
// actual map iteration order. Values occupy Values[ValueStart:+ValueCount].
type MetadataMember struct {
	Account                uint64
	ValueStart, ValueCount uint16
}

// RouterMetadata holds one frame. Begin carries the input set in loop order;
// Assign carries one backend's actual outcome with the values the decision
// read; Refresh carries every member read of one Group's CIDR recomputation
// followed by the stored result; End carries the actual completion counts.
type RouterMetadata struct {
	Kind          MetadataKind
	Generation    uint64
	ObserverError SelectorErrorClass
	Rule          MetadataRule
	// Begin.
	InputCount uint16
	Inputs     [MaxMetadataBackends]MetadataInput
	// Assign and Refresh: values as read. ValuesRead is false when the
	// production path never read them (removal, MatchAll, non-CIDR refresh).
	ValuesRead bool
	ValueCount uint16
	ValueBytes uint32
	Values     [MaxMetadataValues]DataRef
	// Assign: actual outcome for one backend, in the order Go decided it.
	Index   uint16
	Account uint64
	Group   uint64 // Group after the decision (Assign) or refreshed (Refresh); zero when none.
	Removed bool   // Backend was removed from the router.
	Created bool   // This decision created the Group.
	// Refresh: the per-member reads, the stored result (Values[ResultStart:])
	// and whether it parsed. ResultSet closes the frame.
	MemberCount uint16
	Members     [MaxMetadataBackends]MetadataMember
	ResultStart uint16
	ResultSet   bool
	Parsed      bool
	// End: actual completion counts of the whole refresh.
	SupportRedirection bool
	GroupCount         uint16
	CreatedCount       uint16
	RemovedCount       uint16
	RefreshFailed      uint16
	ConflictCount      uint16
}

func (c *Caller) metadataWritable(generation uint64) bool {
	if !c.writable() {
		return false
	}
	if generation == 0 || c.storage.pass.Kind != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 || c.storage.selector.Kind != 0 || c.storage.finish.ID != 0 || c.evaluations != 0 || c.batches != 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	return true
}

func validMetadataRule(rule MetadataRule) bool {
	return rule >= MetadataRuleAll && rule <= MetadataRulePort
}

func validSelectorErrorClass(class SelectorErrorClass) bool {
	return class >= SelectorNoError && class <= SelectorOtherError
}

// CaptureMetadataBegin opens the Begin header before the health loop copies
// any input. With an observer error the refresh reads no backend, so no input
// may follow.
func (c *Caller) CaptureMetadataBegin(generation uint64, observerError SelectorErrorClass, rule MetadataRule) bool {
	if !c.metadataWritable(generation) {
		return false
	}
	if c.storage.metadata.Kind != 0 || c.length != 0 || !validMetadataRule(rule) || !validSelectorErrorClass(observerError) {
		c.owner.Invalidate(Malformed)
		return false
	}
	c.storage.metadata = RouterMetadata{Kind: MetadataBegin, Generation: generation, ObserverError: observerError, Rule: rule}
	return true
}

// CaptureMetadataInput appends one backend from inside the health loop, in the
// actual iteration order. held states the producer's own view and must agree
// with the identity. A 65th input is a capacity violation, not a cut.
func (c *Caller) CaptureMetadataInput(account uint64, held, healthy, supportRedirection, present bool) bool {
	m := &c.storage.metadata
	if !c.metadataWritable(m.Generation) {
		return false
	}
	if m.Kind != MetadataBegin || m.ObserverError != SelectorNoError || held != (account != 0) || !held && (healthy || !present) {
		c.owner.Invalidate(Malformed)
		return false
	}
	if int(m.InputCount) >= MaxMetadataBackends {
		c.owner.Invalidate(Capacity)
		return false
	}
	if held {
		for _, earlier := range m.Inputs[:m.InputCount] {
			if earlier.Account == account {
				c.owner.Invalidate(Malformed)
				return false
			}
		}
	}
	m.Inputs[m.InputCount] = MetadataInput{Account: account, Healthy: healthy, SupportRedirection: supportRedirection, Present: present}
	m.InputCount++
	return true
}

// copyMetadataValues copies already-read values into the frame. The caller
// enforces the per-refresh aggregate; here each value and the frame's own
// storage are bounded.
func (c *Caller) copyMetadataValues(values []string) bool {
	m := &c.storage.metadata
	if len(values) > MaxMetadataValues {
		c.owner.Invalidate(Capacity)
		return false
	}
	for _, value := range values {
		if len(value) > MaxEvaluationStringBytes || len(value) > MaxEvaluationStringsBytes-int(m.ValueBytes) {
			c.owner.Invalidate(Capacity)
			return false
		}
		if !utf8.ValidString(value) {
			c.owner.Invalidate(Malformed)
			return false
		}
		m.Values[m.ValueCount] = DataRef{Offset: uint32(c.length), Length: uint32(len(value))}
		if !c.appendBytes([]byte(value)) {
			return false
		}
		m.ValueCount++
		m.ValueBytes += uint32(len(value))
	}
	return true
}

// CaptureMetadataAssign records one backend's actual outcome right after its
// Group action, together with the grouping values that decision actually read
// (valuesRead is false on the removal and MatchAll paths, where Go reads none).
func (c *Caller) CaptureMetadataAssign(generation uint64, index uint16, account, group uint64, removed, created, valuesRead bool, values []string) bool {
	if !c.metadataWritable(generation) {
		return false
	}
	if c.storage.metadata.Kind != 0 || c.length != 0 || account == 0 || index >= MaxMetadataBackends || removed && group != 0 || created && group == 0 || removed && created || removed && valuesRead || !valuesRead && len(values) != 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	c.storage.metadata = RouterMetadata{Kind: MetadataAssign, Generation: generation, Index: index, Account: account, Group: group, Removed: removed, Created: created, ValuesRead: valuesRead}
	return c.copyMetadataValues(values)
}

// CaptureMetadataRefresh opens one Group's CIDR recomputation frame inside
// that Group's lock, before the first member read. Non-CIDR rules recompute
// nothing (valuesRead false): no member and no result value may follow.
func (c *Caller) CaptureMetadataRefresh(generation uint64, group uint64, valuesRead bool) bool {
	if !c.metadataWritable(generation) {
		return false
	}
	if c.storage.metadata.Kind != 0 || c.length != 0 || group == 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	c.storage.metadata = RouterMetadata{Kind: MetadataRefresh, Generation: generation, Group: group, ValuesRead: valuesRead}
	return true
}

// CaptureMetadataRefreshMember copies one member's actual Cidr() read, at the
// read site. A 65th member is a capacity violation.
func (c *Caller) CaptureMetadataRefreshMember(account uint64, values []string) bool {
	m := &c.storage.metadata
	if !c.metadataWritable(m.Generation) {
		return false
	}
	if m.Kind != MetadataRefresh || !m.ValuesRead || m.ResultSet || account == 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	for _, earlier := range m.Members[:m.MemberCount] {
		if earlier.Account == account {
			c.owner.Invalidate(Malformed)
			return false
		}
	}
	if int(m.MemberCount) >= MaxMetadataBackends {
		c.owner.Invalidate(Capacity)
		return false
	}
	start := m.ValueCount
	if !c.copyMetadataValues(values) {
		return false
	}
	m.Members[m.MemberCount] = MetadataMember{Account: account, ValueStart: start, ValueCount: uint16(len(values))}
	m.MemberCount++
	return true
}

// CaptureMetadataRefreshResult closes the frame with the value list exactly as
// stored on the Group and whether it parsed.
func (c *Caller) CaptureMetadataRefreshResult(values []string, parsed bool) bool {
	m := &c.storage.metadata
	if !c.metadataWritable(m.Generation) {
		return false
	}
	if m.Kind != MetadataRefresh || m.ResultSet || !m.ValuesRead && (len(values) != 0 || !parsed) {
		c.owner.Invalidate(Malformed)
		return false
	}
	m.ResultStart = m.ValueCount
	if !c.copyMetadataValues(values) {
		return false
	}
	m.ResultSet, m.Parsed = true, parsed
	return true
}

// CaptureMetadataEnd records the actual counts after CIDR refresh and port
// conflict rebuild; they are witnesses for the independently derived state.
func (c *Caller) CaptureMetadataEnd(generation uint64, supportRedirection bool, groupCount, created, removed, refreshFailed, conflicts uint16) bool {
	if !c.metadataWritable(generation) {
		return false
	}
	if c.storage.metadata.Kind != 0 || c.length != 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	if groupCount > MaxCallerGroups || created > MaxCallerGroups || removed > MaxCallerGroups || refreshFailed > MaxCallerGroups || conflicts > MaxMetadataValues {
		c.owner.Invalidate(Capacity)
		return false
	}
	c.storage.metadata = RouterMetadata{Kind: MetadataEnd, Generation: generation, SupportRedirection: supportRedirection, GroupCount: groupCount, CreatedCount: created, RemovedCount: removed, RefreshFailed: refreshFailed, ConflictCount: conflicts}
	return true
}

// Metadata returns a borrowed immutable view after sealing.
func (c *Caller) Metadata() *RouterMetadata {
	if c == nil || !c.sealed || c.released.Load() || c.storage.metadata.Kind == 0 {
		return nil
	}
	return &c.storage.metadata
}
