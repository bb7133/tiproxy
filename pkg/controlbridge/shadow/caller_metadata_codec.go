// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import "github.com/pingcap/tiproxy/pkg/balance/observation"

// routerMetadata encodes one header-only router metadata frame (span 1, no
// children). Begin carries the health-loop inputs, Assign one actual backend
// outcome with the values that decision read, Refresh one Group's recomputed
// values, End the actual completion counts. The consumer derives the group
// inventory independently and treats every Go outcome here as a witness.
func (w *nativeEncoder) routerMetadata(record observation.Record) bool {
	c, m := record.Caller, record.Caller.Metadata()
	if m == nil || m.Kind != observation.MetadataInit && m.Generation == 0 || c.Span() != 1 || len(c.Children()) != 0 {
		return false
	}
	switch m.Kind {
	case observation.MetadataInit:
		if m.Generation != 0 || m.Rule < observation.MetadataRuleAll || m.Rule > observation.MetadataRulePort || m.RawRule.Offset != 0 || int(m.RawRule.Length) != len(c.Bytes()) || m.RawRule.Length > observation.MaxEvaluationStringBytes {
			return false
		}
		w.literal(`"metadata_init":{"raw_rule":`)
		w.textBytes(c.Bytes())
		w.literal(`,"rule":`)
		w.small(int64(m.Rule))
		w.literal(`}`)
	case observation.MetadataBegin:
		return w.metadataBegin(c, m)
	case observation.MetadataAssign:
		if m.Account == 0 || m.Index >= observation.MaxMetadataBackends || m.Removed && m.Group != 0 || m.Created && m.Group == 0 || m.Removed && m.Created || m.Removed && m.ValuesRead {
			return false
		}
		w.literal(`"metadata_assign":{"generation":`)
		w.uint(m.Generation)
		w.literal(`,"index":`)
		w.small(int64(m.Index))
		w.literal(`,"account":`)
		w.uint(m.Account)
		w.literal(`,"group":`)
		w.uint(m.Group)
		w.literal(`,"removed":`)
		w.boolean(m.Removed)
		w.literal(`,"created":`)
		w.boolean(m.Created)
		if !w.metadataValues(c, m) {
			return false
		}
		w.literal(`}`)
	case observation.MetadataRefresh:
		return w.metadataRefresh(c, m)
	case observation.MetadataEnd:
		if m.GroupCount > observation.MaxCallerGroups || m.CreatedCount > observation.MaxCallerGroups || m.RemovedCount > observation.MaxCallerGroups ||
			m.RefreshFailed > observation.MaxCallerGroups || m.ConflictCount > observation.MaxMetadataValues || len(c.Bytes()) != 0 {
			return false
		}
		w.literal(`"metadata_end":{"generation":`)
		w.uint(m.Generation)
		w.literal(`,"support_redirection":`)
		w.boolean(m.SupportRedirection)
		w.literal(`,"groups":`)
		w.small(int64(m.GroupCount))
		w.literal(`,"created":`)
		w.small(int64(m.CreatedCount))
		w.literal(`,"removed":`)
		w.small(int64(m.RemovedCount))
		w.literal(`,"refresh_failed":`)
		w.small(int64(m.RefreshFailed))
		w.literal(`,"conflicts":`)
		w.small(int64(m.ConflictCount))
		w.literal(`}`)
	default:
		return false
	}
	return true
}

func (w *nativeEncoder) metadataBegin(c *observation.Caller, m *observation.RouterMetadata) bool {
	if m.ObserverError < observation.SelectorNoError || m.ObserverError > observation.SelectorOtherError ||
		m.Rule < observation.MetadataRuleAll || m.Rule > observation.MetadataRulePort ||
		m.InputCount > observation.MaxMetadataBackends || m.ValueCount != 0 || len(c.Bytes()) != 0 ||
		m.ObserverError != observation.SelectorNoError && m.InputCount != 0 {
		return false
	}
	w.literal(`"metadata_begin":{"generation":`)
	w.uint(m.Generation)
	w.literal(`,"observer_error":`)
	w.small(int64(m.ObserverError))
	w.literal(`,"rule":`)
	w.small(int64(m.Rule))
	w.literal(`,"inputs":[`)
	for i := range m.Inputs[:m.InputCount] {
		input := &m.Inputs[i]
		held := input.Account != 0
		if !held && (input.Healthy || !input.Present) || !input.Present && input.Healthy {
			return false
		}
		for _, earlier := range m.Inputs[:i] {
			if held && earlier.Account == input.Account {
				return false
			}
		}
		if i > 0 {
			w.literal(",")
		}
		w.literal(`{"account":`)
		w.uint(input.Account)
		w.literal(`,"healthy":`)
		w.boolean(input.Healthy)
		w.literal(`,"support_redirection":`)
		w.boolean(input.SupportRedirection)
		w.literal(`,"present":`)
		w.boolean(input.Present)
		w.literal(`}`)
	}
	for _, unused := range m.Inputs[m.InputCount:] {
		if unused.Account != 0 {
			return false
		}
	}
	w.literal(`]}`)
	return true
}

// metadataRefresh encodes the per-member Cidr() read tape followed by the
// stored result; members are absent for a rule that recomputes nothing.
func (w *nativeEncoder) metadataRefresh(c *observation.Caller, m *observation.RouterMetadata) bool {
	if m.Group == 0 || !m.ResultSet || m.MemberCount > observation.MaxMetadataBackends || m.ResultStart > m.ValueCount ||
		!m.ValuesRead && (m.MemberCount != 0 || m.ValueCount != 0 || !m.Parsed) ||
		m.ValueCount > observation.MaxMetadataValues || m.ValueBytes > observation.MaxEvaluationStringsBytes || int(m.ValueBytes) != len(c.Bytes()) {
		return false
	}
	w.literal(`"metadata_refresh":{"generation":`)
	w.uint(m.Generation)
	w.literal(`,"group":`)
	w.uint(m.Group)
	w.literal(`,"values_read":`)
	w.boolean(m.ValuesRead)
	w.literal(`,"members":[`)
	var next uint16
	for i := range m.Members[:m.MemberCount] {
		member := &m.Members[i]
		if member.Account == 0 || member.ValueStart != next || int(member.ValueStart)+int(member.ValueCount) > int(m.ResultStart) {
			return false
		}
		for _, earlier := range m.Members[:i] {
			if earlier.Account == member.Account {
				return false
			}
		}
		next = member.ValueStart + member.ValueCount
		if i > 0 {
			w.literal(",")
		}
		w.literal(`{"account":`)
		w.uint(member.Account)
		w.literal(`,"values":[`)
		if !w.metadataValueRange(c, m, member.ValueStart, next) {
			return false
		}
		w.literal(`]}`)
	}
	if next != m.ResultStart {
		return false
	}
	w.literal(`],"values":[`)
	if !w.metadataValueRange(c, m, m.ResultStart, m.ValueCount) {
		return false
	}
	w.literal(`],"parsed":`)
	w.boolean(m.Parsed)
	w.literal(`}`)
	return true
}

// metadataValues writes the values_read flag and the copied values of an
// Assign frame; a frame that read no values carries none.
func (w *nativeEncoder) metadataValues(c *observation.Caller, m *observation.RouterMetadata) bool {
	if m.ValueCount > observation.MaxMetadataValues || m.ValueBytes > observation.MaxEvaluationStringsBytes || !m.ValuesRead && m.ValueCount != 0 || int(m.ValueBytes) != len(c.Bytes()) {
		return false
	}
	w.literal(`,"values_read":`)
	w.boolean(m.ValuesRead)
	w.literal(`,"values":[`)
	if !w.metadataValueRange(c, m, 0, m.ValueCount) {
		return false
	}
	w.literal(`]`)
	return true
}

// metadataValueRange writes Values[from:to], checking each ref is contiguous
// and inside the copied bytes.
func (w *nativeEncoder) metadataValueRange(c *observation.Caller, m *observation.RouterMetadata, from, to uint16) bool {
	var offset uint64
	for _, ref := range m.Values[:from] {
		offset += uint64(ref.Length)
	}
	for j, ref := range m.Values[from:to] {
		if ref.Length > observation.MaxEvaluationStringBytes || uint64(ref.Offset) != offset || offset+uint64(ref.Length) > uint64(len(c.Bytes())) {
			return false
		}
		value := c.Range(ref)
		if len(value) != int(ref.Length) {
			return false
		}
		offset += uint64(ref.Length)
		if j > 0 {
			w.literal(",")
		}
		w.textBytes(value)
	}
	return true
}
