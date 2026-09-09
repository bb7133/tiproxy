// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"strconv"
	"unicode/utf8"
)

// Native is private mutable capture storage before Seal. A final writer borrows
// it read-only until Release. The 64KiB fixed charge includes this entire value.
func (e *Evaluation) Native() *NativeEvaluation {
	if e == nil || e.lease.released.Load() {
		return nil
	}
	return &e.lease.storage.native
}

func (e *Evaluation) Fail(reason InvalidReason) {
	if e != nil {
		e.owner.Invalidate(reason)
	}
}

func (e *Evaluation) Position() uint32 {
	if e == nil {
		return 0
	}
	return uint32(e.length)
}

// Range returns copied bytes for the producer's equality checks or the final
// writer, never a slice of a live backend or retained query.
func (e *Evaluation) Range(ref DataRef) []byte {
	if e == nil || e.lease.released.Load() || uint64(ref.Offset)+uint64(ref.Length) > uint64(e.length) {
		return nil
	}
	return e.lease.storage.input[ref.Offset : ref.Offset+ref.Length]
}

func (e *Evaluation) textBound(value string) bool {
	if !e.active() {
		return false
	}
	n := e.Native()
	if len(value) > MaxEvaluationStringBytes || len(value) > MaxEvaluationStringsBytes-int(n.StringBytes) {
		e.Fail(Capacity)
		return false
	}
	if !utf8.ValidString(value) {
		e.Fail(Malformed)
		return false
	}
	n.StringBytes += uint32(len(value))
	return true
}

func (e *Evaluation) CopyText(value string) DataRef {
	if !e.textBound(value) {
		return DataRef{}
	}
	ref := DataRef{Offset: e.Position(), Length: uint32(len(value))}
	e.Append([]byte(value))
	return ref
}

// JSONText streams an allowlisted string into the lease, with no temporary
// string-sized escaped allocation. Invalid UTF-8 cannot silently become U+FFFD.
func (e *Evaluation) JSONText(value string) bool {
	if !e.textBound(value) {
		return false
	}
	e.Append([]byte{'"'})
	start := 0
	const digits = "0123456789abcdef"
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 0x20 && b != '"' && b != '\\' {
			continue
		}
		e.Append([]byte(value[start:i]))
		if b == '"' || b == '\\' {
			e.Append([]byte{'\\', b})
		} else {
			e.Append([]byte{'\\', 'u', '0', '0', digits[b>>4], digits[b&15]})
		}
		start = i + 1
	}
	e.Append([]byte(value[start:]))
	return e.Append([]byte{'"'})
}

func (e *Evaluation) JSONUint(value uint64) bool {
	var buffer [22]byte
	out := append(buffer[:0], '"')
	out = strconv.AppendUint(out, value, 10)
	out = append(out, '"')
	return e.Append(out)
}

func (e *Evaluation) JSONInt(value int64) bool {
	var buffer [23]byte
	out := append(buffer[:0], '"')
	out = strconv.AppendInt(out, value, 10)
	out = append(out, '"')
	return e.Append(out)
}

func (e *Evaluation) AddSamples(count int) bool {
	if !e.active() {
		return false
	}
	n := e.Native()
	if count < 0 || count > MaxEvaluationSamples-int(n.SampleCount) {
		e.Fail(Capacity)
		return false
	}
	n.SampleCount += uint32(count)
	return true
}

func (e *Evaluation) AddRead(read NativeRead) bool {
	if !e.active() {
		return false
	}
	n := e.Native()
	if n.ReadCount == MaxEvaluationReads {
		e.Fail(Capacity)
		return false
	}
	switch read.Kind {
	case ReadClock:
		if read.Site < ClockMetricCadence || read.Site > ClockPreferIdleTicket {
			e.Fail(Malformed)
			return false
		}
		if n.ClockCount == MaxEvaluationClocks {
			e.Fail(Capacity)
			return false
		}
		n.ClockCount++
		for _, earlier := range n.Reads[:n.ReadCount] {
			if earlier.Kind == ReadClock && earlier.Site == read.Site {
				read.Ordinal++
			}
		}
	case ReadQuery:
		if read.Query < QueryHealthFailure0 || read.Query > QueryCPU {
			e.Fail(Malformed)
			return false
		}
		n.QueryKinds |= 1 << (read.Query - 1)
	default:
		e.Fail(Malformed)
		return false
	}
	n.Reads[n.ReadCount] = read
	n.ReadCount++
	return true
}
