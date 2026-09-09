// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"encoding/binary"
	"strconv"
	"unicode/utf8"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
)

// nativeEncoder writes directly into the delivery's charged encoding arena.
// It never marshals a whole frame into an additional temporary allocation.
// The four-byte prefix is accounted in the fixed capture-header allowance.
type nativeEncoder struct {
	buffer     []byte
	used       int
	failed     bool
	evaluation *observation.Evaluation
}

func (w *nativeEncoder) raw(value []byte) {
	if w.failed {
		return
	}
	if len(value) > len(w.buffer)-w.used {
		w.failed = true
		return
	}
	copy(w.buffer[w.used:], value)
	w.used += len(value)
}
func (w *nativeEncoder) literal(value string) { w.raw([]byte(value)) }
func (w *nativeEncoder) text(value string) {
	if !utf8.ValidString(value) {
		w.failed = true
		return
	}
	w.literal(`"`)
	const hex = "0123456789abcdef"
	start := 0
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 0x20 && b != '"' && b != '\\' {
			continue
		}
		w.literal(value[start:i])
		if b == '"' || b == '\\' {
			w.raw([]byte{'\\', b})
		} else {
			w.raw([]byte{'\\', 'u', '0', '0', hex[b>>4], hex[b&15]})
		}
		start = i + 1
	}
	w.literal(value[start:])
	w.literal(`"`)
}
func (w *nativeEncoder) ref(value observation.DataRef) {
	bytes := w.evaluation.Range(value)
	if len(bytes) != int(value.Length) {
		w.failed = true
		return
	}
	w.text(string(bytes))
}
func (w *nativeEncoder) uint(value uint64) {
	var scratch [20]byte
	w.literal(`"`)
	w.raw(strconv.AppendUint(scratch[:0], value, 10))
	w.literal(`"`)
}
func (w *nativeEncoder) signed(value int64) {
	var scratch [20]byte
	w.literal(`"`)
	w.raw(strconv.AppendInt(scratch[:0], value, 10))
	w.literal(`"`)
}
func (w *nativeEncoder) small(value int64) {
	var scratch [20]byte
	w.raw(strconv.AppendInt(scratch[:0], value, 10))
}
func (w *nativeEncoder) boolean(value bool) {
	if value {
		w.literal("true")
	} else {
		w.literal("false")
	}
}
func (w *nativeEncoder) name(values []string, index int) {
	if index < 0 || index >= len(values) {
		w.failed = true
		return
	}
	w.text(values[index])
}
func (w *nativeEncoder) clock(value observation.GoTimeValue) {
	if value.Domain != observation.GoTimeDomain || value.Nanoseconds >= 1_000_000_000 || value.Location == 0 || !value.HasMonotonic && value.Monotonic != 0 {
		w.failed = true
		return
	}
	w.literal(`["go",`)
	w.signed(value.Seconds)
	w.literal(",")
	w.small(int64(value.Nanoseconds))
	w.literal(",")
	w.uint(value.Location)
	w.literal(",")
	w.boolean(value.HasMonotonic)
	w.literal(",")
	w.signed(value.Monotonic)
	w.literal("]")
}

var nativeEntryNames = []string{"", "config", "route", "routeable", "balance", "close"}
var nativeFactorNames = []string{"", "label", "status", "health", "memory", "cpu", "location", "connection"}
var nativeClockNames = []string{"", "metric_cadence", "status_snapshot", "health_expiry", "health_snapshot", "memory_snapshot", "memory_expiry", "cpu_snapshot", "cpu_expiry", "random_ticket", "prefer_idle_ticket"}
var nativeQueryNames = []string{"", "failure_pd", "total_pd", "failure_tikv", "total_tikv", "memory", "cpu"}
var nativeValueNames = []string{"", "nil", "none", "matrix", "vector", "scalar", "string"}

// EncodeEvaluation keeps v2 EncodeRecord separate. The returned frame is a
// borrowed view and must be written before releasing this exact delivery.
func EncodeEvaluation(record observation.Record) (frame []byte, err error) {
	defer func() {
		if err != nil && record.Evaluation != nil {
			record.Evaluation.Fail(observation.Malformed)
		}
	}()
	e := record.Evaluation
	if !record.Native || e == nil || record.Caller != nil || record.Batch.EventCount != 0 || record.Sequence == 0 || record.Epoch.Process == 0 || record.Epoch.Owner == 0 || record.Epoch.Nonce == 0 {
		return nil, errSchema
	}
	n := e.Native()
	buffer := e.EncodingBuffer()
	if n == nil || len(buffer) != observation.MaxEvaluationBodyBytes+4 || n.Group == 0 || n.Policy == 0 || n.Config == 0 || n.ID == 0 || n.Entry == 0 ||
		n.BackendCount > observation.MaxEvaluationAccounts || n.FactorCount > observation.MaxEvaluationFactors || n.ReadCount > observation.MaxEvaluationReads || n.ClockCount > observation.MaxEvaluationClocks || n.SampleCount > observation.MaxEvaluationSamples || n.StringBytes > observation.MaxEvaluationStringsBytes || n.AdviceCount > observation.MaxEvaluationAdvice || n.SortedCount > n.BackendCount || n.ReturnedCount > n.BackendCount {
		return nil, errSchema
	}
	w := nativeEncoder{buffer: buffer, used: 4, evaluation: e}
	w.literal(`{"version":3,"kind":"evaluation","process":`)
	w.uint(record.Epoch.Process)
	w.literal(`,"owner":`)
	w.uint(record.Epoch.Owner)
	w.literal(`,"nonce":`)
	w.uint(record.Epoch.Nonce)
	w.literal(`,"sequence":`)
	w.uint(record.Sequence)
	w.literal(`,"group":`)
	w.uint(n.Group)
	w.literal(`,"policy":`)
	w.uint(n.Policy)
	w.literal(`,"config":`)
	w.uint(n.Config)
	w.literal(`,"resource":`)
	w.uint(n.Resource)
	w.literal(`,"evaluation":`)
	w.uint(n.ID)
	w.literal(`,"entry":`)
	w.name(nativeEntryNames, int(n.Entry))
	w.literal(`,"configuration":{"balance":`)
	w.ref(n.Configuration.BalancePolicy)
	w.literal(`,"routing":`)
	w.ref(n.Configuration.RoutingPolicy)
	w.literal(`,"label":`)
	w.ref(n.Configuration.LabelName)
	w.literal(`,"self_label":`)
	w.ref(n.Configuration.SelfLabel)
	w.literal(`,"rates":[`)
	for i, rate := range n.Configuration.Rates {
		if i > 0 {
			w.literal(",")
		}
		w.uint(rate)
	}
	w.literal(`],"count_ratio":`)
	w.uint(n.Configuration.CountRatio)
	w.literal(`},"factors":[`)
	for i := 0; i < int(n.FactorCount); i++ {
		if i > 0 {
			w.literal(",")
		}
		w.literal("[")
		w.name(nativeFactorNames, int(n.Factors[i]))
		w.literal(",")
		w.small(int64(n.Widths[i]))
		w.literal("]")
	}
	w.literal(`],"accounts":[`)
	for i, account := range n.Backends[:n.BackendCount] {
		if i > 0 {
			w.literal(",")
		}
		w.account(account, n.FactorCount)
	}
	w.literal(`],"reads":[`)
	for i, read := range n.Reads[:n.ReadCount] {
		if i > 0 {
			w.literal(",")
		}
		w.read(read)
	}
	w.literal(`],"sorted":`)
	w.indices(n.Sorted[:n.SortedCount], n.BackendCount)
	w.literal(`,"advice":[`)
	for i, advice := range n.Advice[:n.AdviceCount] {
		if i > 0 {
			w.literal(",")
		}
		if uint16(advice.From) >= n.BackendCount || uint16(advice.To) >= n.BackendCount || advice.Advice < 0 || advice.Advice > 2 {
			w.failed = true
		}
		w.literal("[")
		w.name(nativeFactorNames, int(advice.Factor))
		w.literal(",")
		w.small(int64(advice.From))
		w.literal(",")
		w.small(int64(advice.To))
		w.literal(",")
		w.small(int64(advice.Advice))
		w.literal(",")
		w.uint(advice.Count)
		w.literal("]")
	}
	w.literal(`],"returned":`)
	w.indices(n.Returned[:n.ReturnedCount], n.BackendCount)
	if n.From < -1 || n.To < -1 || n.From >= int16(n.BackendCount) || n.To >= int16(n.BackendCount) {
		w.failed = true
	}
	w.literal(`,"from":`)
	w.small(int64(n.From))
	w.literal(`,"to":`)
	w.small(int64(n.To))
	w.literal(`,"balance_count":`)
	w.uint(n.BalanceCount)
	w.literal(`,"reason":`)
	w.name(nativeFactorNames, int(n.Reason))
	w.literal("}")
	if w.failed {
		e.Fail(observation.Capacity)
		return nil, errSchema
	}
	binary.BigEndian.PutUint32(buffer[:4], uint32(w.used-4))
	return buffer[:w.used:w.used], nil
}

func (w *nativeEncoder) indices(indices []uint8, count uint16) {
	w.literal("[")
	for i, index := range indices {
		if i > 0 {
			w.literal(",")
		}
		if uint16(index) >= count {
			w.failed = true
		}
		w.small(int64(index))
	}
	w.literal("]")
}
func (w *nativeEncoder) account(a observation.NativeBackend, factors uint8) {
	if a.Account == 0 {
		w.failed = true
	}
	w.literal(`{"account":`)
	w.uint(a.Account)
	w.literal(`,"seen":`)
	w.small(int64(a.Seen))
	w.literal(`,"id":`)
	w.ref(a.ID)
	w.literal(`,"addr":`)
	w.ref(a.Addr)
	w.literal(`,"keyspace":`)
	w.ref(a.Keyspace)
	w.literal(`,"ip":`)
	w.ref(a.IP)
	w.literal(`,"cluster":`)
	w.ref(a.Cluster)
	w.literal(`,"label":`)
	w.ref(a.Label)
	w.literal(`,"label_present":`)
	w.boolean(a.LabelPresent)
	w.literal(`,"status_port":`)
	w.uint(uint64(a.StatusPort))
	w.literal(`,"physical":`)
	w.signed(a.ConnCount)
	w.literal(`,"score_count":`)
	w.signed(a.ConnScore)
	w.literal(`,"healthy":`)
	w.boolean(a.Healthy)
	w.literal(`,"local":`)
	w.boolean(a.Local)
	w.literal(`,"parts":[`)
	for i, part := range a.Parts[:factors] {
		if i > 0 {
			w.literal(",")
		}
		w.uint(part)
	}
	w.literal(`],"packed":`)
	w.uint(a.Packed)
	w.literal(`,"routeable":`)
	w.boolean(a.Routeable)
	w.literal(`,"routeability_seen":`)
	w.boolean(a.RouteabilitySeen)
	w.literal("}")
}
func (w *nativeEncoder) read(r observation.NativeRead) {
	switch r.Kind {
	case observation.ReadClock:
		w.literal(`{"kind":"clock","site":`)
		w.name(nativeClockNames, int(r.Site))
		w.literal(`,"ordinal":`)
		w.small(int64(r.Ordinal))
		w.literal(`,"time":`)
		w.clock(r.Time)
		w.literal("}")
	case observation.ReadQuery:
		w.literal(`{"kind":"query","query":`)
		w.name(nativeQueryNames, int(r.Query))
		w.literal(`,"time":`)
		w.clock(r.Time)
		p := r.Provenance
		w.literal(`,"provenance":{"cluster":`)
		w.uint(p.Cluster)
		w.literal(`,"generation":`)
		w.uint(p.SourceGeneration)
		w.literal(`,"source":`)
		w.small(int64(p.Source))
		w.literal(`,"producer":`)
		w.uint(p.Producer)
		w.literal(`,"registration":`)
		w.uint(p.Registration)
		w.literal(`,"publication":`)
		w.uint(p.Publication)
		w.literal(`,"read_registration":`)
		w.uint(p.ReadRegistration)
		w.literal(`},"value_kind":`)
		w.name(nativeValueNames, int(r.ValueKind))
		w.literal(`,"typed_nil":`)
		w.boolean(r.TypedNil)
		w.literal(`,"empty":`)
		w.boolean(r.Empty)
		w.literal(`,"series":`)
		series := w.evaluation.Range(r.Series)
		if len(series) != int(r.Series.Length) || len(series) == 0 {
			w.failed = true
		}
		w.raw(series)
		w.literal("}")
	default:
		w.failed = true
	}
}

// EncodeNativeCoverage is owner metadata, before its Begin. Counts of exercised
// and independently compared evaluations are maintained separately by Rust.
func EncodeNativeCoverage(metadata observation.NativeMetadata) ([]byte, error) {
	origin := metadata.Origin
	if metadata.Epoch.Process == 0 || metadata.Epoch.Owner == 0 || metadata.Epoch.Nonce == 0 ||
		(metadata.GoArch != "arm64" && metadata.GoArch != "amd64") ||
		origin.GoVersion != observation.SupportedClockToolchain || origin.HasMonotonic != origin.BaselinePresent || origin.Nanoseconds >= 1_000_000_000 ||
		metadata.Zero.Domain != observation.GoTimeDomain || metadata.Zero.Location == 0 || metadata.Zero.Seconds != 0 || metadata.Zero.Nanoseconds != 0 || metadata.Zero.HasMonotonic || metadata.Zero.Monotonic != 0 {
		return nil, errSchema
	}
	var buffer [observation.BatchCharge]byte
	w := nativeEncoder{buffer: buffer[:], used: 4}
	w.literal(`{"version":3,"kind":"native_coverage","process":`)
	w.uint(metadata.Epoch.Process)
	w.literal(`,"owner":`)
	w.uint(metadata.Epoch.Owner)
	w.literal(`,"nonce":`)
	w.uint(metadata.Epoch.Nonce)
	w.literal(`,"lifecycle_only":false,"factors":true,"selection":false,"scheduler":false,"origin":{"seconds":`)
	w.signed(origin.Seconds)
	w.literal(`,"nanoseconds":`)
	w.small(int64(origin.Nanoseconds))
	w.literal(`,"has_monotonic":`)
	w.boolean(origin.HasMonotonic)
	w.literal(`,"baseline_present":`)
	w.boolean(origin.BaselinePresent)
	w.literal(`,"baseline":`)
	w.signed(origin.MonotonicBase)
	w.literal(`,"go_version":`)
	w.text(origin.GoVersion)
	w.literal(`},"go_arch":`)
	w.text(metadata.GoArch)
	w.literal(`,"zero_time":`)
	w.clock(metadata.Zero)
	w.literal("}")
	if w.failed {
		return nil, errSchema
	}
	binary.BigEndian.PutUint32(buffer[:4], uint32(w.used-4))
	return buffer[:w.used:w.used], nil
}
