// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"errors"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxTimeLocations              = 128
	maxOriginZoneBytes            = 512
	unixToInternalSeconds   int64 = 62135596800
	SupportedClockToolchain       = "go1.25.12"
)

// TimeDomain distinguishes Go's saturating elapsed-time operations from
// Prometheus sample millisecond subtraction and conversion, which both wrap.
type TimeDomain uint8

const (
	GoTimeDomain TimeDomain = iota + 1
	SampleTimeDomain
)

// GoTimeValue preserves raw time.Time cache identity as well as its instant.
// Monotonic is relative to the single captured startup origin, never UnixNano.
// It is zero when HasMonotonic is false. Location is an owner-local identity.
type GoTimeValue struct {
	Domain       TimeDomain
	Seconds      int64
	Nanoseconds  uint32
	Location     uint64
	HasMonotonic bool
	Monotonic    int64
}

// SampleTimeValue retains the original signed millisecond representation.
// Neither its subtraction nor its conversion to a duration saturates.
type SampleTimeValue struct {
	Domain       TimeDomain
	Milliseconds int64
}

// ClockOriginValue is transmitted once for the observation process. The raw
// monotonic baseline permits independent Go Add overflow/stripping semantics.
type ClockOriginValue struct {
	Seconds         int64
	Nanoseconds     uint32
	HasMonotonic    bool
	MonotonicBase   int64
	BaselinePresent bool
	GoVersion       string
}

// ClockOrigin retains one already captured startup value. Construction reads
// no clock; the factory supplies its startup origin and a second startup-only
// sample for exact self-validation. Both precede native policy initialization.
type ClockOrigin struct {
	time  time.Time
	value ClockOriginValue
}

func hasMonotonic(t time.Time) bool { return t != t.Round(0) }

// CaptureClockOrigin projects one value using the pinned Go String monotonic
// suffix. Formatting occurs only here, after bounding its variable zone name;
// per-evaluation projection never formats, reads a clock or accesses internals.
func CaptureClockOrigin(t, verification time.Time) (*ClockOrigin, error) {
	return captureClockOrigin(t, verification, runtime.Version())
}

func captureClockOrigin(t, verification time.Time, version string) (*ClockOrigin, error) {
	if version != SupportedClockToolchain {
		return nil, errors.New("unsupported observation Go clock toolchain")
	}
	value := ClockOriginValue{Seconds: t.Unix() + unixToInternalSeconds,
		Nanoseconds: uint32(t.Nanosecond()), HasMonotonic: hasMonotonic(t), GoVersion: version}
	if value.HasMonotonic != hasMonotonic(verification) {
		return nil, errors.New("inconsistent observation startup clock domains")
	}
	if value.HasMonotonic {
		zone, _ := t.Zone()
		checkZone, _ := verification.Zone()
		if len(zone) > maxOriginZoneBytes || len(checkZone) > maxOriginZoneBytes {
			return nil, errors.New("observation startup time zone exceeds bound")
		}
		var ok bool
		value.MonotonicBase, ok = monotonicSuffix(t.String())
		if !ok {
			return nil, errors.New("unsupported observation startup monotonic representation")
		}
		checkBase, ok := monotonicSuffix(verification.String())
		if !ok || !originConsistent(value.MonotonicBase, checkBase, int64(verification.Sub(t))) {
			return nil, errors.New("observation startup monotonic self-check failed")
		}
		value.BaselinePresent = true
	}
	return &ClockOrigin{time: t, value: value}, nil
}

func originConsistent(base, check, elapsed int64) bool {
	delta := check - base
	if (check > base && delta < 0) || (check < base && delta > 0) ||
		elapsed == math.MinInt64 || elapsed == math.MaxInt64 {
		return false
	}
	return delta == elapsed
}

func (o *ClockOrigin) Value() ClockOriginValue { return o.value }

func monotonicSuffix(value string) (int64, bool) {
	index := strings.LastIndex(value, " m=")
	if index < 0 {
		return 0, false
	}
	suffix := value[index+3:]
	if len(suffix) < 12 || (suffix[0] != '+' && suffix[0] != '-') {
		return 0, false
	}
	seconds, nanos, ok := strings.Cut(suffix[1:], ".")
	if !ok || len(seconds) == 0 || len(nanos) != 9 {
		return 0, false
	}
	for _, digits := range []string{seconds, nanos} {
		for i := range len(digits) {
			if digits[i] < '0' || digits[i] > '9' {
				return 0, false
			}
		}
	}
	s, err := strconv.ParseUint(seconds, 10, 64)
	if err != nil || s > uint64(math.MaxInt64)/1_000_000_000 {
		return 0, false
	}
	n, err := strconv.ParseUint(nanos, 10, 32)
	if err != nil {
		return 0, false
	}
	magnitude := s*1_000_000_000 + n
	limit := uint64(math.MaxInt64)
	if suffix[0] == '-' {
		limit++
	}
	if magnitude > limit {
		return 0, false
	}
	if suffix[0] == '-' {
		return -int64(magnitude), true
	}
	return int64(magnitude), true
}

type timeLocation struct {
	location *time.Location
	identity uint64
}

// TimeProjection is constructed for one observation owner before native policy
// initialization. Its fixed dictionary retains pointer identities for the whole
// epoch, including locations no longer present in a factor's cache.
type TimeProjection struct {
	owner     *Owner
	origin    *ClockOrigin
	mu        sync.Mutex
	locations [MaxTimeLocations]timeLocation
	count     int
}

func NewTimeProjection(owner *Owner, origin *ClockOrigin) *TimeProjection {
	if !owner.Enabled() {
		return nil
	}
	if origin == nil {
		owner.Invalidate(Malformed)
		return nil
	}
	return &TimeProjection{owner: owner, origin: origin}
}

// Project copies only the supplied value. Failure invalidates the Go owner
// immediately; it cannot be serialized as a qualified or missing clock read.
func (p *TimeProjection) Project(t time.Time) (GoTimeValue, bool) {
	if p == nil || !p.owner.Enabled() {
		return GoTimeValue{}, false
	}
	value := GoTimeValue{Domain: GoTimeDomain, Seconds: t.Unix() + unixToInternalSeconds,
		Nanoseconds: uint32(t.Nanosecond()), HasMonotonic: hasMonotonic(t)}
	if value.HasMonotonic {
		if !p.origin.value.HasMonotonic {
			p.owner.Invalidate(Malformed)
			return GoTimeValue{}, false
		}
		delta := int64(t.Sub(p.origin.time))
		// The endpoints cannot distinguish an exact value from Sub saturation.
		// Unsupported projection loses evidence, never changes Go arithmetic.
		if delta == math.MinInt64 || delta == math.MaxInt64 {
			p.owner.Invalidate(Malformed)
			return GoTimeValue{}, false
		}
		base := p.origin.value.MonotonicBase
		if (delta > 0 && base > math.MaxInt64-delta) || (delta < 0 && base < math.MinInt64-delta) {
			p.owner.Invalidate(Malformed)
			return GoTimeValue{}, false
		}
		value.Monotonic = delta
	}
	// This lock precedes only the owner leaf's identity allocation. Publication
	// never takes it, so it is never acquired while holding the owner leaf lock.
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.owner.Enabled() {
		return GoTimeValue{}, false
	}
	location := t.Location()
	for _, entry := range p.locations[:p.count] {
		if entry.location == location {
			value.Location = entry.identity
			return value, true
		}
	}
	if p.count == MaxTimeLocations {
		p.owner.Invalidate(Capacity)
		return GoTimeValue{}, false
	}
	identity := p.owner.NextIdentity()
	if identity == 0 {
		return GoTimeValue{}, false
	}
	p.locations[p.count] = timeLocation{location: location, identity: identity}
	p.count++
	value.Location = identity
	return value, true
}

func ProjectSampleTime(milliseconds int64) SampleTimeValue {
	return SampleTimeValue{Domain: SampleTimeDomain, Milliseconds: milliseconds}
}

// TimeProjection is allocated once per owner at its factory boundary.
func (o *Owner) TimeProjection() *TimeProjection {
	if o == nil {
		return nil
	}
	return o.timeProjection
}
