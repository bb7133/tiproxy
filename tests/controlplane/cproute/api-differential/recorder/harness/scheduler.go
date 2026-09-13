// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

// Package harness composes the real proxy, router and observer for recording
// the API differential corpus (recorder README §1, §4, §5). Everything here is
// test-build only and uses public APIs plus the build-tagged ReplayDriver.
package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	replayclock "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/clock"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
)

// Recorded is one archived line: the trace v1 input fields, the public result
// fields and the consumption-time logical clock, in real order.
type Recorded struct {
	Seq     int             `json:"seq"`
	AtNanos int64           `json:"at_nanos"`
	Wall    time.Time       `json:"wall"`
	Event   apireplay.Event `json:"event"`
}

// Scheduler is the single critical section of the recorder: every input
// delivery (health, config, tick), every public router call reached through
// the overlaid proxy call site and every record happen while it is held, so
// the recorded order is the real consumption order and nothing interleaves
// between a call and its record. It also owns the logical clock.
type Scheduler struct {
	mu      sync.Mutex
	start   time.Time
	nanos   int64
	seq     int
	log     []Recorded
	archive *os.File
	observe func(apireplay.Event)
	closed  bool
	err     error
}

// Observe registers a hook invoked with every recorded event (lock held).
func (s *Scheduler) Observe(fn func(apireplay.Event)) { s.observe = fn }

// OriginNanos is the immutable Unix origin archived with the trace inputs.
func (s *Scheduler) OriginNanos() int64 { return s.start.UnixNano() }

// Seq returns the sequence number the next record will get (lock held by caller).
func (s *Scheduler) Seq() int { return s.seq }

func NewScheduler(archivePath string) (*Scheduler, error) {
	f, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	s := &Scheduler{start: time.Now(), archive: f}
	replayclock.Reset(s.start.UnixNano())
	return s, nil
}

// Serialize implements apireplay.Sink.
func (s *Scheduler) Serialize(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// Record implements apireplay.Sink; it must be called with the lock held
// (from Serialize or from Run).
func (s *Scheduler) Record(ev apireplay.Event) {
	if s.closed {
		s.err = errors.Join(s.err, fmt.Errorf("event %s after archive sealed", ev.Op))
		return
	}
	r := Recorded{Seq: s.seq, AtNanos: s.nanos, Wall: time.Now(), Event: ev}
	s.seq++
	s.log = append(s.log, r)
	if s.observe != nil {
		s.observe(ev)
	}
	if s.archive != nil {
		b, err := json.Marshal(r)
		if err == nil {
			_, err = s.archive.Write(append(b, '\n'))
		}
		if err != nil {
			s.err = errors.Join(s.err, fmt.Errorf("archive seq %d: %w", r.Seq, err))
		}
	}
}

// Run executes a declared tick at logical time `at` (nanoseconds since trace
// start) under the critical section. Only ticks move the logical clock (README
// §1: the clock is the declared timer schedule; inputs and public calls are
// stamped with the clock of the last tick that ran), and it only moves forward.
func (s *Scheduler) Run(at int64, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if at > s.nanos {
		s.nanos = at
		replayclock.Advance(at)
	}
	fn()
}

// RunNow executes an input delivery at the current logical time.
func (s *Scheduler) RunNow(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// Elapsed is the wall clock since trace start (archived only, never asserted).
func (s *Scheduler) Elapsed() time.Duration { return time.Since(s.start) }

// Now returns the current logical time.
func (s *Scheduler) Now() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nanos
}

// Log returns a copy of the recorded lines.
func (s *Scheduler) Log() []Recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Recorded, len(s.log))
	copy(out, s.log)
	return out
}

// Close seals the archive after every producer has been stopped and joined.
// It is idempotent; write, sync and close failures prevent a qualified capture.
func (s *Scheduler) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.err = errors.Join(s.err, s.archive.Sync(), s.archive.Close())
	}
	return s.err
}
