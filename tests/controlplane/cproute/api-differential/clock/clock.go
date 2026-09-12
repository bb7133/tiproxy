// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package clock supplies one public event clock to test-build overlays only.
// It has no routing state and never records individual clock reads.
package clock

import (
	"sync/atomic"
	"time"
)

// DefaultOrigin preserves the epoch of traces recorded before origin capture.
const DefaultOrigin int64 = 1_700_000_000_000_000_000

var origin, elapsed atomic.Int64

func init() { Reset(DefaultOrigin) }

// Reset is called before starting the recorder/replay producers.
func Reset(unixNanos int64) { origin.Store(unixNanos); elapsed.Store(0) }

// Advance is called by the serialized public event dispatcher.
func Advance(nanos int64) { elapsed.Store(nanos) }

// Now retains the recorded Unix origin and the current declared event offset.
func Now() time.Time { return time.Unix(0, origin.Load()).Add(time.Duration(elapsed.Load())) }
