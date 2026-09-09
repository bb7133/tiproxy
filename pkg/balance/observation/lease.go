// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"sync"
	"sync/atomic"
)

const (
	// EvaluationCharge covers bounded copied values and the writer's encoding
	// storage together. The v2 and future v3 paths share one recorder budget.
	EvaluationCharge = 1 << 20
)

// EvaluationLease reserves storage before capture. It grants no comparison
// credit or owner sequence. Its sole owner must release it after capture is
// discarded, or transfer it through publication to the final writer. Invalidation
// cannot reclaim a buffer that a concurrent producer/writer is still using.
// This preparation primitive does not install factor observation or v3 coverage.
type EvaluationLease struct {
	once     sync.Once
	recorder *Recorder
	storage  *evaluationStorage
	released atomic.Bool
}

// LeaseEvaluation atomically reserves one record and the full variable-size
// byte charge. The caller holds its existing Group lock; no owner leaf lock is
// retained across evaluation. Capacity failure invalidates evidence only.
func (o *Owner) LeaseEvaluation() *EvaluationLease {
	if !o.Enabled() {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		return nil
	}
	if !o.recorder.reserve(EvaluationCharge) {
		o.Invalidate(Capacity)
		return nil
	}
	return &EvaluationLease{recorder: o.recorder}
}

// Release returns both counters together, at most once. Close joins admission
// and releases queued records; outstanding capture/writer leases stay charged
// until their owners finish, including after owner invalidation.
func (l *EvaluationLease) Release() {
	if l != nil {
		l.once.Do(func() {
			l.released.Store(true)
			if l.storage != nil {
				storage := l.storage
				l.storage = nil
				l.recorder.releaseEvaluationStorage(storage)
			} else {
				l.recorder.release(EvaluationCharge)
			}
		})
	}
}
