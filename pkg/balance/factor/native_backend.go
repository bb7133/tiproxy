// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
)

func (b scoredBackend) observationBackend() (*observation.Evaluation, *observation.NativeBackend) {
	c := b.capture
	if !c.enabled() || c.current == nil {
		return nil, nil
	}
	e := c.current
	if b.captureIndex < 0 || b.captureIndex >= int(e.Native().BackendCount) {
		e.Fail(observation.Malformed)
		return nil, nil
	}
	return e, &e.Native().Backends[b.captureIndex]
}

func captureBackendText(e *observation.Evaluation, seen bool, ref *observation.DataRef, value string) {
	if seen {
		if string(e.Range(*ref)) != value {
			e.Fail(observation.Malformed)
		}
	} else {
		*ref = e.CopyText(value)
	}
}

func (b scoredBackend) ID() string {
	value := b.BackendCtx.ID()
	if e, n := b.observationBackend(); n != nil {
		captureBackendText(e, n.Seen&observation.BackendID != 0, &n.ID, value)
		n.Seen |= observation.BackendID
	}
	return value
}
func (b scoredBackend) Addr() string {
	value := b.BackendCtx.Addr()
	if e, n := b.observationBackend(); n != nil {
		captureBackendText(e, n.Seen&observation.BackendAddr != 0, &n.Addr, value)
		n.Seen |= observation.BackendAddr
	}
	return value
}
func (b scoredBackend) Keyspace() string {
	value := b.BackendCtx.Keyspace()
	if e, n := b.observationBackend(); n != nil {
		captureBackendText(e, n.Seen&observation.BackendKeyspace != 0, &n.Keyspace, value)
		n.Seen |= observation.BackendKeyspace
	}
	return value
}
func (b scoredBackend) ConnCount() int {
	value := b.BackendCtx.ConnCount()
	if e, n := b.observationBackend(); n != nil {
		if n.Seen&observation.BackendConnCount != 0 && n.ConnCount != int64(value) {
			e.Fail(observation.Malformed)
		}
		n.ConnCount = int64(value)
		n.Seen |= observation.BackendConnCount
	}
	return value
}
func (b scoredBackend) ConnScore() int {
	value := b.BackendCtx.ConnScore()
	if e, n := b.observationBackend(); n != nil {
		if n.Seen&observation.BackendConnScore != 0 && n.ConnScore != int64(value) {
			e.Fail(observation.Malformed)
		}
		n.ConnScore = int64(value)
		n.Seen |= observation.BackendConnScore
	}
	return value
}
func (b scoredBackend) Healthy() bool {
	value := b.BackendCtx.Healthy()
	if e, n := b.observationBackend(); n != nil {
		if n.Seen&observation.BackendHealthy != 0 && n.Healthy != value {
			e.Fail(observation.Malformed)
		}
		n.Healthy = value
		n.Seen |= observation.BackendHealthy
	}
	return value
}
func (b scoredBackend) Local() bool {
	value := b.BackendCtx.Local()
	if e, n := b.observationBackend(); n != nil {
		if n.Seen&observation.BackendLocal != 0 && n.Local != value {
			e.Fail(observation.Malformed)
		}
		n.Local = value
		n.Seen |= observation.BackendLocal
	}
	return value
}
func (b scoredBackend) GetBackendInfo() observer.BackendInfo {
	value := b.BackendCtx.GetBackendInfo()
	if e, n := b.observationBackend(); n != nil {
		seen := n.Seen&observation.BackendInfo != 0
		captureBackendText(e, seen, &n.IP, value.IP)
		captureBackendText(e, seen, &n.Cluster, value.ClusterName)
		// Only the actually configured label is allowlisted; logging's arbitrary
		// label map is neither retained nor copied to the diagnostic stream.
		key := string(e.Range(e.Native().Configuration.LabelName))
		var label string
		var present bool
		if key != "" {
			label, present = value.Labels[key]
		}
		captureBackendText(e, seen, &n.Label, label)
		if seen && (n.StatusPort != value.StatusPort || n.LabelPresent != present) {
			e.Fail(observation.Malformed)
		}
		n.StatusPort, n.LabelPresent = value.StatusPort, present
		n.Seen |= observation.BackendInfo
	}
	return value
}
