// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	mconfig "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/pingcap/tiproxy/pkg/manager/namespace"
	http "github.com/pingcap/tiproxy/pkg/util/http"
	"go.uber.org/zap"
)

// RecordingNamespaceManager serves the single recorded namespace whose router
// is the driven ScoreBasedRouter, to the real proxy's handshake handler
// (README §5 "Composition"). Lifecycle of the observer/router is owned by the
// harness, so Init/Commit/Close are no-ops here.
type RecordingNamespaceManager struct {
	ns *namespace.Namespace
	rt router.Router
}

var _ namespace.NamespaceManager = (*RecordingNamespaceManager)(nil)

func NewRecordingNamespaceManager(rt router.Router) *RecordingNamespaceManager {
	return &RecordingNamespaceManager{ns: namespace.NewNamespaceForTest("default", "", rt), rt: rt}
}

func (m *RecordingNamespaceManager) SetBackendNetwork(observer.BackendNetwork) {}
func (m *RecordingNamespaceManager) Init(*zap.Logger, []*config.Namespace, observer.TopologyFetcher, metricsreader.PromInfoFetcher, *http.Client, *mconfig.ConfigManager, metricsreader.MetricsQuerier) error {
	return nil
}
func (m *RecordingNamespaceManager) CommitNamespaces([]*config.Namespace, []bool) error { return nil }
func (m *RecordingNamespaceManager) GetNamespace(string) (*namespace.Namespace, bool) {
	return m.ns, true
}
func (m *RecordingNamespaceManager) GetNamespaceByUser(string) (*namespace.Namespace, bool) {
	return m.ns, true
}
func (m *RecordingNamespaceManager) ListNamespaces() []*namespace.Namespace {
	return []*namespace.Namespace{m.ns}
}
func (m *RecordingNamespaceManager) RedirectConnections() []error {
	if err := m.rt.RedirectConnections(); err != nil {
		return []error{err}
	}
	return nil
}
func (m *RecordingNamespaceManager) Ready() bool  { return true }
func (m *RecordingNamespaceManager) Close() error { return nil }
