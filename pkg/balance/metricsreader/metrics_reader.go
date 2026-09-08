// Copyright 2024 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metricsreader

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/manager/infosync"
	"github.com/pingcap/tiproxy/pkg/util/http"
	"github.com/pingcap/tiproxy/pkg/util/waitgroup"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

const (
	sourceNone int32 = iota
	sourceProm
	sourceBackend
)

// PromInfoFetcher is an interface to fetch the Prometheus info from ETCD.
type PromInfoFetcher interface {
	GetPromInfo(ctx context.Context) (*infosync.PrometheusInfo, error)
}

// TopologyFetcher is an interface to fetch the tidb topology from ETCD.
type TopologyFetcher interface {
	GetTiDBTopology(ctx context.Context) (map[string]*infosync.TiDBTopologyInfo, error)
}

type MetricsQuerier interface {
	AddQueryExpr(key string, queryExpr QueryExpr, queryRule QueryRule)
	RemoveQueryExpr(key string)
	GetQueryResult(key string) QueryResult
	GetBackendMetrics() []byte
}

type MetricsReader interface {
	MetricsQuerier

	Start(ctx context.Context) error
	PreClose()
	Close()
}

var _ MetricsReader = (*ClusterReader)(nil)

// ClusterReader is the metrics reader owned by one backend cluster.
type ClusterReader struct {
	source            atomic.Pointer[sourceSelection]
	sourceMu          sync.Mutex // serializes only source writers, never spans metric reads
	identity          uint64
	observationOwners diagnosticOwners
	backendReader     *BackendReader
	promReader        *PromReader
	wg                waitgroup.WaitGroup
	cancel            context.CancelFunc
	lg                *zap.Logger
	cfg               *config.HealthCheck
}

func NewClusterReader(lg *zap.Logger, clusterName string, promFetcher PromInfoFetcher, backendFetcher TopologyFetcher, httpCli *http.Client,
	etcdCli *clientv3.Client, cfg *config.HealthCheck, cfgGetter config.ConfigGetter) *ClusterReader {
	promReader := NewPromReader(lg.Named("prom_reader"), promFetcher, cfg)
	promReader.clusterName = clusterName
	return &ClusterReader{
		identity:      nextReaderIdentity(),
		lg:            lg,
		cfg:           cfg,
		promReader:    promReader,
		backendReader: NewClusterBackendReader(lg.Named("backend_reader"), clusterName, cfgGetter, httpCli, etcdCli, backendFetcher, cfg),
	}
}

func NewDefaultMetricsReader(lg *zap.Logger, promFetcher PromInfoFetcher, backendFetcher TopologyFetcher, httpCli *http.Client,
	etcdCli *clientv3.Client, cfg *config.HealthCheck, cfgGetter config.ConfigGetter) *ClusterReader {
	return NewClusterReader(lg, config.DefaultBackendClusterName, promFetcher, backendFetcher, httpCli, etcdCli, cfg, cfgGetter)
}

func (dmr *ClusterReader) Start(ctx context.Context) error {
	if err := dmr.backendReader.Start(ctx); err != nil {
		return err
	}
	childCtx, cancel := context.WithCancel(ctx)
	dmr.cancel = cancel
	dmr.wg.RunWithRecover(func() {
		ticker := time.NewTicker(dmr.cfg.MetricsInterval)
		defer ticker.Stop()
		for childCtx.Err() == nil {
			dmr.readMetrics(childCtx)
			select {
			case <-ticker.C:
			case <-childCtx.Done():
				return
			}
		}
	}, nil, dmr.lg)
	return nil
}

// readMetrics reads from Prometheus first. If it fails, fall back to read backends.
func (dmr *ClusterReader) readMetrics(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	promErr := dmr.promReader.ReadMetrics(ctx)
	if promErr == nil {
		dmr.setSource(sourceProm, nil)
		return
	}

	if ctx.Err() != nil {
		return
	}
	backendErr := dmr.backendReader.ReadMetrics(ctx)
	if backendErr == nil {
		dmr.setSource(sourceBackend, promErr)
		return
	}
	dmr.lg.Warn("read metrics failed", zap.NamedError("prometheus", promErr), zap.NamedError("backends", backendErr))
}

func (dmr *ClusterReader) setSource(source int32, err error) {
	dmr.sourceMu.Lock()
	defer dmr.sourceMu.Unlock()
	old := dmr.source.Load()
	if old != nil && old.kind == source {
		return
	}
	generation := uint64(1)
	if old != nil {
		if old.generation == 0 || old.generation == math.MaxUint64 {
			generation = 0 // sticky diagnostic exhaustion; routing still switches
			dmr.observationOwners.invalidate(observation.SequenceExhausted)
		} else {
			generation = old.generation + 1
		}
	}
	dmr.source.Store(&sourceSelection{kind: source, generation: generation})
	switch source {
	case sourceProm:
		dmr.lg.Info("read metrics from Prometheus")
	case sourceBackend:
		dmr.lg.Info("read Prometheus failed, turn to read backends", zap.Error(err))
	}
}

func (dmr *ClusterReader) AddQueryExpr(key string, queryExpr QueryExpr, queryRule QueryRule) {
	dmr.promReader.AddQueryExpr(key, queryExpr)
	dmr.backendReader.AddQueryRule(key, queryRule)
}

func (dmr *ClusterReader) RemoveQueryExpr(key string) {
	dmr.promReader.RemoveQueryExpr(key)
	dmr.backendReader.RemoveQueryRule(key)
}

// GetQueryResult returns an empty result if the key or the result is not found.
func (dmr *ClusterReader) GetQueryResult(key string) QueryResult {
	selected := dmr.source.Load()
	return dmr.queryResultFromSelection(key, selected)
}

// Selection remains immutable while the selected reader acquires its own lock.
func (dmr *ClusterReader) queryResultFromSelection(key string, selected *sourceSelection) QueryResult {
	var result QueryResult
	if selected != nil {
		switch selected.kind {
		case sourceProm:
			result = dmr.promReader.GetQueryResult(key)
		case sourceBackend:
			result = dmr.backendReader.GetQueryResult(key)
		}
		result.Provenance.Source = selected.kind
		result.Provenance.SourceGeneration = selected.generation
	}
	if dmr.identity == 0 || selected != nil && selected.generation == 0 {
		result.Provenance.Invalid = observation.SequenceExhausted
	}
	result.Provenance.Cluster = dmr.identity
	return result
}

func (dmr *ClusterReader) GetBackendMetrics() []byte {
	return dmr.backendReader.GetBackendMetrics()
}

func (dmr *ClusterReader) PreClose() {
	// No need to update results in the graceful shutdown.
	// Stop the loop before pre-closing the backend reader to avoid data race.
	if dmr.cancel != nil {
		dmr.cancel()
		dmr.cancel = nil
	}
	dmr.wg.Wait()
	dmr.backendReader.PreClose()
}

func (dmr *ClusterReader) Close() {
	if dmr.cancel != nil {
		dmr.cancel()
		dmr.cancel = nil
	}
	dmr.wg.Wait()
	dmr.backendReader.Close()
	dmr.promReader.Close()
}
