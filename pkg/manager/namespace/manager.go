// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Ipalfish, Inc.
// SPDX-License-Identifier: Apache-2.0

package namespace

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"sync"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	mconfig "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/pingcap/tiproxy/pkg/util/http"
	"go.uber.org/zap"
)

type NamespaceManager interface {
	SetBackendNetwork(backendNetwork observer.BackendNetwork)
	Init(logger *zap.Logger, nscs []*config.Namespace, tpFetcher observer.TopologyFetcher,
		promFetcher metricsreader.PromInfoFetcher, httpCli *http.Client, cfgMgr *mconfig.ConfigManager,
		metricsReader metricsreader.MetricsQuerier) error
	CommitNamespaces(nss []*config.Namespace, nssDelete []bool) error
	GetNamespace(nm string) (*Namespace, bool)
	GetNamespaceByUser(user string) (*Namespace, bool)
	ListNamespaces() []*Namespace
	RedirectConnections() []error
	Ready() bool
	Close() error
}

type namespaceManager struct {
	sync.RWMutex
	nsm            map[string]*Namespace
	tpFetcher      observer.TopologyFetcher
	promFetcher    metricsreader.PromInfoFetcher
	metricsReader  metricsreader.MetricsQuerier
	httpCli        *http.Client
	backendNetwork observer.BackendNetwork
	logger         *zap.Logger
	cfgMgr         *mconfig.ConfigManager
}

func NewNamespaceManager() *namespaceManager {
	return &namespaceManager{}
}

func (mgr *namespaceManager) buildNamespace(cfg *config.Namespace) (*Namespace, error) {
	logger := mgr.logger.With(zap.String("namespace", cfg.Namespace))

	healthCheckCfg := config.NewDefaultHealthCheckConfig()
	dynamicFetcher := observer.NewPDFetcher(mgr.tpFetcher, logger.Named("be_fetcher"), healthCheckCfg)
	staticFetcher := observer.NewStaticFetcher(cfg.Backend.Instances)
	fetcher := observer.NewFallbackFetcher(mgr.tpFetcher, dynamicFetcher, staticFetcher)

	// init Router
	rt := router.NewScoreBasedRouter(logger.Named("router"))
	hc := observer.NewDefaultHealthCheckWithNetwork(mgr.backendNetwork, healthCheckCfg, logger.Named("hc"))
	bo := observer.NewDefaultBackendObserver(logger.Named("observer"), healthCheckCfg, fetcher, hc, mgr.cfgMgr)
	bo.Start(context.Background())
	bpCreator := func(lg *zap.Logger) policy.BalancePolicy {
		policy := factor.NewFactorBasedBalance(lg, mgr.metricsReader)
		policy.Init(mgr.cfgMgr.GetConfig())
		return policy
	}
	rt.Init(context.Background(), bo, bpCreator, mgr.cfgMgr, mgr.cfgMgr.WatchConfig())

	return &Namespace{
		name:   cfg.Namespace,
		user:   cfg.Frontend.User,
		bo:     bo,
		router: rt,
	}, nil
}

func (mgr *namespaceManager) CommitNamespaces(nss []*config.Namespace, nssDelete []bool) error {
	nsm := make(map[string]*Namespace)
	mgr.RLock()
	maps.Copy(nsm, mgr.nsm)
	mgr.RUnlock()

	for i, nsc := range nss {
		if nssDelete != nil && nssDelete[i] {
			delete(nsm, nsc.Namespace)
			continue
		}

		ns, err := mgr.buildNamespace(nsc)
		if err != nil {
			return fmt.Errorf("%w: create namespace error, namespace: %s", err, nsc.Namespace)
		}
		nsm[ns.Name()] = ns
	}

	mgr.Lock()
	mgr.nsm = nsm
	mgr.Unlock()
	return nil
}

func (mgr *namespaceManager) Init(logger *zap.Logger, nscs []*config.Namespace, tpFetcher observer.TopologyFetcher,
	promFetcher metricsreader.PromInfoFetcher, httpCli *http.Client, cfgMgr *mconfig.ConfigManager,
	metricsReader metricsreader.MetricsQuerier) error {
	mgr.Lock()
	mgr.tpFetcher = tpFetcher
	mgr.promFetcher = promFetcher
	mgr.httpCli = httpCli
	mgr.logger = logger
	mgr.cfgMgr = cfgMgr
	mgr.metricsReader = metricsReader
	mgr.Unlock()
	return mgr.CommitNamespaces(nscs, nil)
}

func (mgr *namespaceManager) SetBackendNetwork(backendNetwork observer.BackendNetwork) {
	mgr.Lock()
	mgr.backendNetwork = backendNetwork
	mgr.Unlock()
}

func (mgr *namespaceManager) GetNamespace(nm string) (*Namespace, bool) {
	mgr.RLock()
	defer mgr.RUnlock()

	ns, ok := mgr.nsm[nm]
	return ns, ok
}

func (mgr *namespaceManager) GetNamespaceByUser(user string) (*Namespace, bool) {
	mgr.RLock()
	defer mgr.RUnlock()

	for _, ns := range mgr.nsm {
		if ns.User() == user {
			return ns, true
		}
	}
	return nil, false
}

// SetNamespaceForTest installs a prebuilt namespace without building
// routers or observers; used by cross-package routing-parity tests.
func (mgr *namespaceManager) SetNamespaceForTest(ns *Namespace) {
	mgr.Lock()
	defer mgr.Unlock()
	if mgr.nsm == nil {
		mgr.nsm = make(map[string]*Namespace)
	}
	mgr.nsm[ns.Name()] = ns
}

// ListNamespaces snapshots the live namespaces in name order for the
// control-plane topology projection (DPL-07).
func (mgr *namespaceManager) ListNamespaces() []*Namespace {
	mgr.RLock()
	defer mgr.RUnlock()
	namespaces := make([]*Namespace, 0, len(mgr.nsm))
	for _, ns := range mgr.nsm {
		namespaces = append(namespaces, ns)
	}
	sort.Slice(namespaces, func(i, j int) bool { return namespaces[i].Name() < namespaces[j].Name() })
	return namespaces
}

func (mgr *namespaceManager) RedirectConnections() []error {
	mgr.RLock()
	defer mgr.RUnlock()

	var errs []error
	for _, ns := range mgr.nsm {
		err1 := ns.GetRouter().RedirectConnections()
		if err1 != nil {
			errs = append(errs, err1)
		}
	}
	return errs
}

func (mgr *namespaceManager) Ready() bool {
	mgr.RLock()
	defer mgr.RUnlock()
	if len(mgr.nsm) == 0 {
		return false
	}
	for _, ns := range mgr.nsm {
		if ns.GetRouter().HealthyBackendCount() <= 0 {
			return false
		}
	}
	return true
}

func (mgr *namespaceManager) Close() error {
	mgr.RLock()
	for _, ns := range mgr.nsm {
		ns.Close()
	}
	mgr.RUnlock()
	return nil
}
