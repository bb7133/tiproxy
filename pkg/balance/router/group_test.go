// Copyright 2025 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/lib/util/logger"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var nopBpCreator = func(*zap.Logger) policy.BalancePolicy {
	return nil
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		cidrs   []string
		success bool
	}{
		{
			cidrs:   []string{"1.1.1.1"},
			success: true,
		},
		{
			cidrs:   []string{"1.1.1.1/32"},
			success: true,
		},
		{
			cidrs:   []string{"1.1.1.1/33"},
			success: false,
		},
		{
			cidrs:   []string{"1.1.1.1/31"},
			success: true,
		},
		{
			cidrs:   []string{"1.1.1.1/30", "abc"},
			success: false,
		},
	}

	lg, _ := logger.CreateLoggerForTest(t)
	for _, test := range tests {
		g, err := NewGroup(test.cidrs, nopBpCreator, MatchClientCIDR, lg)
		if test.success {
			require.NoError(t, err)
			require.Equal(t, len(test.cidrs), len(g.cidrList))
			require.EqualValues(t, test.cidrs, g.values)
		} else {
			require.Error(t, err)
		}
	}
}

func TestMatchIP(t *testing.T) {
	tests := []struct {
		ip      string
		cidrs   []string
		success bool
	}{
		{
			ip:      "1.1.1.1",
			cidrs:   []string{"1.1.1.1/32"},
			success: true,
		},
		{
			ip:      "1.1.1.2",
			cidrs:   []string{"1.1.1.1/30"},
			success: true,
		},
		{
			ip:      "1.1.1.100",
			cidrs:   []string{"1.1.1.1/30"},
			success: false,
		},
		{
			ip:      "1.1.1.100",
			cidrs:   []string{"1.1.1.1/30", "1.1.1.101/30"},
			success: true,
		},
		{
			ip:      "abc",
			cidrs:   []string{"1.1.1.1/30"},
			success: false,
		},
	}

	lg, _ := logger.CreateLoggerForTest(t)
	for _, matchType := range []MatchType{MatchClientCIDR, MatchProxyCIDR} {
		for _, test := range tests {
			g, err := NewGroup(test.cidrs, nopBpCreator, matchType, lg)
			require.NoError(t, err)
			ci := ClientInfo{}
			addr := &net.TCPAddr{IP: net.ParseIP(test.ip), Port: 10000}
			if matchType == MatchProxyCIDR {
				ci.ProxyAddr = addr
			} else {
				ci.ClientAddr = addr
			}
			require.Equal(t, test.success, g.Match(ci))
		}
	}
}

func TestRefreshCidr(t *testing.T) {
	tests := []struct {
		cidrs1    []string
		cidrs2    []string
		final     []string
		intersect bool
	}{
		{
			cidrs1:    []string{"1.1.1.1/32"},
			cidrs2:    []string{"1.1.1.1/32"},
			final:     []string{"1.1.1.1/32"},
			intersect: true,
		},
		{
			cidrs1:    []string{"1.1.1.1/32"},
			cidrs2:    []string{"1.1.1.2/32"},
			intersect: false,
		},
		{
			cidrs1:    []string{"1.1.1.1/24", "1.1.2.1/24"},
			cidrs2:    []string{"1.1.1.1/24", "1.1.2.1/24"},
			final:     []string{"1.1.1.1/24", "1.1.2.1/24"},
			intersect: true,
		},
		{
			cidrs1:    []string{"1.1.1.1/24", "1.1.2.1/24"},
			cidrs2:    []string{"1.1.1.1/24"},
			final:     []string{"1.1.1.1/24", "1.1.2.1/24"},
			intersect: true,
		},
		{
			cidrs1:    []string{"1.1.1.1/24"},
			cidrs2:    []string{"1.1.1.1/24", "1.1.2.1/24"},
			final:     []string{"1.1.1.1/24", "1.1.2.1/24"},
			intersect: true,
		},
		{
			cidrs1:    []string{"1.1.1.1/24", "1.1.2.1/24"},
			cidrs2:    []string{"1.1.1.1/24", "1.1.3.1/24"},
			final:     []string{"1.1.1.1/24", "1.1.2.1/24", "1.1.3.1/24"},
			intersect: true,
		},
	}

	lg, _ := logger.CreateLoggerForTest(t)
	for _, test := range tests {
		g1, err := NewGroup(test.cidrs1, nopBpCreator, MatchClientCIDR, lg)
		require.NoError(t, err)
		require.Equal(t, test.intersect, g1.Intersect(test.cidrs2))
		if !test.intersect {
			continue
		}

		b1, b2 := &backendWrapper{}, &backendWrapper{}
		b1.mu.BackendHealth.Labels = map[string]string{config.CidrLabelName: strings.Join(test.cidrs1, ",")}
		b2.mu.BackendHealth.Labels = map[string]string{config.CidrLabelName: strings.Join(test.cidrs2, ",")}
		g1.AddBackend("1", b1)
		g1.AddBackend("2", b2)
		g1.RefreshCidr()
		require.True(t, g1.EqualValues(test.final))
		require.Equal(t, len(g1.values), len(g1.cidrList))
	}
}

func TestFailoverBackendByAddr(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)
	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.Addr()},
				FailoverTimeout: 60,
			},
		},
	})

	require.False(t, fromBackend.Healthy())
	require.True(t, toBackend.Healthy())
	selector := tester.router.GetBackendSelector(ClientInfo{})
	backend, err := selector.Next()
	require.NoError(t, err)
	selector.Finish(nil, false)
	require.NotNil(t, backend)
	require.Equal(t, toBackend.Addr(), backend.Addr())
}

func TestIgnoreFailoverListWhenItMatchesAllHealthyBackends(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{"1", "2"},
				FailoverTimeout: 60,
			},
		},
	})
	tester.addBackends(2)

	require.True(t, tester.getBackendByIndex(0).Healthy())
	require.True(t, tester.getBackendByIndex(1).Healthy())
	require.Equal(t, 2, tester.router.HealthyBackendCount())

	selector := tester.router.GetBackendSelector(ClientInfo{})
	backend, err := selector.Next()
	require.NoError(t, err)
	selector.Finish(nil, false)
	require.NotNil(t, backend)
}

func TestIgnoreFailoverListAfterExpandingToAllHealthyBackends(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)
	tester.addConnections(20)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName()},
				FailoverTimeout: 60,
			},
		},
	})
	tester.rebalance(1)
	tester.redirectFinish(10, true)
	require.Equal(t, 0, fromBackend.ConnCount())
	require.Equal(t, 20, toBackend.ConnCount())
	require.False(t, fromBackend.Healthy())
	require.True(t, toBackend.Healthy())

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName(), toBackend.PodName()},
				FailoverTimeout: 0,
			},
		},
	})
	require.True(t, fromBackend.Healthy())
	require.True(t, toBackend.Healthy())
	require.Equal(t, 2, tester.router.HealthyBackendCount())

	tester.router.groups[0].CloseTimedOutFailoverConnections(time.Now())
	for _, conn := range tester.conns {
		require.False(t, conn.closing)
	}
}

func TestFailoverTimeoutForceClose(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(1)
	tester.addConnections(3)
	tester.addBackends(1)

	backend := tester.getBackendByIndex(0)
	tester.updateBackendRedirectSupportByAddr(backend.Addr(), false)
	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{backend.PodName()},
				FailoverTimeout: 0,
			},
		},
	})

	tester.rebalance(1)
	for _, conn := range tester.conns {
		require.True(t, conn.closing)
	}
	tester.closeConnections(3, false)
	tester.checkBackendConnMetrics()
}

// setBackendKeyspace stamps the path-parsed (authoritative) keyspace on
// an already-added backend and re-notifies health, mirroring how a
// keyspace-scoped topology reaches the router.
func setBackendKeyspace(tester *routerTester, index int, keyspace string) {
	addr := strconv.Itoa(index + 1)
	health := tester.backends[addr]
	require.NotNil(tester.t, health)
	health.BackendInfo.Keyspace = keyspace
	tester.notifyHealth()
}

// The cross-keyspace guard at the FINAL issuance boundary: a failover
// that would migrate existing sessions into a different keyspace must
// refuse every redirect (the sessions stay on the failed backend until
// failover-timeout force-close), while a same-keyspace failover keeps
// migrating. This is the DPL-07 (#41) no-keyspace-migration acceptance
// regression: it was RED before Group.redirectConn enforced the
// invariant.
func TestCrossKeyspaceFailoverRefusesRedirect(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)
	setBackendKeyspace(tester, 0, "ks-old")
	setBackendKeyspace(tester, 1, "ks-new")
	tester.addConnections(20)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)
	fromCount := fromBackend.ConnCount()
	toCount := toBackend.ConnCount()
	require.Positive(t, fromCount)

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName()},
				FailoverTimeout: 60,
			},
		},
	})
	tester.rebalance(3)

	// No redirect was issued: every connection keeps its backend and no
	// connection holds a redirect target.
	require.Equal(t, fromCount, fromBackend.ConnCount())
	require.Equal(t, toCount, toBackend.ConnCount())
	for _, conn := range tester.conns {
		require.Empty(t, conn.GetRedirectingBackendID(),
			"connection %d received a cross-keyspace redirect", conn.connID)
	}
}

// Same NON-EMPTY keyspace on both sides: the guard must not block the
// ordinary failover migration.
func TestSameKeyspaceFailoverStillRedirects(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)
	setBackendKeyspace(tester, 0, "ks-same")
	setBackendKeyspace(tester, 1, "ks-same")
	tester.addConnections(20)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)
	fromCount := fromBackend.ConnCount()
	require.Positive(t, fromCount)

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName()},
				FailoverTimeout: 60,
			},
		},
	})
	tester.rebalance(1)
	tester.redirectFinish(fromCount, true)
	require.Equal(t, 0, fromBackend.ConnCount())
	require.Equal(t, 20, toBackend.ConnCount())
}

// Legacy empty==empty keyspaces: unchanged failover behavior.
func TestEmptyKeyspaceFailoverStillRedirects(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)
	tester.addConnections(20)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)
	fromCount := fromBackend.ConnCount()
	require.Positive(t, fromCount)

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName()},
				FailoverTimeout: 60,
			},
		},
	})
	tester.rebalance(1)
	tester.redirectFinish(fromCount, true)
	require.Equal(t, 0, fromBackend.ConnCount())
	require.Equal(t, 20, toBackend.ConnCount())
}

// Empty vs non-empty is a MISMATCH: ambiguity fails closed.
func TestEmptyToNonemptyKeyspaceFailoverRefused(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)
	setBackendKeyspace(tester, 1, "ks-new")
	tester.addConnections(20)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)
	fromCount := fromBackend.ConnCount()
	toCount := toBackend.ConnCount()
	require.Positive(t, fromCount)

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName()},
				FailoverTimeout: 60,
			},
		},
	})
	tester.rebalance(3)
	require.Equal(t, fromCount, fromBackend.ConnCount())
	require.Equal(t, toCount, toBackend.ConnCount())
	for _, conn := range tester.conns {
		require.Empty(t, conn.GetRedirectingBackendID())
	}
}

// Boundedness: one cross-keyspace rebalance round refuses the WHOLE
// pair with a single counted attempt — never one warning/attempt per
// connection — and never calls conn.Redirect. Flipping the target to
// the same keyspace resumes ordinary migration.
func TestCrossKeyspaceRefusalIsBounded(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.addBackends(2)
	setBackendKeyspace(tester, 0, "ks-old")
	setBackendKeyspace(tester, 1, "ks-new")
	tester.addConnections(20)

	fromBackend := tester.getBackendByIndex(0)
	toBackend := tester.getBackendByIndex(1)
	fromCount := fromBackend.ConnCount()
	require.Positive(t, fromCount)

	tester.router.setConfig(&config.Config{
		Proxy: config.ProxyServer{
			ProxyServerOnline: config.ProxyServerOnline{
				FailBackendList: []string{fromBackend.PodName()},
				FailoverTimeout: 60,
			},
		},
	})
	tester.rebalance(3)
	group := tester.router.groups[0]
	require.Equal(t, uint64(3), group.crossKeyspaceSkipCount,
		"one counted attempt per refused round, not per connection")
	for _, conn := range tester.conns {
		require.Empty(t, conn.GetRedirectingBackendID())
	}
	require.Equal(t, fromCount, fromBackend.ConnCount())

	// Same keyspace again: migration resumes.
	setBackendKeyspace(tester, 1, "ks-old")
	tester.rebalance(1)
	tester.redirectFinish(fromCount, true)
	require.Equal(t, 0, fromBackend.ConnCount())
	require.Equal(t, 20, toBackend.ConnCount())
}
