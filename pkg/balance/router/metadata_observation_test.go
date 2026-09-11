// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// metadataFixture is a real ScoreBasedRouter with a native-captured owner whose
// health refreshes are driven directly. Every recorded frame is written raw
// (four-byte prefix included) for the Rust metadata_check example.
type metadataFixture struct {
	r      *observation.Recorder
	o      *observation.Owner
	router *ScoreBasedRouter
	file   *os.File
	frames int
}

func newMetadataFixture(t *testing.T, matchType MatchType, path string) *metadataFixture {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	nativeCreator := func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
		p := factor.NewFactorBasedBalanceObserved(lg, &nativeGroupReader{}, owner, group)
		p.Init(cfg)
		return p
	}
	router := newScoreBasedRouterMetadataCaptured(zap.NewNop(), o, nativeCreator)
	router.bpCreator = simpleBpCreator
	router.matchType = matchType
	t.Cleanup(router.Close)
	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	f := &metadataFixture{r: r, o: o, router: router, file: file}
	f.write(t)(shadowwire.EncodeCoverage(41, 43))
	metadata, ok := r.NativeMetadata(o.Epoch())
	require.True(t, ok)
	f.write(t)(shadowwire.EncodeNativeCoverage(metadata))
	return f
}

func (f *metadataFixture) write(t *testing.T) func(frame []byte, err error) {
	return func(frame []byte, err error) {
		t.Helper()
		require.NoError(t, err)
		_, err = f.file.Write(frame)
		require.NoError(t, err)
		f.frames++
	}
}

// metadataCounts is the number of frames of each kind drained.
type metadataCounts struct{ begins, assigns, refreshes, ends int }

// drain writes every retained record in order: metadata callers, construction
// evaluations and lifecycle batches all keep their real sequence.
func (f *metadataFixture) drain(t *testing.T) (counts metadataCounts) {
	t.Helper()
	for retained, _ := f.r.Retained(); retained > 0; retained, _ = f.r.Retained() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		d, err := f.r.Next(ctx)
		cancel()
		require.NoError(t, err)
		switch {
		case d.Record.Caller != nil:
			m := d.Record.Caller.Metadata()
			require.NotNil(t, m, "METADATA_ONLY_METADATA_CALLERS")
			switch m.Kind {
			case observation.MetadataBegin:
				counts.begins++
			case observation.MetadataAssign:
				counts.assigns++
			case observation.MetadataRefresh:
				counts.refreshes++
			default:
				counts.ends++
			}
			f.write(t)(shadowwire.EncodeCaller(d.Record))
		case d.Record.Evaluation != nil:
			f.write(t)(shadowwire.EncodeEvaluation(d.Record))
		default:
			f.write(t)(shadowwire.EncodeRecord(d.Record))
		}
		d.Release()
	}
	return counts
}

func cidrHealth(addr, cidr string, healthy bool) *observer.BackendHealth {
	labels := map[string]string{}
	if cidr != "" {
		labels[config.CidrLabelName] = cidr
	}
	return &observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: addr, Labels: labels}, Healthy: healthy, SupportRedirection: true}
}

func portHealth(addr, cluster, port string) *observer.BackendHealth {
	return &observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: addr, ClusterName: cluster, Labels: map[string]string{config.TiProxyPortLabelName: port}}, Healthy: true, SupportRedirection: true}
}

func (f *metadataFixture) refresh(t *testing.T, backends map[string]*observer.BackendHealth, err error) metadataCounts {
	t.Helper()
	f.router.updateBackendHealth(observer.NewHealthResult(backends, err))
	return f.drain(t)
}

// TestMetadataActualFrames drives three real routers through the refresh
// transitions the Rust tracker must derive independently and records every
// frame. The Rust example replays each file and checks its own expectations.
func TestMetadataActualFrames(t *testing.T) {
	dir := os.Getenv("CP_ROUTE_METADATA_FRAMES_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))

	// MatchAll: one group; a busy backend is kept while unhealthy and removed
	// once its connection closes; the empty group disappears with it.
	all := newMetadataFixture(t, MatchAll, filepath.Join(dir, "all.frames"))
	counts := all.refresh(t, map[string]*observer.BackendHealth{
		"a": cidrHealth("a:4000", "", true), "b": cidrHealth("b:4000", "", true),
	}, nil)
	require.Equal(t, metadataCounts{1, 2, 1, 1}, counts, "METADATA_ALL_FIRST_REFRESH")
	require.Len(t, all.router.groups, 1)
	conn, target := observedConn(t, all.router, false)
	_ = all.drain(t)
	// Unhealthy but busy: kept (Assign removed=false inside the Group lock),
	// then revisited by the ordinary group branch: three visits for two backends.
	counts = all.refresh(t, map[string]*observer.BackendHealth{
		"a": cidrHealth("a:4000", "", target.id != "a"), "b": cidrHealth("b:4000", "", target.id != "b"),
	}, nil)
	require.Equal(t, metadataCounts{1, 3, 1, 1}, counts, "METADATA_ALL_BUSY_KEPT_AND_REVISITED")
	require.Len(t, all.router.backends, 2)
	require.NoError(t, target.group.OnConnClosed(target.ID(), conn))
	_ = all.drain(t)
	// Idle now: removed; the other backend removed from the list; group empties.
	counts = all.refresh(t, map[string]*observer.BackendHealth{}, nil)
	require.Equal(t, metadataCounts{1, 2, 0, 1}, counts, "METADATA_ALL_IDLE_REMOVED")
	require.Empty(t, all.router.backends)
	require.Empty(t, all.router.groups, "METADATA_ALL_EMPTY_GROUP_REMOVED")

	// MatchClientCIDR: creation, join by raw intersection, an unhealthy backend
	// never held, a value change that keeps the group, a member with an
	// invalid CIDR that fails the refresh while the previously parsed networks
	// stay, a failed construction (GroupCreated+GroupRemoved, no group), and
	// exact / wrapped observer errors.
	cidr := newMetadataFixture(t, MatchClientCIDR, filepath.Join(dir, "cidr.frames"))
	counts = cidr.refresh(t, map[string]*observer.BackendHealth{
		"a": cidrHealth("a:4000", "10.0.0.0/8", true),
		"b": cidrHealth("b:4000", "10.0.0.0/8,192.168.0.0/16", true),
		"c": cidrHealth("c:4000", "", true),
		"d": cidrHealth("d:4000", "bad-cidr", true),
		"e": cidrHealth("e:4000", "172.16.0.0/12", false),
	}, nil)
	require.Equal(t, metadataCounts{1, 4, 1, 1}, counts, "METADATA_CIDR_FIRST_REFRESH")
	require.Len(t, cidr.router.groups, 1, "METADATA_CIDR_ONE_GROUP_BY_INTERSECTION")
	require.Nil(t, cidr.router.backends["c"].group)
	require.Nil(t, cidr.router.backends["d"].group, "METADATA_CIDR_INVALID_CONSTRUCTION_NO_GROUP")
	require.NotContains(t, cidr.router.backends, "e", "METADATA_CIDR_UNHEALTHY_NEVER_HELD")
	counts = cidr.refresh(t, map[string]*observer.BackendHealth{
		"a": cidrHealth("a:4000", "10.0.0.0/8", true),
		"b": cidrHealth("b:4000", "bad-cidr", true), // changed: kept in its group, refresh fails to parse
		"c": cidrHealth("c:4000", "", true),
		"d": cidrHealth("d:4000", "bad-cidr", true),
	}, nil)
	require.Equal(t, metadataCounts{1, 4, 1, 1}, counts)
	require.Len(t, cidr.router.groups, 1, "METADATA_CIDR_VALUE_CHANGE_KEEPS_GROUP")
	require.NotNil(t, cidr.router.backends["b"].group)
	counts = cidr.refresh(t, nil, ErrNoBackend)
	require.Equal(t, metadataCounts{1, 0, 0, 1}, counts, "METADATA_CIDR_OBSERVER_ERROR")
	counts = cidr.refresh(t, nil, errors.Wrapf(ErrNoBackend, "wrapped"))
	require.Equal(t, metadataCounts{1, 0, 0, 1}, counts, "METADATA_CIDR_WRAPPED_ERROR")

	// MatchPort: two clusters claim one listener port and conflict; a third
	// port routes to its own group. Port groups recompute no CIDR values.
	port := newMetadataFixture(t, MatchPort, filepath.Join(dir, "port.frames"))
	counts = port.refresh(t, map[string]*observer.BackendHealth{
		"a": portHealth("a:4000", "alpha", "6000"),
		"b": portHealth("b:4000", "beta", "6000"),
		"c": portHealth("c:4000", "beta", "6001"),
	}, nil)
	require.Equal(t, metadataCounts{1, 3, 3, 1}, counts, "METADATA_PORT_FIRST_REFRESH")
	require.Len(t, port.router.groups, 3)
	require.Equal(t, 1, port.router.portConflictDetector.conflictCount(), "METADATA_PORT_CONFLICT")
	require.Positive(t, all.frames+cidr.frames+port.frames)
}

// TestMetadataCaptureNeedsPrivateFactory: the public native factory emits no
// metadata frame; only the private metadata-captured factory does.
func TestMetadataCaptureNeedsPrivateFactory(t *testing.T) {
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	router := NewScoreBasedRouterWithNativeObservation(zap.NewNop(), o, nil)
	router.bpCreator = simpleBpCreator
	t.Cleanup(router.Close)
	router.updateBackendHealth(observer.NewHealthResult(map[string]*observer.BackendHealth{"a": cidrHealth("a:4000", "", true)}, nil))
	retained, _ := r.Retained()
	for range retained {
		d, err := r.Next(context.Background())
		require.NoError(t, err)
		require.Nil(t, d.Record.Caller, "METADATA_PUBLIC_FACTORY_EMITS_NO_FRAME")
		d.Release()
	}
	require.True(t, o.Enabled())
	require.Zero(t, router.metadataGeneration)
}

// TestMetadataRefreshPanicReleasesLease: a real getter panic inside
// RefreshCidr (a nil wrapper makes b.Cidr() dereference nil) unwinds through
// the Group lock with the open Refresh frame still leased; the deferred
// cleanup returns that lease, so after draining the published frames the
// recorder holds exactly what it held before the refresh, and nothing after
// Close.
func TestMetadataRefreshPanicReleasesLease(t *testing.T) {
	dir := t.TempDir()
	cidr := newMetadataFixture(t, MatchClientCIDR, filepath.Join(dir, "panic.frames"))
	counts := cidr.refresh(t, map[string]*observer.BackendHealth{
		"a": cidrHealth("a:4000", "10.0.0.0/8", true),
	}, nil)
	require.Equal(t, metadataCounts{1, 1, 1, 1}, counts)
	require.Len(t, cidr.router.groups, 1)
	_, before := cidr.r.Retained()
	// The getter panics on the second member; the first member read was
	// already copied into the open frame.
	cidr.router.groups[0].backends["nil"] = nil
	require.Panics(t, func() {
		cidr.router.updateBackendHealth(observer.NewHealthResult(map[string]*observer.BackendHealth{
			"a": cidrHealth("a:4000", "10.0.0.0/8", true),
		}, nil))
	}, "METADATA_REFRESH_GETTER_PANIC")
	delete(cidr.router.groups[0].backends, "nil")
	for retained, _ := cidr.r.Retained(); retained > 0; retained, _ = cidr.r.Retained() {
		d, err := cidr.r.Next(context.Background())
		require.NoError(t, err)
		d.Release()
	}
	_, after := cidr.r.Retained()
	require.Equal(t, before, after, "METADATA_REFRESH_PANIC_NO_LEAK")
	require.False(t, cidr.o.Enabled(), "METADATA_REFRESH_PANIC_INVALIDATES")
	cidr.r.Close()
	_, closed := cidr.r.Retained()
	require.Zero(t, closed, "METADATA_REFRESH_PANIC_ZERO_AFTER_CLOSE")
}
