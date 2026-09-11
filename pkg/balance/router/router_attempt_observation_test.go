// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/require"
)

// A separate String result is consumed at each actual Group visit. A panic or
// extra read is observable; Network must never be consulted for classification.
type routerAttemptAddr struct {
	values    []string
	calls     int
	panicRead bool
}

func (*routerAttemptAddr) Network() string { panic("unused Network") }
func (a *routerAttemptAddr) String() string {
	if a == nil || a.panicRead {
		panic("original address panic")
	}
	if a.calls >= len(a.values) {
		panic("extra address read")
	}
	value := a.values[a.calls]
	a.calls++
	return value
}

type routerAttemptFixture struct {
	*metadataFixture
	attempts, begins, ends, closes, finishes int
}

func newRouterAttemptFixture(t *testing.T, rule MatchType, path string) *routerAttemptFixture {
	t.Helper()
	return &routerAttemptFixture{metadataFixture: newMetadataFixtureWithFactory(t, rule, path, newScoreBasedRouterAttemptCaptured)}
}
func (f *routerAttemptFixture) drain(t *testing.T) {
	t.Helper()
	for retained, _ := f.r.Retained(); retained > 0; retained, _ = f.r.Retained() {
		d, err := f.r.Next(context.Background())
		require.NoError(t, err)
		switch {
		case d.Record.Caller != nil:
			c := d.Record.Caller
			switch {
			case c.RouterRoute() != nil:
				f.attempts++
			case c.Selector() != nil:
				switch c.Selector().Kind {
				case observation.SelectorBegin:
					f.begins++
				case observation.SelectorEnd:
					f.ends++
				case observation.SelectorClose:
					f.closes++
				}
			case c.Finish() != nil:
				f.finishes++
			default:
				require.NotNil(t, c.Metadata(), "ROUTER_ATTEMPT_NO_ESCAPED_GROUP_CALLER")
			}
			f.write(t)(shadowwire.EncodeCaller(d.Record))
		case d.Record.Evaluation != nil:
			require.Equal(t, observation.EntryConfig, d.Record.Evaluation.Native().Entry, "ROUTER_ATTEMPT_ONLY_CONSTRUCTION_PREFIX")
			f.write(t)(shadowwire.EncodeEvaluation(d.Record))
		default:
			f.write(t)(shadowwire.EncodeRecord(d.Record))
		}
		d.Release()
	}
	require.True(t, f.o.Enabled(), "ROUTER_ATTEMPT_VALID_OWNER")
}
func (f *routerAttemptFixture) refresh(t *testing.T, backends map[string]*observer.BackendHealth, err error) {
	t.Helper()
	f.router.updateBackendHealth(observer.NewHealthResult(backends, err))
	f.drain(t)
}
func (f *routerAttemptFixture) next(t *testing.T, bs *BackendSelector, expectedErr observation.SelectorErrorClass, created bool) BackendInst {
	t.Helper()
	backend, err := bs.Next()
	require.Equal(t, expectedErr, selectorErrorClass(err), "ROUTER_ATTEMPT_ORIGINAL_ERROR")
	f.drain(t)
	if expectedErr != observation.SelectorNoError {
		require.Nil(t, backend)
		return nil
	}
	require.NotNil(t, backend)
	conn := newMockRedirectableConn(t, uint64(f.finishes+1))
	bs.Finish(conn, created)
	f.drain(t)
	if created {
		require.NoError(t, backend.(*backendWrapper).group.OnConnClosed(backend.ID(), conn))
		f.drain(t)
	}
	return backend
}
func (f *routerAttemptFixture) once(t *testing.T, client ClientInfo, expectedErr observation.SelectorErrorClass) BackendInst {
	t.Helper()
	bs := f.router.GetBackendSelector(client)
	backend := f.next(t, &bs, expectedErr, false)
	bs.CloseObservation()
	f.drain(t)
	return backend
}
func (f *routerAttemptFixture) finish(t *testing.T, counts [5]int) {
	t.Helper()
	f.r.WatermarkOwners()
	f.drain(t)
	require.Equal(t, counts, [5]int{f.attempts, f.begins, f.ends, f.closes, f.finishes}, "ROUTER_ATTEMPT_GO_POPULATION")
	require.NoError(t, f.file.Close())
	fmt.Printf("ROUTER_ATTEMPT_ACTUAL attempts=%d next=%d closes=%d finishes=%d\n", f.attempts, f.begins, f.closes, f.finishes)
}
func TestRouterAttemptActualFrames(t *testing.T) {
	dir := os.Getenv("CP_ROUTE_ROUTER_ATTEMPT_FRAMES_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	t.Run("all", func(t *testing.T) { routerAttemptAll(t, filepath.Join(dir, "all.frames")) })
	for _, rule := range []MatchType{MatchClientCIDR, MatchProxyCIDR} {
		name := "cidr"
		if rule == MatchProxyCIDR {
			name = "proxy"
		}
		t.Run(name, func(t *testing.T) { routerAttemptCIDR(t, rule, filepath.Join(dir, name+".frames")) })
	}
	t.Run("port", func(t *testing.T) { routerAttemptPort(t, filepath.Join(dir, "port.frames")) })
}
func routerAttemptAll(t *testing.T, path string) {
	f := newRouterAttemptFixture(t, MatchAll, path)
	health := map[string]*observer.BackendHealth{"a": cidrHealth("a:4000", "", true), "b": cidrHealth("b:4000", "", true)}
	f.refresh(t, health, nil)
	unused := &routerAttemptAddr{panicRead: true}
	bs := f.router.GetBackendSelector(ClientInfo{ClientAddr: unused, ProxyAddr: unused})
	a := f.next(t, &bs, observation.SelectorNoError, false)
	b := f.next(t, &bs, observation.SelectorNoError, false)
	require.NotSame(t, a, b)
	f.next(t, &bs, observation.SelectorNoError, true) // exclusions force a real second routeOnce
	bs.CloseObservation()
	f.drain(t)
	for _, err := range []error{ErrNoBackend, errors.Wrapf(ErrNoBackend, "wrapped")} {
		f.refresh(t, nil, err)
		f.once(t, ClientInfo{ClientAddr: unused}, selectorErrorClass(err))
	}
	require.Zero(t, unused.calls)
	f.finish(t, [5]int{6, 5, 5, 3, 3})
}
func routerAttemptCIDR(t *testing.T, rule MatchType, path string) {
	f := newRouterAttemptFixture(t, rule, path)
	f.refresh(t, map[string]*observer.BackendHealth{
		"a": cidrHealth("a:4000", "10.0.0.0/8", true),
		"b": cidrHealth("b:4000", "192.168.0.0/16", true),
	}, nil)
	require.Len(t, f.router.groups, 2)
	unused := &routerAttemptAddr{panicRead: true}
	client := func(addr net.Addr) ClientInfo {
		if rule == MatchClientCIDR {
			return ClientInfo{ClientAddr: addr, ProxyAddr: unused}
		}
		return ClientInfo{ClientAddr: unused, ProxyAddr: addr}
	}
	// Choose the second existing Group regardless of the original Go map order.
	second := f.router.groups[1]
	address := "10.1.2.3:1"
	if strings.HasPrefix(second.values[0], "192.") {
		address = "192.168.1.2:1"
	}
	changing := &routerAttemptAddr{values: []string{"203.0.113.1:1", address}}
	got := f.once(t, client(changing), observation.SelectorNoError)
	require.Same(t, second, got.(*backendWrapper).group, "ROUTER_ATTEMPT_PER_GROUP_STRING")
	require.Equal(t, 2, changing.calls)
	// A match at the first Group stops without consuming a second String.
	firstAddress := "10.1.2.3:1"
	if strings.HasPrefix(f.router.groups[0].values[0], "192.") {
		firstAddress = "192.168.1.2:1"
	}
	first := &routerAttemptAddr{values: []string{firstAddress}}
	f.once(t, client(first), observation.SelectorNoError)
	require.Equal(t, 1, first.calls)
	// nil, typed nil, empty, malformed and mapped IPv4 keep their original Go meaning.
	var typedNil *routerAttemptAddr
	f.once(t, client(nil), observation.SelectorExactNoBackend)
	f.once(t, client(typedNil), observation.SelectorExactNoBackend)
	for _, value := range []string{"", "bad-address"} {
		malformed := &routerAttemptAddr{values: []string{value, value}}
		f.once(t, client(malformed), observation.SelectorExactNoBackend)
		require.Equal(t, 2, malformed.calls)
	}
	mapped := &routerAttemptAddr{values: []string{"[::ffff:10.1.2.3]:1", "[::ffff:10.1.2.3]:1"}}
	f.once(t, client(mapped), observation.SelectorNoError)
	require.Zero(t, unused.calls)
	f.finish(t, [5]int{7, 7, 7, 7, 3})
}
func routerAttemptPort(t *testing.T, path string) {
	f := newRouterAttemptFixture(t, MatchPort, path)
	f.refresh(t, map[string]*observer.BackendHealth{
		"a": portHealth("a:4000", "alpha", "6000"),
		"b": portHealth("b:4000", "beta", "6000"),
		"c": portHealth("c:4000", "beta", "6001"),
	}, nil)
	unused := &routerAttemptAddr{panicRead: true}
	for _, test := range []struct {
		port string
		err  observation.SelectorErrorClass
	}{
		{"6000", observation.SelectorOtherError}, {"6001", observation.SelectorNoError},
		{"6002", observation.SelectorExactNoBackend}, {"", observation.SelectorExactNoBackend},
	} {
		f.once(t, ClientInfo{ClientAddr: unused, ProxyAddr: unused, ListenerPort: test.port}, test.err)
	}
	require.Zero(t, unused.calls)
	f.finish(t, [5]int{4, 4, 4, 4, 1})
}

func TestRouterAttemptPanicAndCapacityReleaseParent(t *testing.T) {
	for _, value := range []string{"panic", strings.Repeat("x", observation.MaxEvaluationStringBytes+1)} {
		t.Run(value[:5], func(t *testing.T) {
			f := newRouterAttemptFixture(t, MatchClientCIDR, filepath.Join(t.TempDir(), "failure.frames"))
			f.refresh(t, map[string]*observer.BackendHealth{"a": cidrHealth("a:4000", "10.0.0.0/8", true)}, nil)
			_, before := f.r.Retained()
			addr := &routerAttemptAddr{values: []string{value}, panicRead: value == "panic"}
			bs := f.router.GetBackendSelector(ClientInfo{ClientAddr: addr})
			if addr.panicRead {
				require.PanicsWithValue(t, "original address panic", func() { _, _ = bs.Next() })
			} else {
				backend, err := bs.Next()
				require.Nil(t, backend)
				require.Same(t, ErrNoBackend, err)
				require.Equal(t, 1, addr.calls)
			}
			require.False(t, f.o.Enabled(), "ROUTER_ATTEMPT_FAILURE_INVALIDATES")
			for n, _ := f.r.Retained(); n > 0; n, _ = f.r.Retained() {
				d, err := f.r.Next(context.Background())
				require.NoError(t, err)
				if d.Record.Caller != nil {
					require.Nil(t, d.Record.Caller.RouterRoute(), "ROUTER_ATTEMPT_NO_FABRICATED_RESULT")
				}
				d.Release()
			}
			_, retained := f.r.Retained()
			require.Equal(t, before, retained, "ROUTER_ATTEMPT_PARENT_RELEASED")
			f.r.Close()
			_, retained = f.r.Retained()
			require.Zero(t, retained)
		})
	}
}
