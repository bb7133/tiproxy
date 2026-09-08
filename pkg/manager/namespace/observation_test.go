// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
package namespace

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/lib/util/waitgroup"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	mconfig "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestObservedNamespaceFactoryAndRealReplacement(t *testing.T) {
	t.Run("queued_values", func(t *testing.T) { observedNamespaceReplacement(t, false) })
	t.Run("queued_old_and_new_over_socket", func(t *testing.T) { observedNamespaceReplacement(t, true) })
}
func observedNamespaceReplacement(t *testing.T, socket bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var workers waitgroup.WaitGroup
	workers.Run(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte{1, 0, 0, 0, 10})
			_ = conn.Close()
		}
	})
	defer func() { _ = listener.Close(); workers.Wait() }()
	cfgFile := filepath.Join(t.TempDir(), "tiproxy.toml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("[balance]\npolicy='connection'\n"), 0600))
	cfg := mconfig.NewConfigManager()
	require.NoError(t, cfg.Init(context.Background(), cfgFile, ""))
	defer cfg.Close()
	var recorder *observation.Recorder
	var socketPath string
	if socket {
		dir, err := os.MkdirTemp("/tmp", "namespace-observe-")
		require.NoError(t, err)
		defer os.RemoveAll(dir)
		socketPath = filepath.Join(dir, "observe.sock")
		service, err := shadowwire.Start(context.Background(), socketPath, zap.NewNop())
		require.NoError(t, err)
		defer service.Close()
		recorder = service.Recorder()
	} else {
		recorder, err = observation.NewRecorder(observation.DefaultLimits(), 41, 43)
		require.NoError(t, err)
		defer recorder.Close()
	}
	mgr := NewNamespaceManagerWithObservation(recorder)
	defer mgr.Close()
	nsConfig := &config.Namespace{Namespace: "same-name", Backend: config.BackendNamespace{Instances: []string{listener.Addr().String()}}}
	require.NoError(t, mgr.Init(zap.NewNop(), []*config.Namespace{nsConfig}, &mockTopologyFetcher{}, nil, nil, cfg, nil))
	require.Eventually(t, mgr.Ready, 5*time.Second, time.Millisecond)
	old, ok := mgr.GetNamespace("same-name")
	require.True(t, ok)
	defer old.Close()
	selector := old.router.GetBackendSelector(router.ClientInfo{})
	_, err = selector.Next()
	require.NoError(t, err)
	require.NoError(t, mgr.CommitNamespaces([]*config.Namespace{nsConfig}, nil))
	fresh, ok := mgr.GetNamespace("same-name")
	require.True(t, ok)
	require.NotSame(t, old, fresh)
	require.NotEqual(t, old.observation.Epoch(), fresh.observation.Epoch())
	require.False(t, old.observation.Enabled())
	require.True(t, fresh.observation.Enabled())
	// Replacement did not close the old production router; its pending real
	// selector still settles through the original closure, without new witnesses.
	require.Positive(t, old.router.HealthyBackendCount())
	selector.Finish(nil, false)
	selector.CloseObservation()
	require.Eventually(t, mgr.Ready, 5*time.Second, time.Millisecond)
	require.Equal(t, observation.OwnerDisappeared, recorder.InvalidOwners()[0].Reason)
	if socket {
		// Both namespace generations were captured before the delayed first peer.
		// Old invalid queued records must not masquerade as fresh contiguous input.
		assertNamespaceSocketTail(t, socketPath, old.observation.Epoch(), fresh.observation.Epoch())
	} else {
		kinds := map[uint64][]observation.Kind{}
		for count, _ := recorder.Retained(); count > 0; count, _ = recorder.Retained() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			delivery, err := recorder.Next(ctx)
			cancel()
			require.NoError(t, err)
			record := delivery.Record
			for i := uint8(0); i < record.Batch.EventCount; i++ {
				kinds[record.Epoch.Owner] = append(kinds[record.Epoch.Owner], record.Batch.Events[i].Kind)
			}
			delivery.Release()
		}
		for _, owner := range []uint64{old.observation.Epoch().Owner, fresh.observation.Epoch().Owner} {
			require.Equal(t, observation.Begin, kinds[owner][0])
			require.Equal(t, observation.GroupCreated, kinds[owner][1])
			require.Equal(t, observation.Account, kinds[owner][2])
		}
	}
	require.NoError(t, mgr.CommitNamespaces([]*config.Namespace{nsConfig}, []bool{true}))
	require.False(t, fresh.observation.Enabled())
	fresh.Close()
}

func assertNamespaceSocketTail(t *testing.T, path string, old, fresh observation.Epoch) {
	t.Helper()
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	sawInvalid, sawBegin, sawAccount := false, false, false
	for count := 0; count < 32 && !sawAccount; count++ {
		var prefix [4]byte
		_, err = io.ReadFull(peer, prefix[:])
		require.NoError(t, err)
		size := binary.BigEndian.Uint32(prefix[:])
		require.LessOrEqual(t, size, uint32(observation.MaxFrameBytes))
		frame := make([]byte, 4+size)
		copy(frame, prefix[:])
		_, err = io.ReadFull(peer, frame[4:])
		require.NoError(t, err)
		require.NoError(t, shadowwire.ValidateFrame(frame))
		var object struct {
			Kind         string
			Owner        string
			Sequence     string
			Reason       string
			LastAdmitted string `json:"last_admitted"`
			Events       []struct{ Kind string }
		}
		require.NoError(t, json.Unmarshal(frame[4:], &object))
		switch object.Kind {
		case "invalid":
			require.Equal(t, strconv.FormatUint(old.Owner, 10), object.Owner)
			require.Equal(t, "owner_disappeared", object.Reason)
			last, err := strconv.ParseUint(object.LastAdmitted, 10, 64)
			require.NoError(t, err)
			require.Positive(t, last)
			sawInvalid = true
		case "batch":
			require.Equal(t, strconv.FormatUint(fresh.Owner, 10), object.Owner, "LIVE_NAMESPACE_OLD_TAIL")
			for _, event := range object.Events {
				if event.Kind == "begin" {
					require.Equal(t, "1", object.Sequence)
					sawBegin = true
				}
				if event.Kind == "account" {
					sawAccount = true
				}
			}
		}
	}
	require.True(t, sawInvalid, "LIVE_NAMESPACE_INVALID_SUMMARY")
	require.True(t, sawBegin && sawAccount, "LIVE_NAMESPACE_FRESH_HISTORY")
}
