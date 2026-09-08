// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "routing-shadow-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	return filepath.Join(dir, "observe.sock")
}
func dial(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func receive(t *testing.T, conn *net.UnixConn) map[string]any {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	var prefix [4]byte
	_, err := io.ReadFull(conn, prefix[:])
	require.NoError(t, err)
	size := binary.BigEndian.Uint32(prefix[:])
	require.LessOrEqual(t, size, uint32(observation.MaxFrameBytes))
	frame := make([]byte, 4+size)
	copy(frame, prefix[:])
	_, err = io.ReadFull(conn, frame[4:])
	require.NoError(t, err)
	require.NoError(t, ValidateFrame(frame))
	var object map[string]any
	require.NoError(t, json.Unmarshal(frame[4:], &object))
	return object
}
func TestServiceDelayedConsumerAndReconnect(t *testing.T) {
	path := socketPath(t)
	s, err := Start(context.Background(), path, zap.NewNop())
	require.NoError(t, err)
	defer s.Close()
	owner := s.Recorder().NewOwner()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	conn := dial(t, path)
	uid, err := transport.PeerUID(conn)
	require.NoError(t, err)
	require.EqualValues(t, os.Geteuid(), uid)
	require.Equal(t, "coverage", receive(t, conn)["kind"])
	first := receive(t, conn)
	require.Equal(t, "batch", first["kind"])
	require.Equal(t, "1", first["sequence"])
	duplicate := dial(t, path)
	require.NoError(t, duplicate.SetReadDeadline(time.Now().Add(time.Second)))
	var b [1]byte
	_, err = duplicate.Read(b[:])
	require.Error(t, err)
	// Any reverse traffic is forbidden; there are no observer commands or ACKs.
	_, err = conn.Write([]byte{1})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return !owner.Enabled() }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.active == nil }, time.Second, time.Millisecond)
	next := dial(t, path)
	require.Equal(t, "coverage", receive(t, next)["kind"])
	invalid := receive(t, next)
	require.Equal(t, "invalid", invalid["kind"])
	require.Equal(t, "1", invalid["owner"])
	fresh := s.Recorder().NewOwner()
	require.NotEqual(t, owner.Epoch(), fresh.Epoch())
	begin := receive(t, next)
	require.Equal(t, "batch", begin["kind"])
	require.Equal(t, "2", begin["owner"])
	require.Equal(t, "1", begin["sequence"])
	s.Close()
	count, bytes := s.Recorder().Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
	_, err = os.Lstat(path)
	require.True(t, os.IsNotExist(err))
}
func TestServiceFullQueueInvalidNoticeAndBoundedClose(t *testing.T) {
	path := socketPath(t)
	s, err := start(context.Background(), path, zap.NewNop(), observation.Limits{Owners: 2, Records: 1, Bytes: observation.BatchCharge})
	require.NoError(t, err)
	defer s.Close()
	owner := s.Recorder().NewOwner()
	require.False(t, owner.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Watermark}}}))
	count, bytes := s.Recorder().Retained()
	require.EqualValues(t, 1, count)
	require.EqualValues(t, observation.BatchCharge, bytes)
	conn := dial(t, path)
	require.Equal(t, "coverage", receive(t, conn)["kind"])
	invalid := receive(t, conn)
	require.Equal(t, "invalid", invalid["kind"])
	require.Equal(t, "capacity", invalid["reason"])
	require.Equal(t, "1", invalid["last_admitted"])
	s.Close()
	count, bytes = s.Recorder().Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
}
func TestServiceRejectsExistingOrPublicPaths(t *testing.T) {
	path := socketPath(t)
	require.NoError(t, os.WriteFile(path, []byte("keep"), 0600))
	_, err := Start(context.Background(), path, zap.NewNop())
	require.Error(t, err)
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "keep", string(value))
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Chmod(filepath.Dir(path), 0755))
	_, err = Start(context.Background(), path, zap.NewNop())
	require.ErrorContains(t, err, "private")
}

func TestServiceSlowReaderTimesOutAndRetainsWriterBudget(t *testing.T) {
	path := socketPath(t)
	s, err := Start(context.Background(), path, zap.NewNop())
	require.NoError(t, err)
	defer s.Close()
	owner := s.Recorder().NewOwner()
	conn := dial(t, path)
	require.NoError(t, conn.SetReadBuffer(1024))
	require.Equal(t, "coverage", receive(t, conn)["kind"])
	require.Equal(t, "batch", receive(t, conn)["kind"])
	s.mu.Lock()
	require.NotNil(t, s.active)
	require.NoError(t, s.active.SetWriteBuffer(1024))
	s.mu.Unlock()
	// Enough to block the writer, well below admission capacity. No more client
	// reads occur; write timeout, rather than record overflow, ends the interval.
	for range 100 {
		require.True(t, owner.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Watermark}}}))
	}
	require.Eventually(t, func() bool { return !owner.Enabled() }, 2*time.Second, time.Millisecond)
	summaries := s.Recorder().InvalidOwners()
	require.Len(t, summaries, 1)
	require.Equal(t, observation.TransportLost, summaries[0].Reason)
	records, bytes := s.Recorder().Retained()
	require.LessOrEqual(t, records, int64(100))
	require.LessOrEqual(t, bytes, int64(100*observation.BatchCharge))
	s.Close()
	records, bytes = s.Recorder().Retained()
	require.Zero(t, records)
	require.Zero(t, bytes)
}
