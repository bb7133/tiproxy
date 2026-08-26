// Copyright 2024 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/pingcap/tiproxy/lib/util/logger"
	"github.com/pingcap/tiproxy/pkg/sctx"
	"github.com/pingcap/tiproxy/pkg/util/etcd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	restore := resetPromRegistry()
	defer restore()

	dir := t.TempDir()
	lg, _ := logger.CreateLoggerForTest(t)
	etcdServer, err := etcd.CreateEtcdServer("0.0.0.0:0", dir, lg)
	require.NoError(t, err)
	configFile := dir + "/config.toml"
	endpoint := etcdServer.Clients[0].Addr().String()
	cfg := etcd.ConfigForEtcdTest(endpoint)
	b, err := toml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configFile, b, 0o644))

	server, err := NewServer(context.Background(), &sctx.Context{
		ConfigFile: configFile,
	})
	require.NoError(t, err)
	require.NoError(t, server.Close())
	etcdServer.Close()
}

func TestServerWithoutBackendCluster(t *testing.T) {
	restore := resetPromRegistry()
	defer restore()

	dir := t.TempDir()
	configFile := dir + "/config.toml"
	require.NoError(t, os.WriteFile(configFile, []byte("[proxy]\npd-addrs = \"\"\n"), 0o644))

	server, err := NewServer(context.Background(), &sctx.Context{
		ConfigFile: configFile,
	})
	require.NoError(t, err)
	require.NoError(t, server.Close())
}

func TestRustDataplaneGateOwnsNoGoListenerAndCloses(t *testing.T) {
	restore := resetPromRegistry()
	defer restore()

	dir, err := os.MkdirTemp("", "tiproxy-rust-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	controlSocket := filepath.Join(dir, "control.sock")
	configFile := filepath.Join(dir, "config.toml")
	content := []byte("workdir = \"" + filepath.Join(dir, "work") + "\"\n" +
		"enable-traffic-replay = false\n" +
		"[rust-dataplane]\n" +
		"enabled = true\n" +
		"control-socket = \"" + controlSocket + "\"\n" +
		"allowed-uid = -1\n" +
		"[proxy]\n" +
		"pd-addrs = \"\"\n" +
		"addr = \"127.0.0.1:6000\"\n")
	require.NoError(t, os.WriteFile(configFile, content, 0o644))

	server, err := NewServer(context.Background(), &sctx.Context{ConfigFile: configFile})
	require.NoError(t, err)
	require.Nil(t, server.proxy)
	require.NotNil(t, server.controlBridge)
	_, err = os.Stat(controlSocket)
	require.NoError(t, err)

	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err = <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Rust dataplane server close did not join its config watcher")
	}
	_, err = os.Stat(controlSocket)
	require.True(t, errors.Is(err, os.ErrNotExist), "control socket survives close: %v", err)
}

func resetPromRegistry() func() {
	registry := prometheus.NewRegistry()
	oldRegisterer := prometheus.DefaultRegisterer
	oldGatherer := prometheus.DefaultGatherer
	prometheus.DefaultRegisterer = registry
	prometheus.DefaultGatherer = registry
	return func() {
		prometheus.DefaultRegisterer = oldRegisterer
		prometheus.DefaultGatherer = oldGatherer
	}
}
