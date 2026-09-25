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

	"github.com/gin-gonic/gin"
	"github.com/pelletier/go-toml/v2"
	"github.com/pingcap/tiproxy/lib/util/logger"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
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
	// Rust dataplane now defaults on; this test exercises the Go server path.
	b = append(b, []byte("\n[rust-dataplane]\nenabled = false\n")...)
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
	require.NoError(t, os.WriteFile(configFile, []byte("[proxy]\npd-addrs = \"\"\n[rust-dataplane]\nenabled = false\n"), 0o644))

	server, err := NewServer(context.Background(), &sctx.Context{
		ConfigFile: configFile,
	})
	require.NoError(t, err)
	require.False(t, server.configManager.GetConfig().RustDataplane.Enabled)
	namespaces, err := server.configManager.ListAllNamespace(t.Context())
	require.NoError(t, err)
	require.Len(t, namespaces, 1)
	require.Equal(t, "default", namespaces[0].Namespace,
		"the all-Go startup seed is visible through its process-local config API")
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

func TestRustRouteOwnerRejectsCustomHandshakeHandler(t *testing.T) {
	require.NoError(t, validateRustHandshakeHandler(false, true))
	require.NoError(t, validateRustHandshakeHandler(true, false))
	err := validateRustHandshakeHandler(true, true)
	require.EqualError(t, err, "custom Go handshake handler is unsupported with Rust route owner")
}

type testServerHandler struct {
	backend.HandshakeHandler
}

func (*testServerHandler) RegisterHTTP(*gin.Engine) error {
	return nil
}

func TestRustRouteOwnerRejectsCustomHandlerBeforeStartingListeners(t *testing.T) {
	restore := resetPromRegistry()
	defer restore()

	dir, err := os.MkdirTemp("", "tiproxy-rust-custom-handler-")
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

	server, err := NewServer(context.Background(), &sctx.Context{
		ConfigFile: configFile,
		Handler: &testServerHandler{
			HandshakeHandler: backend.NewStaticHandshakeHandler("127.0.0.1:4000"),
		},
	})
	require.EqualError(t, err, "custom Go handshake handler is unsupported with Rust route owner")
	require.NotNil(t, server)
	require.Nil(t, server.proxy)
	require.Nil(t, server.controlBridge)
	require.Nil(t, server.apiServer)
	_, statErr := os.Stat(controlSocket)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	require.NoError(t, server.Close())
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
