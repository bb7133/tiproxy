// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	"github.com/pingcap/tiproxy/pkg/util/versioninfo"
	"go.uber.org/zap"
)

const rustControlSocketName = "tiproxy-rust-control.sock"

func (srv *Server) startRustDataplane(
	ctx context.Context,
	cfg *config.Config,
	handshake backend.HandshakeHandler,
	logger *zap.Logger,
) error {
	socketPath := cfg.RustDataplane.ControlSocket
	if socketPath == "" {
		var err error
		socketPath, err = filepath.Abs(filepath.Join(cfg.Workdir, "run", rustControlSocketName))
		if err != nil {
			return fmt.Errorf("resolve Rust dataplane control socket: %w", err)
		}
	}
	allowedUID := uint32(os.Getuid())
	if cfg.RustDataplane.AllowedUID >= 0 {
		allowedUID = uint32(cfg.RustDataplane.AllowedUID)
	}

	builder, err := controlbridge.NewSnapshotBuilder(cfg, cfg.RustDataplane.TLSAllowedRoots)
	if err != nil {
		return fmt.Errorf("create Rust dataplane snapshot builder: %w", err)
	}
	publisher, err := controlbridge.NewSnapshotPublisher(controlbridge.SnapshotPublisherConfig{
		Builder:              builder,
		Initial:              cfg,
		AdvertisedCapability: handshake.GetCapability().Uint32(),
		ServerVersion:        handshake.GetServerVersion(),
	})
	if err != nil {
		return err
	}

	capabilities := []uint64{
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
	}
	bridge, err := controlbridge.NewBridge(controlbridge.BridgeConfig{
		Transport: transport.ServerConfig{
			SocketPath: socketPath,
			AllowedUID: &allowedUID,
			LocalHello: &controlpb.Hello{
				Role:                     controlpb.Role_ROLE_GO_CONTROL,
				ProcessId:                "tiproxy-go-" + strconv.Itoa(os.Getpid()),
				ProcessStartedUnixMillis: uint64(time.Now().UnixMilli()),
				SupportedVersions:        []uint32{controlpb.ProtocolV1},
				Capabilities:             capabilities,
				MaxFrameBytes:            controlpb.DefaultMaxFrameBytes,
				BuildVersion:             versioninfo.TiProxyVersion,
				BuildCommit:              versioninfo.TiProxyGitHash,
			},
			RequiredCapabilities: capabilities,
		},
		Handshake: handshake,
		RouterLookup: func(namespace string) (router.Router, error) {
			ns, ok := srv.namespaceManager.GetNamespace(namespace)
			if !ok {
				return nil, fmt.Errorf("namespace %q is unavailable", namespace)
			}
			return ns.GetRouter(), nil
		},
		Publisher: publisher,
	})
	if err != nil {
		return fmt.Errorf("start Rust dataplane control bridge: %w", err)
	}
	srv.controlBridge = bridge

	bridgeDone := make(chan struct{})
	srv.wg.Run(func() {
		defer close(bridgeDone)
		if err := bridge.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("Rust dataplane control bridge stopped", zap.Error(err))
		}
	}, logger)
	updates := srv.configManager.WatchConfig()
	srv.wg.Run(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-bridgeDone:
				return
			case next, ok := <-updates:
				if !ok {
					return
				}
				if err := publisher.Update(next); err != nil {
					logger.Warn("Rust dataplane snapshot candidate rejected",
						zap.Uint64("generation", publisher.Status().RejectedGeneration),
						zap.Error(err))
				}
			}
		}
	}, logger)
	return nil
}
