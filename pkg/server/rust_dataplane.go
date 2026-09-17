// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	mgrns "github.com/pingcap/tiproxy/pkg/manager/namespace"
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
	meteringStatePath, err := filepath.Abs(filepath.Join(
		cfg.Workdir,
		"run",
		"rust-metering-consumer.json",
	))
	if err != nil {
		return fmt.Errorf("resolve Rust metering consumer state: %w", err)
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
		// RUST_ROUTE_OWNER requires an empty bridge topology. CP-CFG/NS and
		// CP-TOPO/CP-ROUTE publish their process-local views in Rust.
		Topology: nil,
	})
	if err != nil {
		return err
	}

	capabilities := []uint64{
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_METERING_ABSOLUTE_SNAPSHOTS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RUST_CONFIG_NAMESPACE),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RUST_ROUTE_OWNER),
	}
	var meteringSink controlbridge.MeteringSink
	if srv.meter != nil {
		meteringSink = srv.meter
	}
	bridge, err := controlbridge.NewBridge(controlbridge.BridgeConfig{
		RouteOwner: true,
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
		Publisher:         publisher,
		MeteringStatePath: meteringStatePath,
		MeteringSink:      meteringSink,
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

// projectControlTopology projects the live namespaces and their
// routers' backends into the control-snapshot topology (DPL-07).
// Backends are deduplicated by id across namespaces; a namespace whose
// backends all share one cluster reports that cluster, anything else
// stays honestly empty. Routers that cannot enumerate (the static
// test router) contribute no backends.
func projectControlTopology(
	nsMgr mgrns.NamespaceManager,
) ([]*controlpb.BackendSnapshot, []*controlpb.NamespaceSnapshot) {
	namespaces := nsMgr.ListNamespaces()
	nsSnapshots := make([]*controlpb.NamespaceSnapshot, 0, len(namespaces))
	backendIndex := make(map[string]*controlpb.BackendSnapshot)
	for _, ns := range namespaces {
		var users []string
		if user := ns.User(); user != "" {
			users = []string{user}
		}
		cluster := ""
		clusters := make(map[string]struct{})
		if enumerator, ok := ns.GetRouter().(router.TopologyEnumerator); ok {
			for _, backend := range enumerator.EnumerateTopology() {
				clusters[backend.ClusterName] = struct{}{}
				if _, seen := backendIndex[backend.ID]; seen {
					continue
				}
				backendIndex[backend.ID] = &controlpb.BackendSnapshot{
					BackendId:   backend.ID,
					Address:     backend.Addr,
					ClusterName: backend.ClusterName,
					Keyspace:    backend.Keyspace,
					Healthy:     backend.Healthy,
					Local:       backend.Local,
					Cidrs:       backend.CIDRs,
					Labels:      backend.Labels,
				}
			}
		}
		if len(clusters) == 1 {
			for name := range clusters {
				cluster = name
			}
		}
		nsSnapshots = append(nsSnapshots, &controlpb.NamespaceSnapshot{
			Name:           ns.Name(),
			Users:          users,
			BackendCluster: cluster,
		})
	}
	backends := make([]*controlpb.BackendSnapshot, 0, len(backendIndex))
	for _, backend := range backendIndex {
		backends = append(backends, backend)
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].GetBackendId() < backends[j].GetBackendId() })
	return backends, nsSnapshots
}
