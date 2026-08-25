// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"google.golang.org/protobuf/proto"
)

// SnapshotBuilder translates Go-validated configuration into complete,
// deterministic Rust dataplane snapshots. It remembers listener configuration
// from startup because those fields are restart-required in the Go config.
type SnapshotBuilder struct {
	allowedTLSRoots []string
	listeners       []*controlpb.Listener
}

// NewSnapshotBuilder validates the startup listener set and TLS allowlist.
func NewSnapshotBuilder(initial *config.Config, allowedTLSRoots []string) (*SnapshotBuilder, error) {
	if initial == nil {
		return nil, fmt.Errorf("initial config is required")
	}
	listeners, err := buildListeners(initial)
	if err != nil {
		return nil, err
	}
	roots := make([]string, 0, len(allowedTLSRoots))
	for _, root := range allowedTLSRoots {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("TLS allowlist root must be absolute: %q", root)
		}
		canonical, err := filepath.EvalSymlinks(filepath.Clean(root))
		if err != nil {
			return nil, fmt.Errorf("resolve TLS allowlist root %q: %w", root, err)
		}
		metadata, err := os.Stat(canonical)
		if err != nil || !metadata.IsDir() {
			return nil, fmt.Errorf("TLS allowlist root must be a directory: %q", root)
		}
		roots = append(roots, canonical)
	}
	slices.Sort(roots)
	roots = slices.Compact(roots)
	return &SnapshotBuilder{allowedTLSRoots: roots, listeners: listeners}, nil
}

// Build creates one complete state snapshot envelope. The caller sends it
// through a negotiated control session, which fills protocol version and epoch.
func (builder *SnapshotBuilder) Build(
	generation uint64,
	cfg *config.Config,
	advertisedCapability uint32,
	serverVersion string,
	backends []*controlpb.BackendSnapshot,
	namespaces []*controlpb.NamespaceSnapshot,
) (*controlpb.ControlEnvelope, error) {
	if builder == nil {
		return nil, fmt.Errorf("snapshot builder is required")
	}
	if generation == 0 {
		return nil, fmt.Errorf("snapshot generation must be nonzero")
	}
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	normalized := cfg.Clone()
	if err := normalized.Check(); err != nil {
		return nil, fmt.Errorf("validate snapshot config: %w", err)
	}
	listeners, err := buildListeners(normalized)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(&controlpb.StateSnapshot{Config: &controlpb.ConfigSnapshot{Listeners: builder.listeners}},
		&controlpb.StateSnapshot{Config: &controlpb.ConfigSnapshot{Listeners: listeners}}) {
		return nil, fmt.Errorf("proxy.addr and proxy.port-range are restart-required")
	}

	frontendKeepalive, err := buildKeepalive("proxy.frontend-keepalive", normalized.Proxy.FrontendKeepalive)
	if err != nil {
		return nil, err
	}
	healthyKeepalive, err := buildKeepalive("proxy.backend-healthy-keepalive", normalized.Proxy.BackendHealthyKeepalive)
	if err != nil {
		return nil, err
	}
	unhealthyKeepalive, err := buildKeepalive("proxy.backend-unhealthy-keepalive", normalized.Proxy.BackendUnhealthyKeepalive)
	if err != nil {
		return nil, err
	}
	frontendTLS, err := builder.buildTLSPolicy("security.server-tls", normalized.Security.ServerSQLTLS)
	if err != nil {
		return nil, err
	}
	backendTLS, err := builder.buildTLSPolicy("security.sql-tls", normalized.Security.SQLTLS)
	if err != nil {
		return nil, err
	}
	publicCIDRs, err := normalizeCIDRs(normalized.Proxy.PublicEndpoints)
	if err != nil {
		return nil, fmt.Errorf("validate proxy.public-endpoints: %w", err)
	}
	gracefulWait, err := secondsToMillis("proxy.graceful-wait-before-shutdown", normalized.Proxy.GracefulWaitBeforeShutdown)
	if err != nil {
		return nil, err
	}
	gracefulClose, err := secondsToMillis("proxy.graceful-close-conn-timeout", normalized.Proxy.GracefulCloseConnTimeout)
	if err != nil {
		return nil, err
	}
	proxyProtocol := controlpb.ProxyProtocolMode_PROXY_PROTOCOL_MODE_DISABLED
	if normalized.Proxy.ProxyProtocol == "v2" {
		proxyProtocol = controlpb.ProxyProtocolMode_PROXY_PROTOCOL_MODE_V2
	}
	bufferSize := normalized.Proxy.ConnBufferSize
	if bufferSize == 0 {
		bufferSize = pnet.DefaultConnBufferSize
	}

	state := &controlpb.StateSnapshot{
		Config: &controlpb.ConfigSnapshot{
			MaxConnections:            normalized.Proxy.MaxConnections,
			HighMemoryRejectThreshold: normalized.Proxy.HighMemoryUsageRejectThreshold,
			ConnectionBufferBytes:     uint32(bufferSize),
			FrontendKeepalive:         frontendKeepalive,
			HealthyBackendKeepalive:   healthyKeepalive,
			UnhealthyBackendKeepalive: unhealthyKeepalive,
			ProxyProtocol:             proxyProtocol,
			RequireBackendTls:         normalized.Security.RequireBackendTLS,
			GracefulWaitMillis:        gracefulWait,
			GracefulCloseMillis:       gracefulClose,
			Listeners:                 cloneListeners(builder.listeners),
			PublicCidrs:               publicCIDRs,
			AdvertisedCapability:      advertisedCapability,
			ServerVersion:             strings.TrimSpace(serverVersion),
			FrontendTls:               frontendTLS,
			BackendTls:                backendTLS,
			TrafficReplayEnabled:      normalized.EnableTrafficReplay,
		},
		Backends:   cloneBackends(backends),
		Namespaces: cloneNamespaces(namespaces),
	}
	return &controlpb.ControlEnvelope{
		Generation: generation,
		Priority:   controlpb.Priority_PRIORITY_CONTROL,
		Body:       &controlpb.ControlEnvelope_StateSnapshot{StateSnapshot: state},
	}, nil
}

func buildListeners(cfg *config.Config) ([]*controlpb.Listener, error) {
	addrs, err := cfg.Proxy.GetSQLAddrs()
	if err != nil {
		return nil, fmt.Errorf("build SQL listeners: %w", err)
	}
	listeners := make([]*controlpb.Listener, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for index, addr := range addrs {
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("parse SQL listener %q: %w", addr, err)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid SQL listener port in %q", addr)
		}
		canonical := net.JoinHostPort(host, strconv.FormatUint(port, 10))
		if _, ok := seen[canonical]; ok {
			return nil, fmt.Errorf("duplicate SQL listener %q", canonical)
		}
		seen[canonical] = struct{}{}
		listeners = append(listeners, &controlpb.Listener{
			Address: host,
			Port:    uint32(port),
			Name:    fmt.Sprintf("sql-%d", index),
		})
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("at least one SQL listener is required")
	}
	return listeners, nil
}

func buildKeepalive(field string, keepalive config.KeepAlive) (*controlpb.KeepalivePolicy, error) {
	if keepalive.Idle < 0 || keepalive.Intvl < 0 || keepalive.Timeout < 0 || keepalive.Cnt < 0 {
		return nil, fmt.Errorf("%s values must be nonnegative", field)
	}
	if keepalive.Cnt > math.MaxUint32 {
		return nil, fmt.Errorf("%s probe count exceeds uint32", field)
	}
	idle, err := durationMillis(field+".idle", keepalive.Idle)
	if err != nil {
		return nil, err
	}
	interval, err := durationMillis(field+".intvl", keepalive.Intvl)
	if err != nil {
		return nil, err
	}
	timeout, err := durationMillis(field+".timeout", keepalive.Timeout)
	if err != nil {
		return nil, err
	}
	return &controlpb.KeepalivePolicy{
		Enabled:           keepalive.Enabled,
		IdleMillis:        idle,
		ProbeCount:        uint32(keepalive.Cnt),
		IntervalMillis:    interval,
		UserTimeoutMillis: timeout,
	}, nil
}

func durationMillis(field string, value time.Duration) (uint64, error) {
	if value > 0 && value < time.Millisecond {
		return 0, fmt.Errorf("%s must be zero or at least one millisecond", field)
	}
	return uint64(value / time.Millisecond), nil
}

func secondsToMillis(field string, value int) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s must be nonnegative", field)
	}
	seconds := uint64(value)
	if seconds > math.MaxUint64/uint64(time.Second/time.Millisecond) {
		return 0, fmt.Errorf("%s exceeds uint64 milliseconds", field)
	}
	return seconds * uint64(time.Second/time.Millisecond), nil
}

func (builder *SnapshotBuilder) buildTLSPolicy(field string, cfg config.TLSConfig) (*controlpb.TlsPolicy, error) {
	if cfg.AutoCerts {
		return nil, fmt.Errorf("%s.auto-certs is unsupported by the Rust dataplane; use shared certificate files", field)
	}
	if (cfg.Cert == "") != (cfg.Key == "") {
		return nil, fmt.Errorf("%s cert and key must be configured together", field)
	}
	if cfg.MinTLSVersion != "" && cfg.MinTLSVersion != "1.2" && cfg.MinTLSVersion != "1.3" {
		return nil, fmt.Errorf("%s minimum TLS version must be 1.2 or 1.3", field)
	}
	paths := []struct {
		name  string
		value string
	}{
		{"cert", cfg.Cert},
		{"key", cfg.Key},
		{"ca", cfg.CA},
	}
	resolved := make(map[string]string, len(paths))
	for _, path := range paths {
		if path.value == "" {
			continue
		}
		canonical, err := builder.validateTLSPath(path.value)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", field, path.name, err)
		}
		resolved[path.name] = canonical
	}
	allowedCN := make([]string, 0, len(cfg.CertAllowedCN))
	for _, name := range cfg.CertAllowedCN {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("%s cert-allowed-cn contains an empty name", field)
		}
		allowedCN = append(allowedCN, name)
	}
	slices.Sort(allowedCN)
	allowedCN = slices.Compact(allowedCN)
	return &controlpb.TlsPolicy{
		CertificatePath:    resolved["cert"],
		PrivateKeyPath:     resolved["key"],
		CaPath:             resolved["ca"],
		MinimumVersion:     cfg.MinTLSVersion,
		AllowedCommonNames: allowedCN,
		SkipCaVerification: cfg.SkipCA,
	}, nil
}

func (builder *SnapshotBuilder) validateTLSPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	for _, root := range builder.allowedTLSRoots {
		relative, err := filepath.Rel(root, canonical)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return canonical, nil
		}
	}
	return "", fmt.Errorf("path is outside configured TLS roots")
}

func normalizeCIDRs(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addrErr := netip.ParseAddr(value)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid IP or CIDR %q", value)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		result = append(result, prefix.Masked().String())
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func cloneListeners(listeners []*controlpb.Listener) []*controlpb.Listener {
	result := make([]*controlpb.Listener, 0, len(listeners))
	for _, listener := range listeners {
		if listener == nil {
			result = append(result, nil)
			continue
		}
		result = append(result, proto.Clone(listener).(*controlpb.Listener))
	}
	return result
}

func cloneBackends(backends []*controlpb.BackendSnapshot) []*controlpb.BackendSnapshot {
	result := make([]*controlpb.BackendSnapshot, 0, len(backends))
	for _, backend := range backends {
		if backend == nil {
			result = append(result, nil)
			continue
		}
		result = append(result, proto.Clone(backend).(*controlpb.BackendSnapshot))
	}
	slices.SortFunc(result, func(left, right *controlpb.BackendSnapshot) int {
		if left == nil || right == nil {
			return compareNil(left == nil, right == nil)
		}
		return strings.Compare(left.GetBackendId(), right.GetBackendId())
	})
	return result
}

func cloneNamespaces(namespaces []*controlpb.NamespaceSnapshot) []*controlpb.NamespaceSnapshot {
	result := make([]*controlpb.NamespaceSnapshot, 0, len(namespaces))
	for _, namespace := range namespaces {
		if namespace == nil {
			result = append(result, nil)
			continue
		}
		result = append(result, proto.Clone(namespace).(*controlpb.NamespaceSnapshot))
	}
	slices.SortFunc(result, func(left, right *controlpb.NamespaceSnapshot) int {
		if left == nil || right == nil {
			return compareNil(left == nil, right == nil)
		}
		return strings.Compare(left.GetName(), right.GetName())
	})
	return result
}

func compareNil(leftNil, rightNil bool) int {
	if leftNil == rightNil {
		return 0
	}
	if leftNil {
		return -1
	}
	return 1
}
