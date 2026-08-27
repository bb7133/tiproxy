// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"google.golang.org/protobuf/proto"
)

// SnapshotTopologyProvider returns the topology projection included in a
// complete StateSnapshot. DPL-07 owns the production projection; keeping it an
// injected seam lets DPL-03 publish config generations without inventing a
// second namespace/topology owner.
type SnapshotTopologyProvider func() ([]*controlpb.BackendSnapshot, []*controlpb.NamespaceSnapshot)

// SnapshotPublisherConfig configures one monotonic snapshot lineage.
type SnapshotPublisherConfig struct {
	Builder              *SnapshotBuilder
	Initial              *config.Config
	AdvertisedCapability uint32
	ServerVersion        string
	Topology             SnapshotTopologyProvider
}

// SnapshotStatus is the Go-side observable generation state. LastGoodAge is
// computed when Status is called rather than frozen at the last result.
type SnapshotStatus struct {
	DesiredGeneration  uint64
	SentGeneration     uint64
	AppliedGeneration  uint64
	RejectedGeneration uint64
	LastResultCode     controlpb.ErrorCode
	Detail             string
	LastGoodAge        time.Duration
}

// SnapshotPublisher owns the desired complete snapshot, its monotonic
// generation, response correlation, and reconnect resend behavior. At most one
// snapshot is outstanding in an epoch; config changes coalesce behind it.
type SnapshotPublisher struct {
	mu sync.Mutex

	builder              *SnapshotBuilder
	advertisedCapability uint32
	serverVersion        string
	topology             SnapshotTopologyProvider
	nextGeneration       uint64
	desired              *controlpb.ControlEnvelope
	// lastConfig is the config behind the last successfully staged
	// generation; topology refreshes re-stage it with fresh topology.
	lastConfig *config.Config

	pendingEpoch      uint64
	pendingRequestID  uint64
	pendingGeneration uint64
	settledEpoch      uint64
	settledGeneration uint64
	lastGoodAt        time.Time
	status            SnapshotStatus
}

// NewSnapshotPublisher builds generation one before exposing the publisher.
// A bridge therefore never accepts a Rust peer without a complete desired
// snapshot ready to send.
func NewSnapshotPublisher(cfg SnapshotPublisherConfig) (*SnapshotPublisher, error) {
	if cfg.Builder == nil || cfg.Initial == nil {
		return nil, errors.New("snapshot publisher requires a builder and initial config")
	}
	publisher := &SnapshotPublisher{
		builder:              cfg.Builder,
		advertisedCapability: cfg.AdvertisedCapability,
		serverVersion:        cfg.ServerVersion,
		topology:             cfg.Topology,
	}
	if err := publisher.Update(cfg.Initial); err != nil {
		return nil, fmt.Errorf("build initial control snapshot: %w", err)
	}
	return publisher, nil
}

// Update validates and stages the latest complete config generation. Invalid
// candidates consume a generation and are exposed as rejected, while the
// previous desired/last-good snapshot remains available for reconnects.
func (publisher *SnapshotPublisher) Update(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("snapshot config is required")
	}
	var backends []*controlpb.BackendSnapshot
	var namespaces []*controlpb.NamespaceSnapshot
	if publisher.topology != nil {
		backends, namespaces = publisher.topology()
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	return publisher.stageLocked(cfg, backends, namespaces)
}

// stageLocked mints the next generation for cfg plus the given topology
// projection. Callers hold publisher.mu.
func (publisher *SnapshotPublisher) stageLocked(
	cfg *config.Config,
	backends []*controlpb.BackendSnapshot,
	namespaces []*controlpb.NamespaceSnapshot,
) error {
	if publisher.nextGeneration == ^uint64(0) {
		return errors.New("snapshot generation space is exhausted")
	}
	publisher.nextGeneration++
	generation := publisher.nextGeneration
	envelope, err := publisher.builder.Build(
		generation,
		cfg,
		publisher.advertisedCapability,
		publisher.serverVersion,
		backends,
		namespaces,
	)
	if err != nil {
		publisher.status.RejectedGeneration = generation
		publisher.status.Detail = truncateSnapshotDetail(err.Error())
		publisher.status.LastResultCode = controlpb.ErrorCode_ERROR_CODE_INVALID_SNAPSHOT
		if errors.Is(err, ErrListenerRestartRequired) {
			publisher.status.LastResultCode = controlpb.ErrorCode_ERROR_CODE_UNSUPPORTED_CONFIGURATION
		}
		return err
	}
	publisher.desired = envelope
	publisher.lastConfig = cfg
	publisher.status.DesiredGeneration = generation
	return nil
}

// RefreshTopology re-projects the live topology and stages a new
// generation when it differs from the desired snapshot's, so namespace
// commits and backend-health changes reach the wire without a config
// change (DPL-07). Unchanged topology stages nothing: generations only
// advance on real change.
func (publisher *SnapshotPublisher) RefreshTopology() error {
	if publisher.topology == nil {
		return nil
	}
	backends, namespaces := publisher.topology()
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if publisher.lastConfig == nil {
		return nil
	}
	if desired := publisher.desired.GetStateSnapshot(); desired != nil &&
		topologyEqual(desired.GetBackends(), backends) &&
		namespacesEqual(desired.GetNamespaces(), namespaces) {
		return nil
	}
	return publisher.stageLocked(publisher.lastConfig, backends, namespaces)
}

func topologyEqual(current, fresh []*controlpb.BackendSnapshot) bool {
	if len(current) != len(fresh) {
		return false
	}
	for index, backend := range current {
		if !proto.Equal(backend, fresh[index]) {
			return false
		}
	}
	return true
}

func namespacesEqual(current, fresh []*controlpb.NamespaceSnapshot) bool {
	if len(current) != len(fresh) {
		return false
	}
	for index, namespace := range current {
		if !proto.Equal(namespace, fresh[index]) {
			return false
		}
	}
	return true
}

// Sync sends the latest desired snapshot once per negotiated epoch and once
// per newer generation. A failed enqueue is not committed as pending, so the
// next maintenance tick retries; reconnects resend the same desired
// generation idempotently.
func (publisher *SnapshotPublisher) Sync(ctx context.Context, sender EnvelopeSender) error {
	if sender == nil {
		return nil
	}
	epoch := sender.Epoch()
	if epoch == 0 {
		return nil
	}

	publisher.mu.Lock()
	if publisher.pendingEpoch != 0 && publisher.pendingEpoch != epoch {
		publisher.clearPendingLocked()
	}
	if publisher.pendingRequestID != 0 || publisher.desired == nil ||
		(publisher.settledEpoch == epoch && publisher.settledGeneration == publisher.desired.GetGeneration()) {
		publisher.mu.Unlock()
		return nil
	}
	desired, ok := proto.Clone(publisher.desired).(*controlpb.ControlEnvelope)
	if !ok {
		publisher.mu.Unlock()
		return errors.New("clone desired control snapshot")
	}
	publisher.mu.Unlock()

	requestID, err := sender.AllocateRequestID()
	if err != nil {
		return err
	}
	desired.RequestId = requestID

	publisher.mu.Lock()
	// A concurrent result/update/sync may have changed the send decision while
	// request-id allocation was in progress. Burning an id is safe; emitting a
	// duplicate correlated request is not.
	if publisher.pendingRequestID != 0 || publisher.desired == nil ||
		publisher.desired.GetGeneration() != desired.GetGeneration() ||
		(publisher.settledEpoch == epoch && publisher.settledGeneration == desired.GetGeneration()) {
		publisher.mu.Unlock()
		return nil
	}
	publisher.pendingEpoch = epoch
	publisher.pendingRequestID = requestID
	publisher.pendingGeneration = desired.GetGeneration()
	publisher.mu.Unlock()

	if err := sender.Send(ctx, desired); err != nil {
		publisher.mu.Lock()
		if publisher.pendingEpoch == epoch && publisher.pendingRequestID == requestID {
			publisher.clearPendingLocked()
			publisher.status.Detail = truncateSnapshotDetail(err.Error())
		}
		publisher.mu.Unlock()
		return nil
	}
	publisher.mu.Lock()
	publisher.status.SentGeneration = desired.GetGeneration()
	publisher.mu.Unlock()
	return nil
}

// HandleResult applies one exactly correlated SnapshotResult. The caller
// treats a mismatch as a protocol error and tears down that control session.
func (publisher *SnapshotPublisher) HandleResult(
	sender EnvelopeSender,
	envelope *controlpb.ControlEnvelope,
) error {
	if sender == nil || envelope == nil || envelope.GetSnapshotResult() == nil {
		return errors.New("snapshot result envelope is required")
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if publisher.pendingEpoch != sender.Epoch() || publisher.pendingRequestID == 0 ||
		publisher.pendingRequestID != envelope.GetRequestId() ||
		publisher.pendingGeneration != envelope.GetGeneration() {
		return fmt.Errorf("uncorrelated snapshot result request=%d generation=%d epoch=%d",
			envelope.GetRequestId(), envelope.GetGeneration(), sender.Epoch())
	}

	result := envelope.GetSnapshotResult()
	generation := publisher.pendingGeneration
	if result.GetCode() == controlpb.ErrorCode_ERROR_CODE_OK &&
		result.GetAppliedGeneration() != generation {
		return fmt.Errorf("snapshot result applied generation %d, expected %d",
			result.GetAppliedGeneration(), generation)
	}
	publisher.settledEpoch = publisher.pendingEpoch
	publisher.settledGeneration = generation
	publisher.clearPendingLocked()
	publisher.status.LastResultCode = result.GetCode()
	publisher.status.Detail = truncateSnapshotDetail(result.GetDetail())
	if result.GetAppliedGeneration() > publisher.status.AppliedGeneration {
		publisher.status.AppliedGeneration = result.GetAppliedGeneration()
	}
	if result.GetCode() == controlpb.ErrorCode_ERROR_CODE_OK {
		publisher.lastGoodAt = time.Now()
		return nil
	}
	publisher.status.RejectedGeneration = generation
	return nil
}

// Status returns a coherent generation snapshot for APIs and diagnostics.
func (publisher *SnapshotPublisher) Status() SnapshotStatus {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	status := publisher.status
	if !publisher.lastGoodAt.IsZero() {
		status.LastGoodAge = time.Since(publisher.lastGoodAt)
	}
	return status
}

func (publisher *SnapshotPublisher) clearPendingLocked() {
	publisher.pendingEpoch = 0
	publisher.pendingRequestID = 0
	publisher.pendingGeneration = 0
}

func truncateSnapshotDetail(detail string) string {
	if len(detail) <= maxControlDetailBytes {
		return detail
	}
	return detail[:maxControlDetailBytes]
}
