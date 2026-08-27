// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/pingcap/tiproxy/lib/config"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type snapshotSender struct {
	mu      sync.Mutex
	epoch   uint64
	nextID  uint64
	sent    []*controlpb.ControlEnvelope
	sendErr error
}

func (sender *snapshotSender) Send(_ context.Context, envelope *controlpb.ControlEnvelope) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.sendErr != nil {
		return sender.sendErr
	}
	cloned, _ := proto.Clone(envelope).(*controlpb.ControlEnvelope)
	sender.sent = append(sender.sent, cloned)
	return nil
}

func (sender *snapshotSender) Epoch() uint64 {
	return sender.epoch
}

func (*snapshotSender) HasCapability(uint64) bool {
	return true
}

func (sender *snapshotSender) AllocateRequestID() (uint64, error) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.nextID == ^uint64(0) {
		return 0, errors.New("request ids exhausted")
	}
	sender.nextID++
	return sender.nextID, nil
}

func (sender *snapshotSender) envelopes() []*controlpb.ControlEnvelope {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return append([]*controlpb.ControlEnvelope(nil), sender.sent...)
}

func newSnapshotPublisherForTest(t *testing.T) (*SnapshotPublisher, *config.Config) {
	t.Helper()
	cfg := config.NewConfig()
	builder, err := NewSnapshotBuilder(cfg, nil)
	require.NoError(t, err)
	publisher, err := NewSnapshotPublisher(SnapshotPublisherConfig{
		Builder:              builder,
		Initial:              cfg,
		AdvertisedCapability: 123,
		ServerVersion:        "test-server",
	})
	require.NoError(t, err)
	return publisher, cfg
}

func snapshotResultEnvelope(requestID, generation, applied uint64, code controlpb.ErrorCode) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: generation,
		Body: &controlpb.ControlEnvelope_SnapshotResult{SnapshotResult: &controlpb.SnapshotResult{
			AppliedGeneration: applied,
			Code:              code,
		}},
	}
}

func TestSnapshotPublisherApplyRejectReconnectAndCoalesce(t *testing.T) {
	publisher, cfg := newSnapshotPublisherForTest(t)
	first := &snapshotSender{epoch: 7}

	require.NoError(t, publisher.Sync(t.Context(), first))
	require.NoError(t, publisher.Sync(t.Context(), first))
	sent := first.envelopes()
	require.Len(t, sent, 1, "one snapshot may be pending per epoch")
	require.Equal(t, uint64(1), sent[0].GetGeneration())
	require.Equal(t, uint64(1), sent[0].GetRequestId())
	require.Error(t, publisher.HandleResult(first,
		snapshotResultEnvelope(99, 1, 1, controlpb.ErrorCode_ERROR_CODE_OK)))
	require.NoError(t, publisher.HandleResult(first,
		snapshotResultEnvelope(1, 1, 1, controlpb.ErrorCode_ERROR_CODE_OK)))
	require.NoError(t, publisher.Sync(t.Context(), first))
	require.Len(t, first.envelopes(), 1, "settled generation is not resent in the same epoch")

	updated := cfg.Clone()
	updated.Proxy.MaxConnections = 42
	require.NoError(t, publisher.Update(updated))
	require.NoError(t, publisher.Sync(t.Context(), first))
	sent = first.envelopes()
	require.Len(t, sent, 2)
	require.Equal(t, uint64(2), sent[1].GetGeneration())
	require.NoError(t, publisher.HandleResult(first,
		snapshotResultEnvelope(2, 2, 1, controlpb.ErrorCode_ERROR_CODE_INVALID_SNAPSHOT)))
	status := publisher.Status()
	require.Equal(t, uint64(2), status.DesiredGeneration)
	require.Equal(t, uint64(1), status.AppliedGeneration)
	require.Equal(t, uint64(2), status.RejectedGeneration)

	second := &snapshotSender{epoch: 8}
	require.NoError(t, publisher.Sync(t.Context(), second))
	resent := second.envelopes()
	require.Len(t, resent, 1)
	require.Equal(t, uint64(2), resent[0].GetGeneration(), "reconnect resends latest desired generation")
	require.NoError(t, publisher.HandleResult(second,
		snapshotResultEnvelope(1, 2, 2, controlpb.ErrorCode_ERROR_CODE_OK)))
	require.Positive(t, publisher.Status().LastGoodAge)
}

func TestSnapshotPublisherPreservesDesiredAcrossBuildAndSendFailures(t *testing.T) {
	publisher, cfg := newSnapshotPublisherForTest(t)
	sender := &snapshotSender{epoch: 9, sendErr: errors.New("queue closed")}

	require.NoError(t, publisher.Sync(t.Context(), sender))
	require.Empty(t, sender.envelopes())
	sender.mu.Lock()
	sender.sendErr = nil
	sender.mu.Unlock()
	require.NoError(t, publisher.Sync(t.Context(), sender))
	sent := sender.envelopes()
	require.Len(t, sent, 1)
	require.Equal(t, uint64(1), sent[0].GetGeneration())
	require.Equal(t, uint64(2), sent[0].GetRequestId(), "failed enqueue burns but never reuses an id")
	require.NoError(t, publisher.HandleResult(sender,
		snapshotResultEnvelope(2, 1, 1, controlpb.ErrorCode_ERROR_CODE_OK)))

	restartRequired := cfg.Clone()
	restartRequired.Proxy.Addr = "127.0.0.1:6001"
	require.ErrorIs(t, publisher.Update(restartRequired), ErrListenerRestartRequired)
	status := publisher.Status()
	require.Equal(t, uint64(1), status.DesiredGeneration, "bad candidate cannot replace last desired")
	require.Equal(t, uint64(2), status.RejectedGeneration)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_UNSUPPORTED_CONFIGURATION, status.LastResultCode)
	require.NoError(t, publisher.Sync(t.Context(), sender))
	require.Len(t, sender.envelopes(), 1)

	valid := cfg.Clone()
	valid.Proxy.MaxConnections = 84
	require.NoError(t, publisher.Update(valid))
	require.Equal(t, uint64(3), publisher.Status().DesiredGeneration,
		"rejected candidates still consume the monotonic generation")
	require.NoError(t, publisher.Sync(t.Context(), sender))
	require.Equal(t, uint64(3), sender.envelopes()[1].GetGeneration())
}

func TestSnapshotPublisherFailsClosedOnRequestIDExhaustion(t *testing.T) {
	publisher, _ := newSnapshotPublisherForTest(t)
	sender := &snapshotSender{epoch: 10, nextID: ^uint64(0)}
	require.ErrorContains(t, publisher.Sync(t.Context(), sender), "request ids exhausted")
	require.Empty(t, sender.envelopes())
	require.Equal(t, uint64(0), publisher.Status().SentGeneration)
}

func TestSnapshotPublisherRejectsFalseOKWithoutMutatingStatus(t *testing.T) {
	publisher, _ := newSnapshotPublisherForTest(t)
	sender := &snapshotSender{epoch: 11}
	require.NoError(t, publisher.Sync(t.Context(), sender))

	err := publisher.HandleResult(sender,
		snapshotResultEnvelope(1, 1, 99, controlpb.ErrorCode_ERROR_CODE_OK))
	require.ErrorContains(t, err, "applied generation 99, expected 1")
	status := publisher.Status()
	require.Equal(t, uint64(0), status.AppliedGeneration)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_UNSPECIFIED, status.LastResultCode)
}

func TestSnapshotPublisherCarriesTopologyProjection(t *testing.T) {
	cfg := config.NewConfig()
	builder, err := NewSnapshotBuilder(cfg, nil)
	require.NoError(t, err)
	publisher, err := NewSnapshotPublisher(SnapshotPublisherConfig{
		Builder:              builder,
		Initial:              cfg,
		AdvertisedCapability: 123,
		ServerVersion:        "test-server",
		Topology: func() ([]*controlpb.BackendSnapshot, []*controlpb.NamespaceSnapshot) {
			return []*controlpb.BackendSnapshot{{
					BackendId:   "alpha/tidb-1:4000",
					Address:     "tidb-1:4000",
					ClusterName: "alpha",
					Keyspace:    "ks-a",
					Healthy:     true,
				}}, []*controlpb.NamespaceSnapshot{{
					Name:           "ns-alpha",
					Users:          []string{"alice"},
					BackendCluster: "alpha",
				}}
		},
	})
	require.NoError(t, err)

	sender := &snapshotSender{epoch: 7}
	require.NoError(t, publisher.Sync(context.Background(), sender))
	sent := sender.envelopes()
	require.NotEmpty(t, sent)
	snapshot := sent[len(sent)-1].GetStateSnapshot()
	require.NotNil(t, snapshot)
	require.Len(t, snapshot.GetBackends(), 1, "the wire snapshot carries the backend topology")
	require.Equal(t, "alpha/tidb-1:4000", snapshot.GetBackends()[0].GetBackendId())
	require.Equal(t, "ks-a", snapshot.GetBackends()[0].GetKeyspace())
	require.Len(t, snapshot.GetNamespaces(), 1, "the wire snapshot carries the namespace topology")
	require.Equal(t, "ns-alpha", snapshot.GetNamespaces()[0].GetName())
	require.Equal(t, []string{"alice"}, snapshot.GetNamespaces()[0].GetUsers())
	require.Equal(t, "alpha", snapshot.GetNamespaces()[0].GetBackendCluster())
}

func TestSnapshotPublisherStagesTopologyRefreshOnlyOnChange(t *testing.T) {
	var mu sync.Mutex
	cluster := "alpha"
	cfg := config.NewConfig()
	builder, err := NewSnapshotBuilder(cfg, nil)
	require.NoError(t, err)
	publisher, err := NewSnapshotPublisher(SnapshotPublisherConfig{
		Builder:              builder,
		Initial:              cfg,
		AdvertisedCapability: 123,
		ServerVersion:        "test-server",
		Topology: func() ([]*controlpb.BackendSnapshot, []*controlpb.NamespaceSnapshot) {
			mu.Lock()
			defer mu.Unlock()
			return []*controlpb.BackendSnapshot{{
					BackendId:   cluster + "/tidb:4000",
					Address:     "tidb:4000",
					ClusterName: cluster,
					Healthy:     true,
				}}, []*controlpb.NamespaceSnapshot{{
					Name:           "default",
					BackendCluster: cluster,
				}}
		},
	})
	require.NoError(t, err)
	staged := publisher.Status().DesiredGeneration

	// Unchanged topology stages nothing: generations advance only on
	// real change.
	require.NoError(t, publisher.RefreshTopology())
	require.Equal(t, staged, publisher.Status().DesiredGeneration)

	// A live change (namespace commit, backend health) stages a fresh
	// generation carrying the new projection.
	mu.Lock()
	cluster = "beta"
	mu.Unlock()
	require.NoError(t, publisher.RefreshTopology())
	require.Equal(t, staged+1, publisher.Status().DesiredGeneration)
	publisher.mu.Lock()
	snapshot := publisher.desired.GetStateSnapshot()
	publisher.mu.Unlock()
	require.Equal(t, "beta", snapshot.GetNamespaces()[0].GetBackendCluster())
	require.Equal(t, "beta/tidb:4000", snapshot.GetBackends()[0].GetBackendId())
}
