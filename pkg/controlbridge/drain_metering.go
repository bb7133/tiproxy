// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlbridge

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/pingcap/tiproxy/lib/util/errors"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/metrics"
)

// CompositeControlHandler is the production transport handler for the
// Go control plane: it owns the metering consumer alongside the router
// adapter (legacy) or the residual route-owner surface, applies metering
// batches, and rejects retired v1 tombstones (the route family and, since
// CP-ADMIN slice 3, both drain bodies). Everything else goes to the
// RouterAdapter in the legacy composition.
type CompositeControlHandler struct {
	adapter               *RouterAdapter
	consumer              *MeteringConsumer
	publisher             *SnapshotPublisher
	routeOwner            bool
	nativeMeterOwner      bool
	legacyMeterViolations atomic.Uint64
	legacyRouteViolations atomic.Uint64
}

const emptyRouteStateSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// RouteOwnerStatus is the auditable post-cutover Go route-state surface. A
// residual handler owns no route objects, so every route-effect counter and the
// mapping count are structurally zero; the only mutable value records rejected
// legacy route-family traffic.
type RouteOwnerStatus struct {
	RouterAdapterConstructions uint64
	SelectorCalls              uint64
	SelectorEffects            uint64
	RouteFinishes              uint64
	RedirectsIssued            uint64
	OrphansRehydrated          uint64
	RouteCloses                uint64
	ConnectionMappings         uint64
	LegacyRouteViolations      uint64
	RouteStateSHA256           string
}

// AttachSnapshotPublisher routes correlated Rust apply/reject answers to the
// Go generation owner. It is optional for legacy Go-dataplane compositions.
func (handler *CompositeControlHandler) AttachSnapshotPublisher(publisher *SnapshotPublisher) {
	handler.publisher = publisher
}

// NewCompositeControlHandler wires the legacy owners together; the
// consumer's applied sequence becomes the adapter's reconcile
// acknowledgement. Operator drains are issued inside the Rust process
// (CP-ADMIN slice 3), so no composition carries a Go drain issuer.
func NewCompositeControlHandler(
	adapter *RouterAdapter,
	consumer *MeteringConsumer,
) (*CompositeControlHandler, error) {
	if adapter == nil || consumer == nil {
		return nil, errors.New("composite control handler requires adapter and consumer")
	}
	adapter.AttachMetering(consumer)
	return &CompositeControlHandler{adapter: adapter, consumer: consumer}, nil
}

// NewRouteOwnerControlHandler installs the post-cutover residual handler. It
// deliberately has no RouterAdapter and therefore no Go-side route state,
// and no drain issuer: `drain_command`/`drain_result` are retired tombstones
// under RUST_ROUTE_OWNER.
func NewRouteOwnerControlHandler(
	consumer *MeteringConsumer,
) (*CompositeControlHandler, error) {
	if consumer == nil {
		return nil, errors.New("route-owner control handler requires a consumer")
	}
	return &CompositeControlHandler{consumer: consumer, routeOwner: true}, nil
}

// NewNativeMeterOwnerControlHandler owns neither route state nor a metering
// consumer. Metering batches/ACKs are retired in this process-fixed composition.
func NewNativeMeterOwnerControlHandler() (*CompositeControlHandler, error) {
	return &CompositeControlHandler{routeOwner: true, nativeMeterOwner: true}, nil
}

// RouteOwnerStatus snapshots the residual handler's zero-route proof.
func (handler *CompositeControlHandler) RouteOwnerStatus() RouteOwnerStatus {
	return RouteOwnerStatus{
		LegacyRouteViolations: handler.legacyRouteViolations.Load(),
		RouteStateSHA256:      emptyRouteStateSHA256,
	}
}

// HandleControlMessage implements transport.Handler.
func (handler *CompositeControlHandler) HandleControlMessage(
	ctx context.Context,
	session *transport.Session,
	envelope *controlpb.ControlEnvelope,
) error {
	return handler.HandleEnvelope(ctx, session, envelope)
}

// HandleEnvelope dispatches one control message across the three
// production owners.
func (handler *CompositeControlHandler) HandleEnvelope(
	ctx context.Context,
	sender EnvelopeSender,
	envelope *controlpb.ControlEnvelope,
) error {
	if envelope == nil {
		return errors.New("control envelope is required")
	}
	if handler.nativeMeterOwner {
		switch envelope.GetBody().(type) {
		case *controlpb.ControlEnvelope_MeteringBatch, *controlpb.ControlEnvelope_MeteringAck:
			handler.legacyMeterViolations.Add(1)
			metrics.ServerErrCounter.WithLabelValues("rust_legacy_metering_violation").Inc()
			return sendBody(ctx, sender, envelope.GetRequestId(), controlpb.Priority_PRIORITY_CRITICAL,
				&controlpb.ControlEnvelope_Error{Error: &controlpb.ProtocolError{
					Code:               controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION,
					OffendingRequestId: envelope.GetRequestId(),
					Detail:             "retired metering message under RUST_METER_OWNER",
				}})
		}
	}
	switch body := envelope.GetBody().(type) {
	case *controlpb.ControlEnvelope_SnapshotResult:
		if handler.publisher == nil {
			return errors.New("snapshot result received without a publisher")
		}
		return handler.publisher.HandleResult(sender, envelope)
	case *controlpb.ControlEnvelope_MeteringBatch:
		if body.MeteringBatch.GetProducerId() == "" {
			// Legacy peers retain delta + reconcile-watermark semantics.
			_ = handler.consumer.Apply(body.MeteringBatch)
			return nil
		}
		// Capability 4: persist source baselines + pending aggregates before
		// the explicit critical ACK. Duplicates are re-ACKed; gaps,
		// producer mismatches, or durable-state failures return without an
		// ACK and emit a fatal, capability-gated error. Rust then stops SQL
		// admission and drains the dataplane owner; merely tearing down this
		// session would reconnect and could leave billable SQL serving while
		// the durable consumer remained unavailable.
		if _, err := handler.consumer.ApplyAbsolute(body.MeteringBatch); err != nil {
			metrics.ServerErrCounter.WithLabelValues("rust_metering_invalid").Inc()
			return sendFatalMeteringError(ctx, sender, envelope.GetRequestId(), err)
		}
		requestID, err := sender.AllocateRequestID()
		if err != nil {
			return sendFatalMeteringError(ctx, sender, envelope.GetRequestId(), err)
		}
		return sender.Send(ctx, &controlpb.ControlEnvelope{
			RequestId: requestID,
			Priority:  controlpb.Priority_PRIORITY_CRITICAL,
			RequiredCapabilities: []uint64{
				uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_METERING_ABSOLUTE_SNAPSHOTS),
			},
			Body: &controlpb.ControlEnvelope_MeteringAck{MeteringAck: &controlpb.MeteringAck{
				ProducerId: body.MeteringBatch.GetProducerId(),
				Sequence:   body.MeteringBatch.GetSequence(),
			}},
		})
	case *controlpb.ControlEnvelope_MetricsBatch:
		// Metrics are deliberately best effort: invalid or stale batches are
		// counted and ignored without taking down the control stream. The
		// closed metric catalog and bounded series store prevent arbitrary
		// labels from becoming an allocation channel.
		if err := metrics.ApplyRustMetricsBatch(sender.Epoch(), body.MetricsBatch); err != nil {
			metrics.ServerErrCounter.WithLabelValues("rust_metrics_invalid").Inc()
		}
		return nil
	case *controlpb.ControlEnvelope_DrainCommand, *controlpb.ControlEnvelope_DrainResult:
		// Operator drains are issued inside the Rust process (CP-ADMIN
		// slice 3): no Go composition issues or consumes drain bodies. The
		// route owner rejects them as retired tombstones; the legacy
		// composition ignores them.
		if handler.routeOwner {
			return handler.rejectRetiredRouteBody(ctx, sender, envelope)
		}
		return nil
	case *controlpb.ControlEnvelope_Error:
		// Errors keep the transport's generic (ignore) handling via the
		// adapter; no drain issuance correlates to them any more.
		if handler.routeOwner {
			return nil
		}
		return handler.adapter.HandleEnvelope(ctx, sender, envelope)
	case *controlpb.ControlEnvelope_ReconcileRequest:
		// `last_drain_command_sequence` is Rust's own gate watermark,
		// reported for diagnostics only: local drains keep their sequence
		// lineage inside the Rust process and Go restores nothing.
		if handler.routeOwner {
			return handler.handleResidualReconcile(ctx, sender, envelope, body.ReconcileRequest)
		}
		return handler.adapter.HandleEnvelope(ctx, sender, envelope)
	default:
		if handler.routeOwner && isRetiredRouteBody(envelope.GetBody()) {
			return handler.rejectRetiredRouteBody(ctx, sender, envelope)
		}
		if handler.routeOwner {
			return nil
		}
		return handler.adapter.HandleEnvelope(ctx, sender, envelope)
	}
}

func (handler *CompositeControlHandler) handleResidualReconcile(
	ctx context.Context,
	sender EnvelopeSender,
	envelope *controlpb.ControlEnvelope,
	request *controlpb.ReconcileRequest,
) error {
	if request == nil || request.GetLastConnectionEventSequence() != 0 || len(request.GetConnections()) != 0 {
		return handler.rejectRetiredRouteBody(ctx, sender, envelope)
	}
	var meteringSequence uint64
	if handler.consumer != nil {
		meteringSequence = handler.consumer.LastApplied()
	}
	return sendBodyWithOptions(ctx, sender, envelope.GetRequestId(), envelope.GetGeneration(),
		controlpb.Priority_PRIORITY_CRITICAL,
		[]uint64{uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RUST_ROUTE_OWNER)},
		&controlpb.ControlEnvelope_ReconcileSnapshot{ReconcileSnapshot: &controlpb.ReconcileSnapshot{
			AppliedGeneration:       request.GetKnownGeneration(),
			ConnectionEventSequence: 0,
			MetricsSequence:         request.GetLastMetricsSequence(),
			MeteringSequence:        meteringSequence,
			Connections:             nil,
		}})
}

func (handler *CompositeControlHandler) rejectRetiredRouteBody(
	ctx context.Context,
	sender EnvelopeSender,
	envelope *controlpb.ControlEnvelope,
) error {
	handler.legacyRouteViolations.Add(1)
	metrics.ServerErrCounter.WithLabelValues("rust_legacy_route_violation").Inc()
	return sendBody(ctx, sender, envelope.GetRequestId(), controlpb.Priority_PRIORITY_CRITICAL,
		&controlpb.ControlEnvelope_Error{Error: &controlpb.ProtocolError{
			Code:               controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION,
			OffendingRequestId: envelope.GetRequestId(),
			Detail:             "retired route-family message under RUST_ROUTE_OWNER",
			Fatal:              false,
		}})
}

// isRetiredRouteBody lists the v1 tombstones the route owner rejects: the
// route family retired at cutover and, since CP-ADMIN slice 3, both drain
// bodies (`rust_legacy_route_violation` counts retired drains too).
func isRetiredRouteBody(body any) bool {
	switch body.(type) {
	case *controlpb.ControlEnvelope_DrainCommand,
		*controlpb.ControlEnvelope_DrainResult,
		*controlpb.ControlEnvelope_HandshakeResponse,
		*controlpb.ControlEnvelope_HandshakeDecision,
		*controlpb.ControlEnvelope_HandshakeResult,
		*controlpb.ControlEnvelope_RouteRequest,
		*controlpb.ControlEnvelope_RouteAssignment,
		*controlpb.ControlEnvelope_RouteResult,
		*controlpb.ControlEnvelope_ConnectionEvent,
		*controlpb.ControlEnvelope_RedirectCommand,
		*controlpb.ControlEnvelope_RedirectResult,
		*controlpb.ControlEnvelope_CloseCommand,
		*controlpb.ControlEnvelope_CloseResult,
		*controlpb.ControlEnvelope_ReconcileSnapshot:
		return true
	default:
		return false
	}
}

// sendFatalMeteringError is intentionally correlated to the inbound batch id,
// so failure of the sender's request-id allocator cannot suppress the
// fail-closed signal. A successful send keeps this control session alive long
// enough for Rust to receive the fatal frame and run its coordinated
// stop-admission -> graceful drain -> force-close path.
func sendFatalMeteringError(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	cause error,
) error {
	return sender.Send(ctx, &controlpb.ControlEnvelope{
		RequestId: requestID,
		Priority:  controlpb.Priority_PRIORITY_CRITICAL,
		RequiredCapabilities: []uint64{
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_METERING_ABSOLUTE_SNAPSHOTS),
		},
		Body: &controlpb.ControlEnvelope_Error{Error: &controlpb.ProtocolError{
			Code:               controlpb.ErrorCode_ERROR_CODE_INTERNAL,
			OffendingRequestId: requestID,
			Detail:             bounded(cause.Error()),
			Fatal:              true,
		}},
	})
}

// ResolveOrphans delegates the maintenance cadence to the adapter.
func (handler *CompositeControlHandler) ResolveOrphans(ctx context.Context) error {
	if handler.routeOwner {
		return nil
	}
	return handler.adapter.ResolveOrphans(ctx)
}

// MeteringConsumer owns the Go side of deduplicated cumulative metering
// (CTL-06): a batch applies only when its sequence is strictly greater
// than the last applied one, so the Rust producer's at-least-once
// replay (verbatim batches under their original sequences) can never
// double-count. LastApplied feeds the reconcile snapshot so the
// producer can drop acknowledged retention.
type MeteringConsumer struct {
	mu                sync.Mutex
	lastApplied       uint64
	processGeneration uint64
	totals            map[meteringKey]*meteringTotals
	producerID        string
	sources           map[meteringSourceKey]meteringSourceBaseline
	pending           map[meteringKey]*meteringTotals
	statePath         string
	sink              MeteringSink
	healthy           bool
}

type meteringKey struct {
	keyspace       string
	backendID      string
	publicEndpoint bool
}

type meteringTotals struct {
	responseBytes      uint64
	crossLocationBytes uint64
}

// NewMeteringConsumer creates an empty consumer.
func NewMeteringConsumer() *MeteringConsumer {
	return &MeteringConsumer{
		totals:  make(map[meteringKey]*meteringTotals),
		sources: make(map[meteringSourceKey]meteringSourceBaseline),
		pending: make(map[meteringKey]*meteringTotals),
		healthy: true,
	}
}

// Apply accumulates one batch if and only if its sequence advances past
// the last applied one; duplicates and reordered replays return false
// without changing any counter.
func (consumer *MeteringConsumer) Apply(batch *controlpb.MeteringBatch) bool {
	if batch == nil {
		return false
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	// The sequence space is exhausted: +1 would wrap and accept
	// sequence 0. Fail closed on everything.
	if consumer.lastApplied == ^uint64(0) {
		return false
	}
	// Only the contiguous next sequence applies: a gap means an earlier
	// batch is still in flight (the producer replays in order), and
	// applying past it would lose that batch forever.
	if batch.GetSequence() != consumer.lastApplied+1 {
		return false
	}
	// Transactional: validate every checked addition first; only a
	// fully valid batch advances the sequence or touches a counter, so
	// an overflow can neither wrap totals nor acknowledge the batch.
	type pendingAdd struct {
		key      meteringKey
		response uint64
		cross    uint64
	}
	adds := make([]pendingAdd, 0, len(batch.GetDeltas()))
	staged := make(map[meteringKey]meteringTotals, len(batch.GetDeltas()))
	for _, delta := range batch.GetDeltas() {
		key := meteringKey{
			keyspace:       delta.GetKeyspace(),
			backendID:      delta.GetBackendId(),
			publicEndpoint: delta.GetPublicEndpoint(),
		}
		current, ok := staged[key]
		if !ok {
			if existing, present := consumer.totals[key]; present {
				current = *existing
			}
		}
		response := current.responseBytes + delta.GetResponseBytes()
		cross := current.crossLocationBytes + delta.GetCrossLocationBytes()
		if response < current.responseBytes || cross < current.crossLocationBytes {
			return false
		}
		staged[key] = meteringTotals{responseBytes: response, crossLocationBytes: cross}
		adds = append(adds, pendingAdd{key: key, response: response, cross: cross})
	}
	for _, add := range adds {
		totals, ok := consumer.totals[add.key]
		if !ok {
			totals = &meteringTotals{}
			consumer.totals[add.key] = totals
		}
		totals.responseBytes = add.response
		totals.crossLocationBytes = add.cross
	}
	consumer.lastApplied = batch.GetSequence()
	return true
}

// LastApplied returns the highest applied sequence for the reconcile
// snapshot's metering acknowledgement.
func (consumer *MeteringConsumer) LastApplied() uint64 {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.lastApplied
}

// Totals returns the accumulated counters for one metering dimension.
func (consumer *MeteringConsumer) Totals(keyspace, backendID string, publicEndpoint bool) (responseBytes, crossLocationBytes uint64) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	totals, ok := consumer.totals[meteringKey{keyspace: keyspace, backendID: backendID, publicEndpoint: publicEndpoint}]
	if !ok {
		return 0, 0
	}
	return totals.responseBytes, totals.crossLocationBytes
}
