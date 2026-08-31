// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"sync"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrQueueFull indicates that a bounded lane has no count or byte capacity.
	ErrQueueFull = errors.New("control transport queue is full")
	// ErrMetricsDropped indicates intentional bulk-metric shedding under pressure.
	ErrMetricsDropped = errors.New("control metrics dropped under pressure")
	// ErrTransportClosed indicates that the session no longer accepts messages.
	ErrTransportClosed = errors.New("control transport is closed")
)

// QueueLimit bounds one priority lane by both message count and encoded bytes.
type QueueLimit struct {
	Messages int
	Bytes    uint64
}

// QueueLimits contains all outbound priority-lane limits.
type QueueLimits struct {
	Critical QueueLimit
	Control  QueueLimit
	Bulk     QueueLimit
}

// DefaultQueueLimits returns the v1 defaults from the control-protocol ADR.
func DefaultQueueLimits() QueueLimits {
	return QueueLimits{
		Critical: QueueLimit{Messages: 1024, Bytes: 8 * 1024 * 1024},
		Control:  QueueLimit{Messages: 4096, Bytes: 32 * 1024 * 1024},
		Bulk:     QueueLimit{Messages: 256, Bytes: 16 * 1024 * 1024},
	}
}

type queuedEnvelope struct {
	envelope *controlpb.ControlEnvelope
	size     uint64
}

type laneQueue struct {
	mu       sync.Mutex
	items    []queuedEnvelope
	bytes    uint64
	limit    QueueLimit
	notEmpty chan struct{}
	space    chan struct{}
	done     chan struct{}
	closed   bool
}

func newLaneQueue(limit QueueLimit) *laneQueue {
	return &laneQueue{
		items:    make([]queuedEnvelope, 0, limit.Messages),
		limit:    limit,
		notEmpty: make(chan struct{}, 1),
		space:    make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

func (queue *laneQueue) push(ctx context.Context, item queuedEnvelope, dropWhenFull bool) error {
	for {
		queue.mu.Lock()
		if queue.closed {
			queue.mu.Unlock()
			return ErrTransportClosed
		}
		if len(queue.items) < queue.limit.Messages && queue.bytes+item.size <= queue.limit.Bytes {
			queue.items = append(queue.items, item)
			queue.bytes += item.size
			queue.mu.Unlock()
			signal(queue.notEmpty)
			return nil
		}
		queue.mu.Unlock()
		if dropWhenFull {
			return ErrMetricsDropped
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-queue.done:
			return ErrTransportClosed
		case <-queue.space:
		}
	}
}

// pushMetering gives durable metering precedence over best-effort metrics in
// the shared bulk lane. It first evicts queued metrics until the metering
// record fits; if the lane contains only metering, it applies backpressure.
// An in-flight record is no longer owned by the queue and is never evicted.
func (queue *laneQueue) pushMetering(ctx context.Context, item queuedEnvelope) error {
	for {
		queue.mu.Lock()
		if queue.closed {
			queue.mu.Unlock()
			return ErrTransportClosed
		}
		for (len(queue.items) >= queue.limit.Messages || queue.bytes+item.size > queue.limit.Bytes) &&
			queue.evictOldestMetricLocked() {
		}
		if len(queue.items) < queue.limit.Messages && queue.bytes+item.size <= queue.limit.Bytes {
			queue.items = append(queue.items, item)
			queue.bytes += item.size
			queue.mu.Unlock()
			signal(queue.notEmpty)
			return nil
		}
		queue.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-queue.done:
			return ErrTransportClosed
		case <-queue.space:
		}
	}
}

func (queue *laneQueue) evictOldestMetricLocked() bool {
	for index, item := range queue.items {
		if item.envelope.GetMetricsBatch() == nil {
			continue
		}
		copy(queue.items[index:], queue.items[index+1:])
		queue.items[len(queue.items)-1] = queuedEnvelope{}
		queue.items = queue.items[:len(queue.items)-1]
		queue.bytes -= item.size
		signal(queue.space)
		return true
	}
	return false
}

func (queue *laneQueue) pop() (queuedEnvelope, bool) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.items) == 0 {
		return queuedEnvelope{}, false
	}
	item := queue.items[0]
	copy(queue.items, queue.items[1:])
	queue.items[len(queue.items)-1] = queuedEnvelope{}
	queue.items = queue.items[:len(queue.items)-1]
	queue.bytes -= item.size
	signal(queue.space)
	if len(queue.items) > 0 {
		signal(queue.notEmpty)
	}
	return item, true
}

func (queue *laneQueue) popMeteringFirst() (queuedEnvelope, bool) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.items) == 0 {
		return queuedEnvelope{}, false
	}
	index := 0
	for candidate := range queue.items {
		if queue.items[candidate].envelope.GetMeteringBatch() != nil {
			index = candidate
			break
		}
	}
	item := queue.items[index]
	copy(queue.items[index:], queue.items[index+1:])
	queue.items[len(queue.items)-1] = queuedEnvelope{}
	queue.items = queue.items[:len(queue.items)-1]
	queue.bytes -= item.size
	signal(queue.space)
	if len(queue.items) > 0 {
		signal(queue.notEmpty)
	}
	return item, true
}

func (queue *laneQueue) close() {
	queue.mu.Lock()
	if !queue.closed {
		queue.closed = true
		close(queue.done)
	}
	queue.mu.Unlock()
}

type outboundQueues struct {
	critical *laneQueue
	control  *laneQueue
	bulk     *laneQueue
	schedule []*laneQueue
	cursor   int
}

func newOutboundQueues(limits QueueLimits) *outboundQueues {
	queues := &outboundQueues{
		critical: newLaneQueue(limits.Critical),
		control:  newLaneQueue(limits.Control),
		bulk:     newLaneQueue(limits.Bulk),
	}
	queues.schedule = make([]*laneQueue, 0, 25)
	for range 16 {
		queues.schedule = append(queues.schedule, queues.critical)
	}
	for range 8 {
		queues.schedule = append(queues.schedule, queues.control)
	}
	queues.schedule = append(queues.schedule, queues.bulk)
	return queues
}

func (queues *outboundQueues) enqueue(ctx context.Context, envelope *controlpb.ControlEnvelope) error {
	cloned, ok := proto.Clone(envelope).(*controlpb.ControlEnvelope)
	if !ok {
		return errors.New("clone control envelope")
	}
	item := queuedEnvelope{
		envelope: cloned,
		size:     uint64(proto.Size(cloned) + 4),
	}
	queue := queues.control
	dropWhenFull := false
	switch envelope.GetPriority() {
	case controlpb.Priority_PRIORITY_CRITICAL:
		queue = queues.critical
	case controlpb.Priority_PRIORITY_BULK:
		queue = queues.bulk
		dropWhenFull = envelope.GetMetricsBatch() != nil
	case controlpb.Priority_PRIORITY_UNSPECIFIED, controlpb.Priority_PRIORITY_CONTROL:
	}
	if item.size > queue.limit.Bytes {
		if dropWhenFull {
			return ErrMetricsDropped
		}
		return ErrQueueFull
	}
	if envelope.GetMeteringBatch() != nil && queue == queues.bulk {
		return queue.pushMetering(ctx, item)
	}
	return queue.push(ctx, item, dropWhenFull)
}

func (queues *outboundQueues) next(ctx context.Context) (*controlpb.ControlEnvelope, error) {
	for {
		for range len(queues.schedule) {
			queue := queues.schedule[queues.cursor]
			queues.cursor = (queues.cursor + 1) % len(queues.schedule)
			var item queuedEnvelope
			var ok bool
			if queue == queues.bulk {
				item, ok = queue.popMeteringFirst()
			} else {
				item, ok = queue.pop()
			}
			if ok {
				return item.envelope, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queues.critical.done:
			return nil, ErrTransportClosed
		case <-queues.critical.notEmpty:
		case <-queues.control.notEmpty:
		case <-queues.bulk.notEmpty:
		}
	}
}

func (queues *outboundQueues) close() {
	queues.critical.close()
	queues.control.close()
	queues.bulk.close()
}

func signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}
