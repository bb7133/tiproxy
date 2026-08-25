// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pingcap/tiproxy/lib/util/waitgroup"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"google.golang.org/protobuf/proto"
)

// Handler receives validated messages from one owning dataplane session.
// Implementations must return when ctx is canceled.
type Handler interface {
	HandleControlMessage(ctx context.Context, session *Session, envelope *controlpb.ControlEnvelope) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(context.Context, *Session, *controlpb.ControlEnvelope) error

// HandleControlMessage implements Handler.
func (handler HandlerFunc) HandleControlMessage(
	ctx context.Context,
	session *Session,
	envelope *controlpb.ControlEnvelope,
) error {
	return handler(ctx, session, envelope)
}

type sessionConfig struct {
	maxFrameBytes     uint32
	queues            QueueLimits
	heartbeatInterval time.Duration
	peerTimeout       time.Duration
	writeTimeout      time.Duration
}

// Session is one negotiated, epoch-bound Go/Rust control stream.
type Session struct {
	conn         *net.UnixConn
	epoch        uint64
	capabilities map[uint64]struct{}
	config       sessionConfig
	queues       *outboundQueues
	done         chan struct{}

	cancelMu sync.Mutex
	cancel   context.CancelFunc
	stopOnce sync.Once
	lastRecv atomic.Int64
	nextID   atomic.Uint64
}

func newSession(conn *net.UnixConn, epoch uint64, capabilities []uint64, config sessionConfig) *Session {
	negotiated := make(map[uint64]struct{}, len(capabilities))
	for _, capability := range capabilities {
		negotiated[capability] = struct{}{}
	}
	session := &Session{
		conn:         conn,
		epoch:        epoch,
		capabilities: negotiated,
		config:       config,
		queues:       newOutboundQueues(config.queues),
		done:         make(chan struct{}),
	}
	session.lastRecv.Store(time.Now().UnixNano())
	return session
}

// HasCapability reports whether Hello negotiation enabled an additive protocol capability.
func (session *Session) HasCapability(capability uint64) bool {
	_, ok := session.capabilities[capability]
	return ok
}

// Epoch returns the Go-assigned owner epoch.
func (session *Session) Epoch() uint64 {
	return session.epoch
}

// Done closes after all reader, writer, and heartbeat work has joined.
func (session *Session) Done() <-chan struct{} {
	return session.done
}

// LastReceived returns when the peer last delivered a valid complete frame.
func (session *Session) LastReceived() time.Time {
	return time.Unix(0, session.lastRecv.Load())
}

// Send queues a defensive copy of one envelope in its declared priority lane.
func (session *Session) Send(ctx context.Context, envelope *controlpb.ControlEnvelope) error {
	cloned, ok := proto.Clone(envelope).(*controlpb.ControlEnvelope)
	if !ok {
		return errors.New("clone outbound control envelope")
	}
	cloned.ProtocolVersion = controlpb.ProtocolV1
	cloned.ControlEpoch = session.epoch
	return session.queues.enqueue(ctx, cloned)
}

// Stop cancels the session without waiting. It is safe from a Handler callback.
func (session *Session) Stop() {
	session.stopOnce.Do(func() {
		session.cancelMu.Lock()
		if session.cancel != nil {
			session.cancel()
		}
		session.cancelMu.Unlock()
		session.queues.close()
		_ = session.conn.Close()
	})
}

// Close stops the session and waits for all owned tasks to exit.
// Handler callbacks must call Stop instead to avoid waiting on themselves.
func (session *Session) Close() error {
	session.Stop()
	<-session.done
	return nil
}

func (session *Session) run(parent context.Context, handler Handler) error {
	ctx, cancel := context.WithCancel(parent)
	session.cancelMu.Lock()
	session.cancel = cancel
	session.cancelMu.Unlock()

	errorsCh := make(chan error, 3)
	var workers waitgroup.WaitGroup
	workers.Run(func() { errorsCh <- session.readLoop(ctx, handler) })
	workers.Run(func() { errorsCh <- session.writeLoop(ctx) })
	workers.Run(func() { errorsCh <- session.heartbeatLoop(ctx) })

	err := <-errorsCh
	cancel()
	session.queues.close()
	_ = session.conn.Close()
	workers.Wait()
	close(session.done)
	if parent.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (session *Session) readLoop(ctx context.Context, handler Handler) error {
	for {
		if err := session.conn.SetReadDeadline(time.Now().Add(session.config.peerTimeout)); err != nil {
			return fmt.Errorf("set control read deadline: %w", err)
		}
		envelope, err := controlpb.ReadFrame(session.conn, session.config.maxFrameBytes)
		if err != nil {
			return err
		}
		if envelope.GetProtocolVersion() != controlpb.ProtocolV1 {
			return fmt.Errorf("%w: %d", controlpb.ErrUnsupportedVersion, envelope.GetProtocolVersion())
		}
		if envelope.GetControlEpoch() != session.epoch {
			return fmt.Errorf("stale control epoch %d, expected %d", envelope.GetControlEpoch(), session.epoch)
		}
		session.lastRecv.Store(time.Now().UnixNano())
		if handler != nil {
			if err := handler.HandleControlMessage(ctx, session, envelope); err != nil {
				return fmt.Errorf("handle control message: %w", err)
			}
		}
	}
}

func (session *Session) writeLoop(ctx context.Context) error {
	for {
		envelope, err := session.queues.next(ctx)
		if err != nil {
			return err
		}
		if err := session.conn.SetWriteDeadline(time.Now().Add(session.config.writeTimeout)); err != nil {
			return fmt.Errorf("set control write deadline: %w", err)
		}
		if err := controlpb.WriteFrame(session.conn, envelope, session.config.maxFrameBytes); err != nil {
			return err
		}
	}
}

func (session *Session) heartbeatLoop(ctx context.Context) error {
	ticker := time.NewTicker(session.config.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			heartbeat := &controlpb.ControlEnvelope{
				RequestId: session.nextID.Add(1),
				Priority:  controlpb.Priority_PRIORITY_CRITICAL,
				Body: &controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{
					MonotonicMillis: uint64(time.Since(processStartedAt).Milliseconds()),
				}},
			}
			if err := session.Send(ctx, heartbeat); err != nil {
				return err
			}
		}
	}
}

var processStartedAt = time.Now()
