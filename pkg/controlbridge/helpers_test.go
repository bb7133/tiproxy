// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Shared test doubles. These outlived the legacy RouterAdapter deleted at
// #223 Phase 2: the residual route-owner handler, the snapshot publisher and
// the metering tests all still need a control peer and a handshake handler.

package controlbridge

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type fakeSender struct {
	mu           sync.Mutex
	epoch        uint64
	nextID       uint64
	capabilities map[uint64]struct{}
	messages     []*controlpb.ControlEnvelope
}

func newFakeSender(epoch uint64, capabilities ...uint64) *fakeSender {
	peer := &fakeSender{epoch: epoch, capabilities: make(map[uint64]struct{}, len(capabilities))}
	for _, capability := range capabilities {
		peer.capabilities[capability] = struct{}{}
	}
	return peer
}

func (peer *fakeSender) Send(_ context.Context, envelope *controlpb.ControlEnvelope) error {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	cloned, ok := proto.Clone(envelope).(*controlpb.ControlEnvelope)
	if !ok {
		return errors.New("clone fake envelope")
	}
	cloned.ControlEpoch = peer.epoch
	peer.messages = append(peer.messages, cloned)
	return nil
}

func (peer *fakeSender) Epoch() uint64 { return peer.epoch }

func (peer *fakeSender) HasCapability(capability uint64) bool {
	_, ok := peer.capabilities[capability]
	return ok
}

func (peer *fakeSender) AllocateRequestID() (uint64, error) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.nextID == ^uint64(0) {
		return 0, transport.ErrRequestIDExhausted
	}
	peer.nextID++
	return peer.nextID, nil
}

type recordingHandler struct {
	mu                   sync.Mutex
	rt                   router.Router
	response             *pnet.HandshakeResp
	retryHandshakeErrors int
	handshakeCalls       int
	handshakeErr         error
	trafficCalls         int
	closeCalls           int
	lastClientIn         uint64
	lastClientOut        uint64
}

func (handler *recordingHandler) HandleHandshakeResp(_ backend.ConnContext, response *pnet.HandshakeResp) error {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.response = response
	return nil
}

func (handler *recordingHandler) HandleHandshakeErr(_ backend.ConnContext, _ *mysql.MyError) bool {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.retryHandshakeErrors > 0 {
		handler.retryHandshakeErrors--
		return true
	}
	return false
}

func (handler *recordingHandler) GetRouter(_ backend.ConnContext, _ *pnet.HandshakeResp) (router.Router, error) {
	if handler.rt == nil {
		return nil, errors.New("no router")
	}
	return handler.rt, nil
}

func (handler *recordingHandler) OnHandshake(_ backend.ConnContext, _ string, err error, _ backend.ErrorSource) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.handshakeCalls++
	handler.handshakeErr = err
}

func (handler *recordingHandler) OnConnClose(_ backend.ConnContext, _ backend.ErrorSource) error {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.closeCalls++
	return nil
}

func (handler *recordingHandler) OnTraffic(ctx backend.ConnContext) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.trafficCalls++
	handler.lastClientIn = ctx.ClientInBytes()
	handler.lastClientOut = ctx.ClientOutBytes()
}

func (handler *recordingHandler) GetCapability() pnet.Capability {
	return backend.SupportedServerCapabilities
}
func (handler *recordingHandler) GetServerVersion() string { return pnet.ServerVersion }

func (handler *recordingHandler) handshakeCount() int {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.handshakeCalls
}

func (handler *recordingHandler) closeCount() int {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.closeCalls
}

func lastEnvelope(t *testing.T, peer *fakeSender) *controlpb.ControlEnvelope {
	t.Helper()
	peer.mu.Lock()
	defer peer.mu.Unlock()
	require.NotEmpty(t, peer.messages)
	return peer.messages[len(peer.messages)-1]
}
