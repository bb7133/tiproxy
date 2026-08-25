// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/pingcap/tiproxy/lib/util/waitgroup"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrDuplicatePeer indicates a second dataplane connection while one owns the server.
	ErrDuplicatePeer = errors.New("duplicate Rust dataplane control connection")
	// ErrPeerCredential indicates that the operating-system peer identity is not allowed.
	ErrPeerCredential = errors.New("unexpected control peer credential")
)

// ServerConfig configures the Go owner of the control UDS.
type ServerConfig struct {
	SocketPath           string
	AllowedUID           *uint32
	LocalHello           *controlpb.Hello
	RequiredCapabilities []uint64
	MaxFrameBytes        uint32
	QueueLimits          QueueLimits
	HandshakeTimeout     time.Duration
	HeartbeatInterval    time.Duration
	PeerTimeout          time.Duration
	WriteTimeout         time.Duration
}

// Server owns one permission-checked UDS and at most one Rust dataplane peer.
type Server struct {
	config     ServerConfig
	listener   *net.UnixListener
	socketInfo os.FileInfo
	handler    Handler

	mu        sync.Mutex
	occupied  bool
	active    *Session
	conns     map[*net.UnixConn]struct{}
	nextEpoch uint64
	closed    bool
	closeOnce sync.Once
	workers   waitgroup.WaitGroup
}

// Listen creates a mode-0600 UDS. Serve must be called to accept peers.
func Listen(config ServerConfig, handler Handler) (*Server, error) {
	normalized, err := normalizeServerConfig(config)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(normalized.SocketPath), 0o700); err != nil {
		return nil, fmt.Errorf("create control socket directory: %w", err)
	}
	if _, err := os.Lstat(normalized.SocketPath); err == nil {
		return nil, fmt.Errorf("control socket path already exists: %s", normalized.SocketPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect control socket path: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: normalized.SocketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on control socket: %w", err)
	}
	if err := os.Chmod(normalized.SocketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restrict control socket permissions: %w", err)
	}
	info, err := os.Lstat(normalized.SocketPath)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("inspect created control socket: %w", err)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		return nil, fmt.Errorf("control socket is not a mode-0600 socket: %s", info.Mode())
	}
	return &Server{
		config:     normalized,
		listener:   listener,
		socketInfo: info,
		handler:    handler,
		conns:      make(map[*net.UnixConn]struct{}),
	}, nil
}

// Serve accepts peers until ctx is canceled or Close is called.
func (server *Server) Serve(ctx context.Context) error {
	for {
		if err := server.listener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return fmt.Errorf("set control accept deadline: %w", err)
		}
		conn, err := server.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				server.stopActive()
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept control peer: %w", err)
		}
		server.mu.Lock()
		if server.closed {
			server.mu.Unlock()
			_ = conn.Close()
			return nil
		}
		server.conns[conn] = struct{}{}
		server.mu.Unlock()
		server.workers.Run(func() { server.serveConn(ctx, conn) })
	}
}

// Active returns the current negotiated session, if any.
func (server *Server) Active() *Session {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.active
}

// Close stops accepting, joins every peer task, and removes only this server's socket inode.
func (server *Server) Close() error {
	var closeErr error
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		server.mu.Unlock()
		if err := server.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = fmt.Errorf("close control listener: %w", err)
		}
		server.stopAllConnections()
		server.workers.Wait()
		current, err := os.Lstat(server.config.SocketPath)
		if err == nil && os.SameFile(server.socketInfo, current) {
			if err := os.Remove(server.config.SocketPath); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("remove control socket: %w", err))
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			closeErr = errors.Join(closeErr, fmt.Errorf("inspect control socket during close: %w", err))
		}
	})
	return closeErr
}

func (server *Server) serveConn(ctx context.Context, conn *net.UnixConn) {
	defer func() {
		server.mu.Lock()
		delete(server.conns, conn)
		server.mu.Unlock()
	}()
	session, err := server.handshake(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	err = session.run(ctx, server.handler)
	_ = err
	server.mu.Lock()
	if server.active == session {
		server.active = nil
		server.occupied = false
	}
	server.mu.Unlock()
}

func (server *Server) handshake(conn *net.UnixConn) (_ *Session, returnErr error) {
	credential, err := readPeerCredential(conn)
	if err != nil {
		return nil, fmt.Errorf("read control peer credential: %w", err)
	}
	if credential.UID != *server.config.AllowedUID {
		return nil, fmt.Errorf("%w: uid %d", ErrPeerCredential, credential.UID)
	}
	deadline := time.Now().Add(server.config.HandshakeTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set control handshake deadline: %w", err)
	}
	if err := controlpb.WriteFrame(conn, helloEnvelope(server.config.LocalHello), server.config.MaxFrameBytes); err != nil {
		return nil, err
	}
	peerEnvelope, err := controlpb.ReadFrame(conn, server.config.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	peerHello := peerEnvelope.GetHello()
	if peerEnvelope.GetProtocolVersion() != controlpb.ProtocolV1 || peerHello == nil ||
		peerHello.GetRole() != controlpb.Role_ROLE_RUST_DATAPLANE {
		_ = server.writeRejectedHello(conn, controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "expected Hello")
		return nil, errors.New("control peer did not send Hello")
	}

	server.mu.Lock()
	if server.closed || server.occupied {
		server.mu.Unlock()
		_ = server.writeRejectedHello(conn, controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, ErrDuplicatePeer.Error())
		return nil, ErrDuplicatePeer
	}
	server.occupied = true
	server.nextEpoch++
	epoch := server.nextEpoch
	server.mu.Unlock()
	reserved := true
	defer func() {
		if returnErr != nil && reserved {
			server.mu.Lock()
			server.occupied = false
			server.mu.Unlock()
		}
	}()

	ack, err := controlpb.NegotiateHello(
		server.config.LocalHello,
		peerHello,
		server.config.RequiredCapabilities,
		epoch,
	)
	if err != nil {
		code := controlpb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION
		if errors.Is(err, controlpb.ErrMissingCapability) {
			code = controlpb.ErrorCode_ERROR_CODE_MISSING_CAPABILITY
		}
		_ = server.writeRejectedHello(conn, code, err.Error())
		return nil, err
	}
	if err := controlpb.WriteFrame(conn, helloAckEnvelope(ack), ack.GetMaxFrameBytes()); err != nil {
		return nil, err
	}
	peerAckEnvelope, err := controlpb.ReadFrame(conn, ack.GetMaxFrameBytes())
	if err != nil {
		return nil, err
	}
	peerAck := peerAckEnvelope.GetHelloAck()
	if peerAck == nil || peerAck.GetSelectedVersion() != controlpb.ProtocolV1 ||
		peerAck.GetControlEpoch() != epoch || peerAck.GetRejectionCode() != controlpb.ErrorCode_ERROR_CODE_OK {
		return nil, errors.New("control peer rejected or mismatched HelloAck")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear control handshake deadline: %w", err)
	}
	session := newSession(conn, epoch, ack.GetNegotiatedCapabilities(), sessionConfig{
		maxFrameBytes:     ack.GetMaxFrameBytes(),
		queues:            server.config.QueueLimits,
		heartbeatInterval: server.config.HeartbeatInterval,
		peerTimeout:       server.config.PeerTimeout,
		writeTimeout:      server.config.WriteTimeout,
	})
	server.mu.Lock()
	server.active = session
	server.mu.Unlock()
	reserved = false
	return session, nil
}

func (server *Server) writeRejectedHello(conn *net.UnixConn, code controlpb.ErrorCode, detail string) error {
	return controlpb.WriteFrame(conn, helloAckEnvelope(&controlpb.HelloAck{
		RejectionCode:   code,
		RejectionDetail: detail,
	}), server.config.MaxFrameBytes)
}

func (server *Server) stopActive() {
	server.mu.Lock()
	active := server.active
	server.mu.Unlock()
	if active != nil {
		active.Stop()
	}
}

func (server *Server) stopAllConnections() {
	server.mu.Lock()
	active := server.active
	connections := make([]*net.UnixConn, 0, len(server.conns))
	for conn := range server.conns {
		connections = append(connections, conn)
	}
	server.mu.Unlock()
	if active != nil {
		active.Stop()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func helloEnvelope(hello *controlpb.Hello) *controlpb.ControlEnvelope {
	cloned, _ := proto.Clone(hello).(*controlpb.Hello)
	return &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_Hello{Hello: cloned},
	}
}

func helloAckEnvelope(ack *controlpb.HelloAck) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    ack.GetControlEpoch(),
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_HelloAck{HelloAck: ack},
	}
}

func normalizeServerConfig(config ServerConfig) (ServerConfig, error) {
	if !filepath.IsAbs(config.SocketPath) {
		return config, errors.New("control socket path must be absolute")
	}
	if config.LocalHello == nil {
		return config, errors.New("local control Hello is required")
	}
	if config.LocalHello.GetRole() != controlpb.Role_ROLE_GO_CONTROL ||
		!slices.Contains(config.LocalHello.GetSupportedVersions(), controlpb.ProtocolV1) {
		return config, errors.New("local control Hello must advertise Go role and protocol v1")
	}
	if config.AllowedUID == nil {
		uid := uint32(os.Getuid())
		config.AllowedUID = &uid
	}
	if config.MaxFrameBytes == 0 || config.MaxFrameBytes > controlpb.DefaultMaxFrameBytes {
		config.MaxFrameBytes = controlpb.DefaultMaxFrameBytes
	}
	clonedHello, ok := proto.Clone(config.LocalHello).(*controlpb.Hello)
	if !ok {
		return config, errors.New("clone local control Hello")
	}
	clonedHello.MaxFrameBytes = config.MaxFrameBytes
	config.LocalHello = clonedHello
	if config.QueueLimits == (QueueLimits{}) {
		config.QueueLimits = DefaultQueueLimits()
	}
	if err := validateQueueLimits(config.QueueLimits); err != nil {
		return config, err
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = 5 * time.Second
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = time.Second
	}
	if config.PeerTimeout <= config.HeartbeatInterval {
		config.PeerTimeout = 3 * config.HeartbeatInterval
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 5 * time.Second
	}
	return config, nil
}

func validateQueueLimits(limits QueueLimits) error {
	hard := QueueLimits{
		Critical: QueueLimit{Messages: 4096, Bytes: 32 * 1024 * 1024},
		Control:  QueueLimit{Messages: 16384, Bytes: 128 * 1024 * 1024},
		Bulk:     QueueLimit{Messages: 1024, Bytes: 64 * 1024 * 1024},
	}
	for name, pair := range map[string][2]QueueLimit{
		"critical": {limits.Critical, hard.Critical},
		"control":  {limits.Control, hard.Control},
		"bulk":     {limits.Bulk, hard.Bulk},
	} {
		if pair[0].Messages <= 0 || pair[0].Bytes == 0 ||
			pair[0].Messages > pair[1].Messages || pair[0].Bytes > pair[1].Bytes {
			return fmt.Errorf("invalid %s control queue limit", name)
		}
	}
	return nil
}
