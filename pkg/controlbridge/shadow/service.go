// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/pingcap/tiproxy/lib/util/waitgroup"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"go.uber.org/zap"
)

// Service owns the optional observation transport, its producers and bounded
// queue. It must be constructed before namespace Init and closed on rollback.
type Service struct {
	recorder       *observation.Recorder
	listener       *net.UnixListener
	socketInfo     os.FileInfo
	process, nonce uint64
	logger         *zap.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	active         *net.UnixConn
	closed         bool
	workers        waitgroup.WaitGroup
	closeOnce      sync.Once
}

// Start creates a fresh private socket and starts accepting without waiting for
// the first consumer. Capture can retain Begin before Rust starts connecting.
func Start(ctx context.Context, path string, logger *zap.Logger) (*Service, error) {
	return start(ctx, path, logger, observation.DefaultLimits())
}
func start(ctx context.Context, path string, logger *zap.Logger, limits observation.Limits) (*Service, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("routing shadow socket must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("routing shadow directory must be private and owned by this UID")
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("routing shadow socket must be fresh")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// Keep inode ownership explicit; Close never removes a replacement socket.
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	info, err = os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	process, nonce := binary.BigEndian.Uint64(random[:8]), binary.BigEndian.Uint64(random[8:])
	if process == 0 || nonce == 0 {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, errors.New("zero routing shadow random identity")
	}
	recorder, err := observation.NewRecorder(limits, process, nonce)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	s := &Service{recorder: recorder, listener: listener, socketInfo: info, process: process, nonce: nonce, logger: logger, ctx: child, cancel: cancel}
	s.workers.RunWithRecover(s.accept, s.onPanic, logger)
	s.workers.RunWithRecover(s.watermarks, s.onPanic, logger)
	return s, nil
}

// Recorder supplies the immutable namespace factory; it is never attached late.
func (s *Service) Recorder() *observation.Recorder { return s.recorder }

func (s *Service) accept() {
	for s.ctx.Err() == nil {
		if err := s.listener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			break
		}
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			break
		}
		uid, err := transport.PeerUID(conn)
		if err != nil || uid != uint32(os.Geteuid()) {
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed || s.active != nil {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		s.active = conn
		// The active peer slot remains held until loss invalidation has completed.
		s.workers.RunWithRecover(func() { s.serve(conn) }, s.onPanic, s.logger)
		s.mu.Unlock()
	}
	if s.ctx.Err() == nil {
		s.recorder.InvalidateAll(observation.TransportLost)
	}
}
func (s *Service) watermarks() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.recorder.WatermarkOwners()
		}
	}
}
func (s *Service) onPanic(any) {
	s.recorder.InvalidateAll(observation.Malformed)
	s.cancel()
	_ = s.listener.Close()
	s.mu.Lock()
	if s.active != nil {
		_ = s.active.Close()
	}
	s.mu.Unlock()
}
func (s *Service) serve(conn *net.UnixConn) {
	ctx, cancel := context.WithCancel(s.ctx)
	var reader waitgroup.WaitGroup
	defer func() {
		cancel()
		_ = conn.Close()
		reader.Wait()
		s.recorder.InvalidateAll(observation.TransportLost)
		s.mu.Lock()
		s.active = nil
		s.mu.Unlock()
	}()
	reader.RunWithRecover(func() { defer cancel(); var unexpected [1]byte; _, _ = conn.Read(unexpected[:]) }, func(any) { cancel() }, s.logger)
	err := s.write(ctx, conn)
	if err != nil && s.ctx.Err() == nil {
		s.logger.Warn("routing lifecycle observation interval lost", zap.Error(err), zap.Bool("lifecycle_only", true))
	}
}
func (s *Service) write(ctx context.Context, conn *net.UnixConn) error {
	coverage, err := EncodeCoverage(s.process, s.nonce)
	if err != nil {
		return err
	}
	if err = writeFrame(conn, coverage); err != nil {
		return err
	}
	sent := make(map[observation.Epoch]observation.InvalidSummary)
	for {
		for _, summary := range s.recorder.InvalidOwners() {
			if previous, ok := sent[summary.Epoch]; ok && previous == summary {
				continue
			}
			frame, err := EncodeInvalid(summary)
			if err != nil {
				return err
			}
			if err = writeFrame(conn, frame); err != nil {
				return err
			}
			sent[summary.Epoch] = summary
		}
		delivery, err := s.recorder.NextOrChanged(ctx)
		if err != nil {
			return err
		}
		if delivery == nil {
			continue
		}
		if s.recorder.IsInvalid(delivery.Record.Epoch) {
			delivery.Release()
			continue
		}
		frame, err := EncodeRecord(delivery.Record)
		if err == nil {
			err = writeFrame(conn, frame)
		}
		delivery.Release()
		if err != nil {
			return err
		}
	}
}
func writeFrame(conn *net.UnixConn, frame []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		return err
	}
	n, err := conn.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

// Close fences acceptance, invalidates unfinished owners, cancels and joins all
// tasks, then releases the retained journal. No synthetic clean end is emitted.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		_ = s.listener.Close()
		if s.active != nil {
			_ = s.active.Close()
		}
		s.mu.Unlock()
		s.recorder.InvalidateAll(observation.Shutdown)
		s.workers.Wait()
		s.recorder.Close()
		path := s.listener.Addr().String()
		if info, err := os.Lstat(path); err == nil && os.SameFile(info, s.socketInfo) {
			if err = os.Remove(path); err != nil {
				s.logger.Warn("remove routing observation socket", zap.Error(fmt.Errorf("unlink owned socket: %w", err)))
			}
		}
	})
}
