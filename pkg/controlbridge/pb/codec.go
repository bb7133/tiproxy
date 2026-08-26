// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlpb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"google.golang.org/protobuf/proto"
)

const (
	// ProtocolV1 is the first production Go/Rust control protocol.
	ProtocolV1 uint32 = 1
	// DefaultMaxFrameBytes is both the v1 default and hard frame limit.
	DefaultMaxFrameBytes uint32 = 1024 * 1024
)

var (
	// ErrEmptyFrame indicates a zero-length record.
	ErrEmptyFrame = errors.New("empty control frame")
	// ErrUnsupportedVersion indicates that Hello peers have no common version.
	ErrUnsupportedVersion = errors.New("no common control protocol version")
	// ErrMissingCapability indicates an absent required remote capability.
	ErrMissingCapability = errors.New("missing required control capability")
)

// FrameSizeError reports an input that exceeds its negotiated limit.
type FrameSizeError struct {
	Length uint64
	Limit  uint32
}

func (err *FrameSizeError) Error() string {
	return fmt.Sprintf("control frame size %d exceeds limit %d", err.Length, err.Limit)
}

// MarshalFrame deterministically encodes one length-prefixed envelope.
func MarshalFrame(envelope *ControlEnvelope, limit uint32) ([]byte, error) {
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal control envelope: %w", err)
	}
	if len(body) == 0 {
		return nil, ErrEmptyFrame
	}
	limit = normalizeLimit(limit)
	if uint64(len(body)) > uint64(limit) {
		return nil, &FrameSizeError{Length: uint64(len(body)), Limit: limit}
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}

// ReadFrame reads exactly one framed envelope without allocating an oversized body.
func ReadFrame(reader io.Reader, limit uint32) (*ControlEnvelope, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, fmt.Errorf("read control frame prefix: %w", err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 {
		return nil, ErrEmptyFrame
	}
	limit = normalizeLimit(limit)
	if length > limit {
		return nil, &FrameSizeError{Length: uint64(length), Limit: limit}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, fmt.Errorf("read control frame body: %w", err)
	}
	envelope := new(ControlEnvelope)
	if err := proto.Unmarshal(body, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal control envelope: %w", err)
	}
	return envelope, nil
}

// WriteFrame writes a complete frame even when writer accepts partial chunks.
func WriteFrame(writer io.Writer, envelope *ControlEnvelope, limit uint32) error {
	frame, err := MarshalFrame(envelope, limit)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		written, writeErr := writer.Write(frame)
		if writeErr != nil {
			return fmt.Errorf("write control frame: %w", writeErr)
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}

// NegotiateHello selects v1 and the sorted intersection of capabilities.
func NegotiateHello(local, remote *Hello, requiredRemoteCapabilities []uint64, controlEpoch uint64) (*HelloAck, error) {
	if !slices.Contains(local.GetSupportedVersions(), ProtocolV1) ||
		!slices.Contains(remote.GetSupportedVersions(), ProtocolV1) {
		return nil, ErrUnsupportedVersion
	}
	remoteCapabilities := make(map[uint64]struct{}, len(remote.GetCapabilities()))
	for _, capability := range remote.GetCapabilities() {
		remoteCapabilities[capability] = struct{}{}
	}
	for _, capability := range requiredRemoteCapabilities {
		if _, ok := remoteCapabilities[capability]; !ok {
			return nil, fmt.Errorf("%w: %d", ErrMissingCapability, capability)
		}
	}
	localCapabilities := make(map[uint64]struct{}, len(local.GetCapabilities()))
	for _, capability := range local.GetCapabilities() {
		localCapabilities[capability] = struct{}{}
	}
	negotiated := make([]uint64, 0, min(len(localCapabilities), len(remoteCapabilities)))
	for capability := range localCapabilities {
		if _, ok := remoteCapabilities[capability]; ok {
			negotiated = append(negotiated, capability)
		}
	}
	slices.Sort(negotiated)
	// Capability closure: RECONCILE_SESSION_REHYDRATION (3) extends the
	// reconcile exchange and must not be negotiated without
	// RECONCILE_CONNECTIONS (2).
	if slices.Contains(negotiated, uint64(3)) && !slices.Contains(negotiated, uint64(2)) {
		return nil, fmt.Errorf("%w: capability 3 requires capability 2", ErrMissingCapability)
	}
	return &HelloAck{
		SelectedVersion:        ProtocolV1,
		NegotiatedCapabilities: negotiated,
		MaxFrameBytes:          min(normalizeLimit(local.GetMaxFrameBytes()), normalizeLimit(remote.GetMaxFrameBytes())),
		ControlEpoch:           controlEpoch,
		RejectionCode:          ErrorCode_ERROR_CODE_OK,
	}, nil
}

func normalizeLimit(limit uint32) uint32 {
	if limit == 0 {
		return DefaultMaxFrameBytes
	}
	return min(limit, DefaultMaxFrameBytes)
}
