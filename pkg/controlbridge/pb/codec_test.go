// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlpb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestDecodeRustGolden(t *testing.T) {
	golden, err := os.ReadFile("../../../proto/dataplane/v1/testdata/rust-snapshot.frame")
	require.NoError(t, err)
	envelope, err := ReadFrame(bytes.NewReader(golden), DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.Equal(t, uint64(11), envelope.GetGeneration())
	require.Equal(t, "backend-1", envelope.GetStateSnapshot().GetBackends()[0].GetBackendId())
	encoded, err := MarshalFrame(envelope, DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.Equal(t, golden, encoded)
}

func TestFrameBoundsAndPartialIO(t *testing.T) {
	envelope := &ControlEnvelope{
		ProtocolVersion: ProtocolV1,
		Priority:        Priority(math.MaxInt32),
		Body: &ControlEnvelope_Error{Error: &ProtocolError{
			Code:   ErrorCode_ERROR_CODE_INTERNAL,
			Detail: strings.Repeat("x", 64*1024),
		}},
	}
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	require.NoError(t, err)
	frame, err := MarshalFrame(envelope, uint32(len(body)))
	require.NoError(t, err)
	_, err = MarshalFrame(envelope, uint32(len(body)-1))
	var sizeErr *FrameSizeError
	require.ErrorAs(t, err, &sizeErr)

	writer := newChunkWriter(3)
	require.NoError(t, WriteFrame(writer, envelope, uint32(len(body))))
	require.Equal(t, frame, writer.Bytes())
	decoded, err := ReadFrame(&chunkReader{reader: bytes.NewReader(frame), chunk: 2}, uint32(len(body)))
	require.NoError(t, err)
	require.Equal(t, int32(math.MaxInt32), int32(decoded.GetPriority()))

	oversizedPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(oversizedPrefix, DefaultMaxFrameBytes+1)
	_, err = ReadFrame(bytes.NewReader(oversizedPrefix), DefaultMaxFrameBytes)
	require.ErrorAs(t, err, &sizeErr)

	emptyFields := &ControlEnvelope{ProtocolVersion: ProtocolV1}
	frame, err = MarshalFrame(emptyFields, DefaultMaxFrameBytes)
	require.NoError(t, err)
	_, err = ReadFrame(bytes.NewReader(frame), DefaultMaxFrameBytes)
	require.NoError(t, err)
}

func TestUnknownOptionalFieldAndRequiredCapability(t *testing.T) {
	frame, err := MarshalFrame(&ControlEnvelope{
		ProtocolVersion: ProtocolV1,
		Body: &ControlEnvelope_Hello{Hello: &Hello{
			SupportedVersions: []uint32{ProtocolV1},
			Capabilities:      []uint64{1, 3, 5},
		}},
	}, DefaultMaxFrameBytes)
	require.NoError(t, err)
	body := append([]byte(nil), frame[4:]...)
	body = protowire.AppendTag(body, 123, protowire.VarintType)
	body = protowire.AppendVarint(body, 77)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	frame = append(frame[:4], body...)
	decoded, err := ReadFrame(bytes.NewReader(frame), DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.NotEmpty(t, decoded.ProtoReflect().GetUnknown())

	local := &Hello{SupportedVersions: []uint32{ProtocolV1}, Capabilities: []uint64{1, 3}}
	remote := &Hello{SupportedVersions: []uint32{ProtocolV1}, Capabilities: []uint64{3, 5}}
	ack, err := NegotiateHello(local, remote, []uint64{3}, 9)
	require.NoError(t, err)
	require.Equal(t, []uint64{3}, ack.GetNegotiatedCapabilities())
	_, err = NegotiateHello(local, remote, []uint64{7}, 9)
	require.ErrorIs(t, err, ErrMissingCapability)
	_, err = NegotiateHello(local, &Hello{SupportedVersions: []uint32{2}}, nil, 9)
	require.ErrorIs(t, err, ErrUnsupportedVersion)
}

type chunkReader struct {
	reader *bytes.Reader
	chunk  int
}

func (reader *chunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.chunk {
		buffer = buffer[:reader.chunk]
	}
	return reader.reader.Read(buffer)
}

type chunkWriter struct {
	bytes.Buffer
	chunk int
}

func newChunkWriter(chunk int) *chunkWriter {
	return &chunkWriter{chunk: chunk}
}

func (writer *chunkWriter) Write(buffer []byte) (int, error) {
	if writer.chunk <= 0 {
		return 0, errors.New("invalid chunk size")
	}
	if len(buffer) > writer.chunk {
		buffer = buffer[:writer.chunk]
	}
	return writer.Buffer.Write(buffer)
}
