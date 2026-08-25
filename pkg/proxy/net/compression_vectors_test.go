// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"bytes"
	"encoding/hex"
	"io"
	stdnet "net"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func encodeGoCompressionVector(t *testing.T, algorithm CompressAlgorithm, level int, payload []byte) []byte {
	t.Helper()
	writerConn, readerConn := stdnet.Pipe()
	errCh := make(chan error, 1)
	go func() {
		writer := newCompressedReadWriter(newBasicReadWriter(writerConn, DefaultConnBufferSize), algorithm, level, zap.NewNop())
		writer.BeginRW(rwWrite)
		if _, err := writer.Write(payload); err != nil {
			errCh <- err
			_ = writer.Close()
			return
		}
		if err := writer.Flush(); err != nil {
			errCh <- err
			_ = writer.Close()
			return
		}
		errCh <- writer.Close()
	}()
	wire, err := io.ReadAll(readerConn)
	require.NoError(t, err)
	require.NoError(t, readerConn.Close())
	require.NoError(t, <-errCh)
	return wire
}

func decodeGoCompressionVector(t *testing.T, algorithm CompressAlgorithm, level int, frame []byte, payloadLen int) []byte {
	t.Helper()
	writerConn, readerConn := stdnet.Pipe()
	errCh := make(chan error, 1)
	go func() {
		_, err := writerConn.Write(frame)
		if err == nil {
			err = writerConn.Close()
		} else {
			_ = writerConn.Close()
		}
		errCh <- err
	}()
	reader := newCompressedReadWriter(newBasicReadWriter(readerConn, DefaultConnBufferSize), algorithm, level, zap.NewNop())
	reader.BeginRW(rwRead)
	payload := make([]byte, payloadLen)
	_, err := io.ReadFull(reader, payload)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.NoError(t, <-errCh)
	return payload
}

func mustDecodeCompressionHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	require.NoError(t, err)
	return decoded
}

// TestCompressionGoldenVectors freezes both encoders and proves that each
// production decoder accepts the other implementation's frame.
func TestCompressionGoldenVectors(t *testing.T) {
	const (
		goZlibRaw49    = "3100000000000072727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272"
		goZlibLevel6   = "49000000000f00789c0ac90c28caafa8d475f60dd02d4b4d2ec92fd23530343236313533b7b0b41e951d951d951d951d951d951d951d951d951d951d951d951d951d951d1eb280000000ffff39b890bd"
		goZstd         = "36000000000f0028b52ffd64000e450100e401546950726f78792d434d502d766563746f722d303132333435363738393b015415052f7e3b04e2c82b7e"
		rustZlibRaw49  = goZlibRaw49
		rustZlibLevel6 = "44000000000f00789cedc94b0a40111480e1159dbaef4b86c6cac00e6460a424b17bfbd03ffe42f6b58c29d679e929b652e538affb79bf5f691350144551144551144551740b5d39b890bd"
		rustZstd       = "30000000000f0028b52ffd60000e350100f0546950726f78792d434d502d766563746f722d303132333435363738393b01007e3bf8ca09"
	)
	raw := bytes.Repeat([]byte{'r'}, minCompressSize-1)
	compressed := bytes.Repeat([]byte("TiProxy-CMP-vector-0123456789;"), 128)
	cases := []struct {
		name      string
		algorithm CompressAlgorithm
		level     int
		payload   []byte
		goHex     string
		rustHex   string
	}{
		{name: "zlib-raw-49", algorithm: CompressionZlib, payload: raw, goHex: goZlibRaw49, rustHex: rustZlibRaw49},
		{name: "zlib-level-6", algorithm: CompressionZlib, payload: compressed, goHex: goZlibLevel6, rustHex: rustZlibLevel6},
		{name: "zstd-level-1", algorithm: CompressionZstd, level: 1, payload: compressed, goHex: goZstd, rustHex: rustZstd},
		{name: "zstd-level-3", algorithm: CompressionZstd, level: 3, payload: compressed, goHex: goZstd, rustHex: rustZstd},
		{name: "zstd-level-9", algorithm: CompressionZstd, level: 9, payload: compressed, goHex: goZstd, rustHex: rustZstd},
		{name: "zstd-level-22", algorithm: CompressionZstd, level: 22, payload: compressed, goHex: goZstd, rustHex: rustZstd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goWire := encodeGoCompressionVector(t, tc.algorithm, tc.level, tc.payload)
			require.Equal(t, tc.goHex, hex.EncodeToString(goWire))
			rustWire := mustDecodeCompressionHex(t, tc.rustHex)
			require.Equal(t, tc.payload, decodeGoCompressionVector(t, tc.algorithm, tc.level, rustWire, len(tc.payload)))
		})
	}
}
