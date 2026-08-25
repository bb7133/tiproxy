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

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProxyV2HeaderIPv4(t *testing.T) {
	header, err := makeProxyV2Header(
		&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 4000},
	)
	require.NoError(t, err)
	require.Equal(t, proxyV2Signature[:], header[:12])
	require.Equal(t, byte(0x21), header[12])
	require.Equal(t, byte(0x11), header[13])
	require.Equal(t, uint16(12), binary.BigEndian.Uint16(header[14:16]))
	require.Equal(t, net.ParseIP("192.0.2.10").To4(), net.IP(header[16:20]))
	require.Equal(t, net.ParseIP("198.51.100.20").To4(), net.IP(header[20:24]))
	require.Equal(t, uint16(12345), binary.BigEndian.Uint16(header[24:26]))
	require.Equal(t, uint16(4000), binary.BigEndian.Uint16(header[26:28]))
}

func TestFaultProxyForwardsDropsAndReleasesPorts(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		for {
			conn, acceptErr := backend.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = backend.Close()
		<-backendDone
	})

	proxy := newFaultProxy(backend.Addr().String(), false, 0, log.New(io.Discard, "", 0))
	require.NoError(t, proxy.start("127.0.0.1:0", "127.0.0.1:0"))
	proxyAddr := proxy.listener.Addr().String()
	adminURL := "http://" + proxy.adminListen.Addr().String()

	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	require.NoError(t, err)
	_, err = conn.Write([]byte("select 1\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "select 1\n", line)
	require.NoError(t, conn.Close())

	request, err := http.NewRequest(http.MethodPost, adminURL+"/fault/drop-next", nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusNoContent, response.StatusCode)

	dropped, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	require.NoError(t, err)
	_, _ = dropped.Write([]byte("must be dropped"))
	_ = dropped.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 1)
	_, err = dropped.Read(data)
	require.Error(t, err)
	require.NoError(t, dropped.Close())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, proxy.close(ctx))

	rebound, err := net.Listen("tcp", proxyAddr)
	require.NoError(t, err, "traffic port leaked after shutdown")
	require.NoError(t, rebound.Close())
}

func TestProxyV2HeaderRejectsNonTCPAddresses(t *testing.T) {
	_, err := makeProxyV2Header(&net.UnixAddr{Name: "client", Net: "unix"}, &net.TCPAddr{})
	require.Error(t, err)
}

func TestHealthResponseContainsNoTargetCredentials(t *testing.T) {
	proxy := newFaultProxy("user:password@127.0.0.1:4000", false, 0, log.New(io.Discard, "", 0))
	recorder := &responseRecorder{header: make(http.Header)}
	request, err := http.NewRequest(http.MethodGet, "http://test/healthz", nil)
	require.NoError(t, err)
	proxy.handleHealth(recorder, request)
	require.Equal(t, http.StatusOK, recorder.statusCode())
	require.NotContains(t, recorder.body.String(), "password")
}

type responseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
}

func (r *responseRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
