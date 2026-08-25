// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package transport

import (
	"errors"
	"net"
)

type peerCredential struct {
	UID uint32
	GID uint32
	PID int32
}

func readPeerCredential(*net.UnixConn) (peerCredential, error) {
	return peerCredential{}, errors.New("control peer credentials are unsupported on this platform")
}
