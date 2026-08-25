// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"net"

	"golang.org/x/sys/unix"
)

type peerCredential struct {
	UID uint32
	GID uint32
	PID int32
}

func readPeerCredential(conn *net.UnixConn) (peerCredential, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return peerCredential{}, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peerCredential{}, err
	}
	if socketErr != nil {
		return peerCredential{}, socketErr
	}
	return peerCredential{UID: credential.Uid, GID: credential.Gid, PID: credential.Pid}, nil
}
