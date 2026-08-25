// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

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
	var credential *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return peerCredential{}, err
	}
	if socketErr != nil {
		return peerCredential{}, socketErr
	}
	var gid uint32
	if credential.Ngroups > 0 {
		gid = credential.Groups[0]
	}
	return peerCredential{UID: credential.Uid, GID: gid}, nil
}
