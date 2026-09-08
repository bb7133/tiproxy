// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import "net"

// PeerUID returns the OS-authenticated local socket peer, for independently
// permission-checked observation channels using the same platform credential API.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	credential, err := readPeerCredential(conn)
	return credential.UID, err
}
