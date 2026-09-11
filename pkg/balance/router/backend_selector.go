// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
)

type ClientInfo struct {
	ClientAddr net.Addr
	ProxyAddr  net.Addr
	// ListenerPort is the SQL listener port that accepted the connection.
	ListenerPort string
	// TODO: username, database, etc.
}

type BackendSelector struct {
	selectionCapture *selectionObservation // Private construction only; no live attachment.
	excluded         []BackendInst
	cur              BackendInst
	routeOnce        func(excluded []BackendInst) (BackendInst, error)
	onCreate         func(backend BackendInst, conn RedirectableConn, succeed bool)
	closeObservation func()
}

func (bs *BackendSelector) Next() (BackendInst, error) {
	bs.selectorBoundary(observation.SelectorBegin, nil, nil)
	backend, err := bs.routeOnce(bs.excluded)
	// If all backends are enumerated, reset and try again.
	if err == ErrNoBackend && len(bs.excluded) > 0 {
		bs.excluded = bs.excluded[:0]
		backend, err = bs.routeOnce(bs.excluded)
	}
	if err != nil {
		bs.selectorBoundary(observation.SelectorEnd, backend, err)
		return backend, err
	}
	bs.cur = backend
	bs.excluded = append(bs.excluded, backend)
	bs.selectorBoundary(observation.SelectorEnd, backend, nil)
	return backend, nil
}

func (bs *BackendSelector) Finish(conn RedirectableConn, succeed bool) {
	bs.onCreate(bs.cur, conn, succeed)
}

// CloseObservation records the real end of selection without changing routing
// or accounting. Finish remains the only creation-result/accounting callback.
func (bs *BackendSelector) CloseObservation() {
	captureClose := bs.selectionCapture != nil && !bs.selectionCapture.ended
	if bs.closeObservation != nil {
		bs.closeObservation()
	}
	if captureClose {
		bs.selectorBoundary(observation.SelectorClose, nil, nil)
	}
}
