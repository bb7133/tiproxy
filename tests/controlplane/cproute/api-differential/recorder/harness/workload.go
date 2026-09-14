// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pingcap/tiproxy/lib/util/waitgroup"
)

var heldDialCounter atomic.Uint64

// Workload drives real MySQL connection lifecycles through the recorded proxy
// listeners: connect → SELECT 1 → close, from `clients` concurrent clients,
// each optionally bound to a loopback source address (CIDR families). Every
// lifecycle is one recorded open/next/finish/close sequence. HeldClients adds
// supplemental long-lived sessions so failover scripts can exercise real
// redirect and force-close callbacks while the lifecycle workload continues.
type Workload struct {
	Listener    string   // legacy single listener; ignored when Listeners is nonempty
	Listeners   []string // proxy listener host:ports
	Sources     []string // loopback source IPs; empty = default
	Clients     int
	HeldClients int
	Pause       time.Duration
	User        string
	completed   atomic.Int64
	failed      atomic.Int64
	heldQueries atomic.Int64
	heldFailed  atomic.Int64
	heldMu      sync.Mutex
	heldHistory map[string][]*heldInterval
}

// LifecycleConnection is one real MySQL client kept open across the recorder's
// router Close/new/Rehydrate action. It is separate from the qualifying
// workload counters and closes through the ordinary proxy callback path.
type LifecycleConnection struct {
	db   *sql.DB
	conn *sql.Conn
}

// OpenLifecycleConnection establishes and proves one real SELECT 1 session,
// then retains its physical connection until Close.
func (w *Workload) OpenLifecycleConnection(ctx context.Context, listener, source string) (*LifecycleConnection, error) {
	connector, err := w.connector(listener, source, false)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	var one int
	if err = conn.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		_ = conn.Close()
		_ = db.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected SELECT 1 result %d", one)
	}
	return &LifecycleConnection{db: db, conn: conn}, nil
}

// Close releases the retained client and joins its ordinary SQL lifetime.
func (c *LifecycleConnection) Close() error {
	if c == nil {
		return nil
	}
	return errors.Join(c.conn.Close(), c.db.Close())
}

func (w *Workload) Completed() int64   { return w.completed.Load() }
func (w *Workload) Failed() int64      { return w.failed.Load() }
func (w *Workload) HeldQueries() int64 { return w.heldQueries.Load() }
func (w *Workload) HeldFailed() int64  { return w.heldFailed.Load() }

// IsHeldClientAt reports whether address belonged to a held connection when
// the recorder observed a session open. Each interval begins before DialContext
// so a proxy accept that races the dial callback is still classified, and ends
// at client Close so later reuse of the same ephemeral port is not classified.
func (w *Workload) IsHeldClientAt(address string, openedAt time.Time) bool {
	w.heldMu.Lock()
	defer w.heldMu.Unlock()
	for _, interval := range w.heldHistory[address] {
		if openedAt.Before(interval.start) {
			continue
		}
		if interval.end.IsZero() || openedAt.Before(interval.end) {
			return true
		}
	}
	return false
}

func (w *Workload) trackHeldConnection(conn net.Conn, startedAt time.Time) net.Conn {
	address := conn.LocalAddr().String()
	interval := &heldInterval{start: startedAt}
	w.heldMu.Lock()
	if w.heldHistory == nil {
		w.heldHistory = make(map[string][]*heldInterval)
	}
	w.heldHistory[address] = append(w.heldHistory[address], interval)
	w.heldMu.Unlock()
	return &heldConnection{Conn: conn, release: func() {
		w.heldMu.Lock()
		defer w.heldMu.Unlock()
		interval.end = time.Now()
	}}
}

type heldInterval struct {
	start time.Time
	end   time.Time
}

type heldConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *heldConnection) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func (w *Workload) connector(listener, source string, held bool) (driver.Connector, error) {
	cfg := mysql.NewConfig()
	cfg.User = w.User
	cfg.Net = "tcp"
	cfg.Addr = listener
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	d := &net.Dialer{Timeout: 5 * time.Second}
	if source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	if held {
		network := fmt.Sprintf("rec-held-%d", heldDialCounter.Add(1))
		mysql.RegisterDialContext(network, func(ctx context.Context, addr string) (net.Conn, error) {
			startedAt := time.Now()
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn = w.trackHeldConnection(conn, startedAt)
			}
			return conn, err
		})
		cfg.Net = network
	} else if source != "" {
		mysql.RegisterDialContext("rec-"+source, func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) })
		cfg.Net = "rec-" + source
	}
	return mysql.NewConnector(cfg)
}

// Run drives the clients until ctx ends.
func (w *Workload) Run(ctx context.Context) {
	var wg waitgroup.WaitGroup
	for i := 0; i < w.Clients; i++ {
		listener, source := w.target(i)
		wg.Run(func() {
			connector, err := w.connector(listener, source, false)
			if err != nil {
				w.failed.Add(1)
				return
			}
			for ctx.Err() == nil {
				if err := w.once(ctx, connector); err != nil {
					w.failed.Add(1)
				} else {
					w.completed.Add(1)
				}
				select {
				case <-ctx.Done():
				case <-time.After(w.Pause):
				}
			}
		})
	}
	for i := 0; i < w.HeldClients; i++ {
		listener, source := w.target(i)
		wg.Run(func() {
			connector, err := w.connector(listener, source, true)
			if err != nil {
				w.heldFailed.Add(1)
				return
			}
			w.hold(ctx, connector)
		})
	}
	wg.Wait()
}

func (w *Workload) target(i int) (listener, source string) {
	listeners := w.Listeners
	if len(listeners) == 0 && w.Listener != "" {
		listeners = []string{w.Listener}
	}
	if len(listeners) == 0 {
		return "", ""
	}
	listenerIndex := i
	if len(w.Sources) > 0 {
		source = w.Sources[i%len(w.Sources)]
		listenerIndex = i / len(w.Sources)
	}
	return listeners[listenerIndex%len(listeners)], source
}

func (w *Workload) once(ctx context.Context, connector driver.Connector) error {
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return err
	}
	if one != 1 {
		return fmt.Errorf("unexpected SELECT 1 result %d", one)
	}
	return nil
}

func (w *Workload) hold(ctx context.Context, connector driver.Connector) {
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	pause := w.Pause
	if pause < 200*time.Millisecond {
		pause = 200 * time.Millisecond
	}
	for ctx.Err() == nil {
		var one int
		err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
		if err == nil && one == 1 {
			w.heldQueries.Add(1)
		} else if ctx.Err() == nil {
			w.heldFailed.Add(1)
		}
		select {
		case <-ctx.Done():
		case <-time.After(pause):
		}
	}
}
