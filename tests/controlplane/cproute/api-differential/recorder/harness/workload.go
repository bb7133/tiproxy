// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Workload drives real MySQL connection lifecycles through the recorded proxy
// listener: connect → SELECT 1 → close, from `clients` concurrent clients, each
// optionally bound to a loopback source address (CIDR families). Every
// lifecycle is one recorded open/next/finish/close sequence.
type Workload struct {
	Listener  string   // proxy listener host:port
	Sources   []string // loopback source IPs to bind (round-robin); empty = default
	Clients   int
	Pause     time.Duration
	User      string
	completed atomic.Int64
	failed    atomic.Int64
}

func (w *Workload) Completed() int64 { return w.completed.Load() }
func (w *Workload) Failed() int64    { return w.failed.Load() }

func (w *Workload) connector(source string) (driver.Connector, error) {
	cfg := mysql.NewConfig()
	cfg.User = w.User
	cfg.Net = "tcp"
	cfg.Addr = w.Listener
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	if source != "" {
		d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		mysql.RegisterDialContext("rec-"+source, func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) })
		cfg.Net = "rec-" + source
	}
	return mysql.NewConnector(cfg)
}

// Run drives the clients until ctx ends.
func (w *Workload) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < w.Clients; i++ {
		source := ""
		if len(w.Sources) > 0 {
			source = w.Sources[i%len(w.Sources)]
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if err := w.once(ctx, source); err != nil {
					w.failed.Add(1)
				} else {
					w.completed.Add(1)
				}
				select {
				case <-ctx.Done():
				case <-time.After(w.Pause):
				}
			}
		}()
	}
	wg.Wait()
}

func (w *Workload) once(ctx context.Context, source string) error {
	c, err := w.connector(source)
	if err != nil {
		return err
	}
	db := sql.OpenDB(c)
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
