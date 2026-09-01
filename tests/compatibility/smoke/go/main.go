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

// VAL-01 smoke adapter for the Go database/sql + go-sql-driver/mysql client.
//
// It runs exactly one workload per invocation against a live TiProxy SQL
// listener and exits 0 on success, non-zero on failure. It only asserts the
// CLIENT side (the operation succeeds and returns the expected value); the
// PROXY-side negotiation assertion (that TLS/compression was actually
// negotiated, never silently downgraded) is done by the orchestrator from the
// dataplane's connection-close log. This adapter never prints packet payloads.
//
// It deliberately requests only the capabilities go-sql-driver/mysql actually
// supports: zlib compression (via compress=true), no zstd — a driver that
// cannot request a capability is a driver limitation, not a proxy failure, so
// the matrix marks those cases non-blocking and the orchestrator does not run
// them here.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func main() {
	var (
		host       = flag.String("host", "127.0.0.1", "TiProxy SQL host")
		port       = flag.Int("port", 6000, "TiProxy SQL port")
		user       = flag.String("user", "root", "user")
		password   = flag.String("password", "", "password")
		database   = flag.String("database", "test", "database")
		caFile     = flag.String("ca-file", "", "CA cert PEM for TLS verification")
		serverName = flag.String("server-name", "", "TLS server name (SNI/verify)")
		attr       = flag.String("attr", "", "unique connection attribute value for log correlation")
		workload   = flag.String("workload", "", "connect|crud|tls|prepared|compress-zlib")
	)
	flag.Parse()

	if err := run(*host, *port, *user, *password, *database, *caFile, *serverName, *attr, *workload); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL go %s: %v\n", *workload, err)
		os.Exit(1)
	}
	fmt.Printf("PASS go %s\n", *workload)
}

func run(host string, port int, user, password, database, caFile, serverName, attr, workload string) error {
	// DSN parameters. go-sql-driver enables zlib via `compress=true` and TLS
	// via a registered `tls=<name>` config; both are DSN params, not exported
	// Config fields, so the smoke builds the DSN directly.
	params := url.Values{}
	params.Set("timeout", "15s")
	params.Set("readTimeout", "15s")
	params.Set("writeTimeout", "15s")
	// A unique per-case connection attribute, set for future
	// attribute-correlatable observability. The orchestrator currently
	// correlates POSITIONALLY (exactly one new connection_closed line in the
	// case's log window), because the dataplane close log does not yet echo
	// connection attributes.
	if attr != "" {
		params.Set("connectionAttributes", "tiproxy_smoke_case:"+attr)
	}

	switch workload {
	case "tls":
		if caFile == "" {
			return fmt.Errorf("tls workload requires --ca-file")
		}
		tlsName, err := registerTLS(caFile, serverName)
		if err != nil {
			return err
		}
		params.Set("tls", tlsName)
	case "compress-zlib":
		// go-sql-driver requests zlib via compress=true (it has no zstd).
		params.Set("compress", "true")
	case "connect", "crud", "prepared", "":
		// plaintext, no compression
	default:
		return fmt.Errorf("unknown workload %q", workload)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?%s",
		url.QueryEscape(user), url.QueryEscape(password), host, port,
		url.PathEscape(database), params.Encode())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect/auth: %w", err)
	}

	switch workload {
	case "connect", "tls", "compress-zlib":
		// A trivial round-trip proves the connection is usable end to end.
		var one int
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			return fmt.Errorf("select 1: %w", err)
		}
		if one != 1 {
			return fmt.Errorf("select 1 returned %d", one)
		}
	case "crud":
		return crud(ctx, db)
	case "prepared":
		return prepared(ctx, db)
	}
	return nil
}

// crud proves a full create/insert/select round-trip returns the exact value.
func crud(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "CREATE TEMPORARY TABLE tiproxy_smoke (id INT PRIMARY KEY, v VARCHAR(32))"); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO tiproxy_smoke (id, v) VALUES (1, 'hello')"); err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	var v string
	if err := db.QueryRowContext(ctx, "SELECT v FROM tiproxy_smoke WHERE id = 1").Scan(&v); err != nil {
		return fmt.Errorf("select: %w", err)
	}
	if v != "hello" {
		return fmt.Errorf("select returned %q, want hello", v)
	}
	return nil
}

// prepared proves a server-side prepared statement with a bound parameter
// (COM_STMT_PREPARE + COM_STMT_EXECUTE) round-trips the exact value.
func prepared(ctx context.Context, db *sql.DB) error {
	// interpolateParams stays false (the default) so the driver uses the
	// binary protocol, exercising COM_STMT_PREPARE/EXECUTE through the proxy.
	stmt, err := db.PrepareContext(ctx, "SELECT ? + ?")
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()
	var sum int
	if err := stmt.QueryRowContext(ctx, 40, 2).Scan(&sum); err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	if sum != 42 {
		return fmt.Errorf("prepared sum = %d, want 42", sum)
	}
	return nil
}

func registerTLS(caFile, serverName string) (string, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return "", fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return "", fmt.Errorf("ca file %s has no PEM certificate", caFile)
	}
	name := "tiproxy-smoke-verify"
	if err := mysqldriver.RegisterTLSConfig(name, &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}); err != nil {
		return "", fmt.Errorf("register tls: %w", err)
	}
	return name, nil
}
