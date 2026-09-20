// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command go-prune rotates a lumberjack log file exactly as TiProxy's Go
// logger does (LocalTime: true) and reports which backups survive the
// max-days/max-backups pruning. It is the oracle for the Rust log rotation
// parity check under an explicit TZ.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go-prune LOG_FILE MAX_DAYS MAX_BACKUPS")
		os.Exit(2)
	}
	maxDays, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	maxBackups, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := &lumberjack.Logger{
		Filename:   os.Args[1],
		MaxSize:    300,
		MaxBackups: maxBackups,
		MaxAge:     maxDays,
		LocalTime:  true,
	}
	if _, err := logger.Write([]byte("probe\n")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := logger.Rotate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// lumberjack prunes on a background goroutine; give it time to settle.
	time.Sleep(500 * time.Millisecond)
	if err := logger.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	entries, err := os.ReadDir(filepath.Dir(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}
