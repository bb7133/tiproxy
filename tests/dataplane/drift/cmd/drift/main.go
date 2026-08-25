// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pingcap/tiproxy/tests/dataplane/drift/internal/drift"
)

func main() {
	mode := flag.String("mode", "check", "output mode: check, report, or hashes")
	base := flag.String("base", "", "base Git revision")
	head := flag.String("head", "HEAD", "head Git revision")
	policy := flag.String("policy", "", "watch policy path (defaults to the repository policy)")
	flag.Parse()

	result, err := drift.Check(context.Background(), drift.Options{
		RepoDir:    ".",
		BaseRef:    *base,
		HeadRef:    *head,
		PolicyPath: *policy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "parity drift check failed: %v\n", err)
		os.Exit(2)
	}

	switch *mode {
	case "check":
		fmt.Println(result.CheckOutput())
	case "report":
		fmt.Print(result.MarkdownReport())
	case "hashes":
		inventory, err := result.HashInventory()
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode hash inventory: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(inventory)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (want check, report, or hashes)\n", *mode)
		os.Exit(2)
	}
	if result.HasDrift() {
		os.Exit(1)
	}
}
