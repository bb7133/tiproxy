// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pingcap/tiproxy/tests/dataplane/corpus/internal/corpus"
)

func main() {
	mode := flag.String("mode", "validate", "operation: generate, validate, check, compare, or expected")
	dir := flag.String("dir", "tests/dataplane/corpus/v1", "corpus version directory")
	observed := flag.String("observed", "", "observation JSON for compare mode")
	implementation := flag.String("implementation", "go-oracle", "implementation name for expected mode")
	flag.Parse()

	var err error
	switch *mode {
	case "generate":
		err = corpus.Write(*dir)
	case "validate":
		err = corpus.Validate(*dir)
	case "check":
		err = corpus.Validate(*dir)
		if err == nil {
			err = corpus.CheckGenerated(*dir)
		}
	case "compare":
		if *observed == "" {
			err = fmt.Errorf("-observed is required in compare mode")
			break
		}
		var manifest corpus.Manifest
		manifest, err = corpus.ReadManifest(*dir)
		if err != nil {
			break
		}
		var data []byte
		data, err = os.ReadFile(*observed)
		if err != nil {
			break
		}
		var observations corpus.ObservationSet
		if err = json.Unmarshal(data, &observations); err == nil {
			err = corpus.Compare(manifest, observations)
		}
	case "expected":
		var manifest corpus.Manifest
		manifest, err = corpus.ReadManifest(*dir)
		if err != nil {
			break
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(corpus.ExpectedObservations(manifest, *implementation))
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
