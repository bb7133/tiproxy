// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// This fixture generator uses the production Go native capture encoder.
// Run from the repository root:
// go run ./tests/dataplane/capture-format > tests/dataplane/capture-format/native-v1.log
package main

import (
	"bytes"
	"os"
	"time"

	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"github.com/pingcap/tiproxy/pkg/sqlreplay/cmd"
)

func main() {
	zone := time.FixedZone("fixture", 8*3600+10*60)
	start := time.Date(2024, 8, 28, 18, 51, 20, 477067001, zone)
	preparedText := "select '中文'\n\"x\"\x00"
	query := cmd.NewCommand(append([]byte{pnet.ComQuery.Byte()}, []byte("SELECT 1\nSELECT 2")...), start, 100)
	prepare := cmd.NewCommand(append([]byte{pnet.ComStmtPrepare.Byte()}, []byte("SELECT ?\n")...), start.Add(time.Second), 100)
	prepare.CapturedPsID = 37
	prepare.PreparedStmt = preparedText
	execute := cmd.NewCommand([]byte{pnet.ComStmtExecute.Byte(), 37, 0, 0, 0, 0, 1, 0xff, '\n'}, start.Add(2*time.Second), 100)
	execute.CapturedPsID = 37
	execute.PreparedStmt = preparedText
	reset := cmd.NewCommand([]byte{pnet.ComResetConnection.Byte()}, start.Add(3*time.Second), 100)
	reset.Success = false
	quit := cmd.NewCommand([]byte{pnet.ComQuit.Byte()}, start.Add(4*time.Second), 100)
	var output bytes.Buffer
	encoder := cmd.NewNativeEncoder()
	for _, record := range []*cmd.Command{query, prepare, execute, reset, quit} {
		if err := encoder.Encode(record, &output); err != nil {
			panic(err)
		}
	}
	if _, err := os.Stdout.Write(output.Bytes()); err != nil {
		panic(err)
	}
}
