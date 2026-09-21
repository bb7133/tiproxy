// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// serverinfo-probe prints the `ServerInfo` answers of the production Go
// diagnostics service (pingcap/sysutil) for every request type as JSON, so the
// Rust port can be checked against the real item inventory of the host.
package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/pingcap/kvproto/pkg/diagnosticspb"
	"github.com/pingcap/sysutil"
)

type pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type item struct {
	Tp    string `json:"tp"`
	Name  string `json:"name"`
	Pairs []pair `json:"pairs"`
}

func main() {
	server := sysutil.NewDiagnosticsServer("")
	out := map[string][]item{}
	for name, tp := range map[string]diagnosticspb.ServerInfoType{
		"all":      diagnosticspb.ServerInfoType_All,
		"hardware": diagnosticspb.ServerInfoType_HardwareInfo,
		"system":   diagnosticspb.ServerInfoType_SystemInfo,
		"load":     diagnosticspb.ServerInfoType_LoadInfo,
	} {
		resp, err := server.ServerInfo(context.Background(), &diagnosticspb.ServerInfoRequest{Tp: tp})
		if err != nil {
			panic(err)
		}
		items := make([]item, 0, len(resp.Items))
		for _, it := range resp.Items {
			pairs := make([]pair, 0, len(it.Pairs))
			for _, p := range it.Pairs {
				pairs = append(pairs, pair{Key: p.Key, Value: p.Value})
			}
			items = append(items, item{Tp: it.Tp, Name: it.Name, Pairs: pairs})
		}
		out[name] = items
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}
