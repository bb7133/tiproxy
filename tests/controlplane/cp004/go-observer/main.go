// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// The CP-CFG/NS Go observation producer drives the production config model
// and ConfigManager. Rust emits the same semantic observations from
// control-config; the shared exact comparator rejects any drift.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/pingcap/tiproxy/lib/config"
	mgrcfg "github.com/pingcap/tiproxy/pkg/manager/config"
)

const partialTOML = `
[proxy]
max-connections = 23

[proxy.frontend-keepalive]
enabled = true
idle = "1h2m3.004s"
cnt = 7
intvl = "2500us"
timeout = "4.5s"

[log]
level = "warn"
`

func main() {
	if os.Getenv("CP004_DUMP_NAMESPACE") != "" {
		dumpNamespaces()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := mgrcfg.NewConfigManager()
	if err := manager.Init(ctx, "", ""); err != nil {
		panic(err)
	}
	defer manager.Close()
	mode := os.Getenv("CP004_DUMP_TOML")
	if mode == "partial" || mode == "full" {
		data := []byte(partialTOML)
		if mode == "full" {
			var err error
			data, err = os.ReadFile("tests/controlplane/cp004/testdata/full.toml")
			if err != nil {
				panic(err)
			}
		}
		if err := manager.SetTOMLConfig(data); err != nil {
			panic(err)
		}
	}
	data, err := manager.GetConfig().ToBytes()
	if err != nil {
		panic(err)
	}
	fmt.Print(string(data))
}

func dumpNamespaces() {
	values := [][]byte{
		[]byte(`{"namespace":"b","frontend":{"user":"user-b"},"backend":{"instances":["b:4000"]}}`),
		[]byte(`{"namespace":"a","frontend":{"user":"user-a","security":{"cert":"/cert","key":"/key","ca":"/ca","min-tls-version":"1.3","cert-allowed-cn":["b","a"],"auto-certs":true,"rsa-key-size":2048,"autocert-expire-duration":"24h","skip-ca":true}},"backend":{"instances":["a:4000"],"security":{"ca":"/backend-ca","min-tls-version":"1.2","skip-ca":true}}}`),
	}
	namespaces := make([]*config.Namespace, 0, len(values))
	for _, value := range values {
		var namespace config.Namespace
		if err := json.Unmarshal(value, &namespace); err != nil {
			panic(err)
		}
		namespaces = append(namespaces, &namespace)
	}
	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].Namespace < namespaces[j].Namespace
	})
	data, err := json.Marshal(namespaces)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(data))
}
