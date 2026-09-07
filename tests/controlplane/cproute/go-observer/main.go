// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// The CP-ROUTE Go observation producer drives the production config manager
// and namespace model. Rust emits the same normalized routing projection; an
// exact comparator rejects drift before routing ownership moves.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pingcap/tiproxy/lib/config"
	mgrcfg "github.com/pingcap/tiproxy/pkg/manager/config"
)

type pair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type factor struct {
	MigrationsPerSecond string `json:"migrations_per_second"`
}

type connectionFactor struct {
	MigrationsPerSecond string `json:"migrations_per_second"`
	CountRatioThreshold string `json:"count_ratio_threshold"`
}

type routingConfig struct {
	LabelName              string           `json:"label_name"`
	RoutingRule            string           `json:"routing_rule"`
	BalancePolicy          string           `json:"balance_policy"`
	SelectionPolicy        string           `json:"selection_policy"`
	Status                 factor           `json:"status"`
	Health                 factor           `json:"health"`
	Memory                 factor           `json:"memory"`
	CPU                    factor           `json:"cpu"`
	Location               factor           `json:"location"`
	Connection             connectionFactor `json:"connection"`
	ProxyLabels            []pair           `json:"proxy_labels"`
	FailedBackends         []string         `json:"failed_backends"`
	FailoverTimeoutSeconds uint64           `json:"failover_timeout_seconds"`
}

type tlsConfig struct {
	CAPath             string   `json:"ca_path"`
	CertificatePath    string   `json:"certificate_path"`
	PrivateKeyPath     string   `json:"private_key_path"`
	MinimumVersion     string   `json:"minimum_version"`
	SkipCAVerification bool     `json:"skip_ca_verification"`
	AllowedCommonNames []string `json:"allowed_common_names"`
}

type routingNamespace struct {
	Name             string    `json:"name"`
	Users            []string  `json:"users"`
	BackendInstances []string  `json:"backend_instances"`
	BackendTLS       tlsConfig `json:"backend_tls"`
}

type observation struct {
	Config     routingConfig      `json:"config"`
	Namespaces []routingNamespace `json:"namespaces"`
}

func number(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

func rule(value string) string {
	switch value {
	case "":
		return "match_all"
	case config.MatchClientCIDRStr:
		return "client_cidr"
	case config.MatchProxyCIDRStr:
		return "proxy_cidr"
	case config.MatchPortStr:
		return "listener_port"
	default:
		panic("unvalidated routing rule")
	}
}

func normalizedNames(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[strings.TrimSpace(value)] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func projectTLS(value config.TLSConfig) tlsConfig {
	return tlsConfig{
		CAPath:             value.CA,
		CertificatePath:    value.Cert,
		PrivateKeyPath:     value.Key,
		MinimumVersion:     value.MinTLSVersion,
		SkipCAVerification: value.SkipCA,
		AllowedCommonNames: normalizedNames(value.CertAllowedCN),
	}
}

func projectConfig(value *config.Config) routingConfig {
	labels := make([]pair, 0, len(value.Labels))
	for name, label := range value.Labels {
		labels = append(labels, pair{Name: name, Value: label})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
	return routingConfig{
		LabelName:       value.Balance.LabelName,
		RoutingRule:     rule(value.Balance.RoutingRule),
		BalancePolicy:   value.Balance.Policy,
		SelectionPolicy: value.Balance.RoutingPolicy,
		Status:          factor{number(value.Balance.Status.MigrationsPerSecond)},
		Health:          factor{number(value.Balance.Health.MigrationsPerSecond)},
		Memory:          factor{number(value.Balance.Memory.MigrationsPerSecond)},
		CPU:             factor{number(value.Balance.CPU.MigrationsPerSecond)},
		Location:        factor{number(value.Balance.Location.MigrationsPerSecond)},
		Connection: connectionFactor{
			MigrationsPerSecond: number(value.Balance.ConnCount.MigrationsPerSecond),
			CountRatioThreshold: number(value.Balance.ConnCount.CountRatioThreshold),
		},
		ProxyLabels:            labels,
		FailedBackends:         append([]string{}, value.Proxy.FailBackendList...),
		FailoverTimeoutSeconds: uint64(value.Proxy.FailoverTimeout),
	}
}

func projectNamespace(value *config.Namespace) routingNamespace {
	users := []string{}
	if value.Frontend.User != "" {
		users = append(users, value.Frontend.User)
	}
	return routingNamespace{
		Name:             value.Namespace,
		Users:            users,
		BackendInstances: append([]string{}, value.Backend.Instances...),
		BackendTLS:       projectTLS(value.Backend.Security),
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := mgrcfg.NewConfigManager()
	if err := manager.Init(ctx, "", ""); err != nil {
		panic(err)
	}
	defer manager.Close()

	values := [][]byte{}
	if os.Getenv("CPROUTE_MODE") != "default" {
		data, err := os.ReadFile("tests/controlplane/cproute/testdata/routing.toml")
		if err != nil {
			panic(err)
		}
		if err := manager.SetTOMLConfig(data); err != nil {
			panic(err)
		}
		values = append(values,
			[]byte(`{"namespace":"b","frontend":{},"backend":{"instances":["b:4000"]}}`),
			[]byte(`{"namespace":"a","frontend":{"user":"user-a"},"backend":{"instances":["a:4000","a2:4000"],"security":{"ca":"/backend-ca","cert":"/backend-cert","key":"/backend-key","min-tls-version":"1.2","skip-ca":true,"cert-allowed-cn":[" b ","a","a"]}}}`),
		)
	}
	namespaces := make([]routingNamespace, 0, len(values))
	for _, raw := range values {
		var namespace config.Namespace
		if err := json.Unmarshal(raw, &namespace); err != nil {
			panic(err)
		}
		namespaces = append(namespaces, projectNamespace(&namespace))
	}
	sort.Slice(namespaces, func(i, j int) bool { return namespaces[i].Name < namespaces[j].Name })

	result := observation{Config: projectConfig(manager.GetConfig()), Namespaces: namespaces}
	encoded, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(encoded))
}
