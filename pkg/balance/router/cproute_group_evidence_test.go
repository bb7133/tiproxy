// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// This observer executes production Group and portConflictDetector methods.
// No test-only replica of matching or conflict semantics is used.
func TestCPRouteGroupObservation(t *testing.T) {
	fixtureDir := os.Getenv("CPROUTE_GROUP_FIXTURES")
	if fixtureDir == "" {
		t.Skip("run make controlplane-cproute-evidence for shared Go/Rust observations")
	}
	output, err := os.Create(os.Getenv("CPROUTE_GROUP_OUTPUT"))
	require.NoError(t, err)
	defer func() { require.NoError(t, output.Close()) }()
	emit := func(format string, args ...any) {
		_, err := fmt.Fprintf(output, format, args...)
		require.NoError(t, err)
	}
	fields := func(name string, count int, observe func([]string)) {
		f, err := os.Open(filepath.Join(fixtureDir, name))
		require.NoError(t, err)
		defer func() { require.NoError(t, f.Close()) }()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			row := strings.Split(line, "\t")
			require.Len(t, row, count)
			observe(row)
		}
		require.NoError(t, scanner.Err())
	}
	values := func(value string) []string {
		if value == "-" {
			return nil
		}
		return strings.Split(value, ";")
	}
	address := func(value string) net.Addr {
		if value == "-" {
			return nil
		}
		addr := cpRouteEvidenceAddr(value)
		return &addr
	}
	rule := map[string]MatchType{"all": MatchAll, "client": MatchClientCIDR, "proxy": MatchProxyCIDR, "port": MatchPort}
	fields("match.tsv", 6, func(row []string) {
		matchType, ok := rule[row[1]]
		require.True(t, ok)
		group, err := NewGroup(values(row[2]), func(*zap.Logger) policy.BalancePolicy { return nil }, matchType, zap.NewNop())
		if err != nil {
			emit("%s\tinvalid\n", row[0])
			return
		}
		matched := group.Match(ClientInfo{ClientAddr: address(row[4]), ProxyAddr: address(row[5])})
		emit("%s\tvalid\t%t\t%t\t%t\n", row[0], matched, group.EqualValues(values(row[3])), group.Intersect(values(row[3])))
	})
	detector := newPortConflictDetector()
	groups := make(map[*Group]string)
	scalar := func(value string) string {
		if value == "-" {
			return ""
		}
		return value
	}
	fields("port.tsv", 5, func(row []string) {
		port := scalar(row[2])
		switch row[1] {
		case "reset":
			detector = newPortConflictDetector()
		case "bind":
			group := &Group{}
			groups[group] = row[4]
			detector.bind(port, scalar(row[3]), group)
		case "get":
		default:
			t.Fatalf("unknown action %s", row[1])
		}
		group, err := detector.groupFor(port)
		switch {
		case err != nil:
			emit("%s\tconflict\n", row[0])
		case group == nil:
			emit("%s\tabsent\n", row[0])
		default:
			emit("%s\tgroup\t%s\n", row[0], groups[group])
		}
	})
}

type cpRouteEvidenceAddr string

func (cpRouteEvidenceAddr) Network() string     { return "tcp" }
func (addr cpRouteEvidenceAddr) String() string { return string(addr) }
