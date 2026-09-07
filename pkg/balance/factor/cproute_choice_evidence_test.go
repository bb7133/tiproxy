// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Used only by the evidence runner's Go overlay of the two production clock
// reads. BackendToRoute, score updates and candidate/weight logic are unchanged.
var cprouteTicket int64

func TestCPRouteChoiceObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_CHOICE_FIXTURE")
	if input == "" {
		t.Skip("run make controlplane-cproute-evidence")
	}
	require.Equal(t, "1", os.Getenv("CPROUTE_CLOCK_OVERLAY"))
	rows, err := os.Open(input)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	output, err := os.Create(os.Getenv("CPROUTE_CHOICE_OUTPUT"))
	require.NoError(t, err)
	defer func() { require.NoError(t, output.Close()) }()
	scan := bufio.NewScanner(rows)
	for scan.Scan() {
		if scan.Text() == "" || strings.HasPrefix(scan.Text(), "#") {
			continue
		}
		fields := strings.Split(scan.Text(), "\t")
		require.Len(t, fields, 6)
		scores := strings.Split(fields[2], ",")
		backends := createBackends(len(scores))
		for i, score := range scores {
			count, err := strconv.Atoi(score)
			require.NoError(t, err)
			backends[i].(*mockBackend).connScore = count
		}
		cfg := config.NewConfig()
		cfg.Balance.ConnCount.CountRatioThreshold, err = strconv.ParseFloat(fields[3], 64)
		require.NoError(t, err)
		cfg.Balance.ConnCount.MigrationsPerSecond, err = strconv.ParseFloat(fields[4], 64)
		require.NoError(t, err)
		conn := NewFactorConnCount()
		conn.SetConfig(cfg)
		fbb := NewFactorBasedBalance(zap.NewNop(), newMockMetricsReader())
		fbb.factors = []Factor{conn}
		fbb.routePolicy = fields[1]
		require.NoError(t, fbb.updateBitNum())
		period, err := strconv.ParseInt(fields[5], 10, 64)
		require.NoError(t, err)
		weights := make([]int, len(scores))
		for cprouteTicket = 0; cprouteTicket < period; cprouteTicket++ {
			selected := fbb.BackendToRoute(backends)
			require.NotNil(t, selected)
			index, err := strconv.Atoi(selected.Addr())
			require.NoError(t, err)
			weights[index]++
		}
		values := make([]string, len(weights))
		for i, count := range weights {
			values[i] = strconv.Itoa(count)
		}
		_, err = fmt.Fprintf(output, "%s\t%s\n", fields[0], strings.Join(values, ","))
		require.NoError(t, err)
	}
	require.NoError(t, scan.Err())
}
