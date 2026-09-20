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

// Run with aws-adaptive-go.sh. Uses the pinned SDK's documented testing clock
// hooks from a temporary module under its internal-package import boundary.
// Production SDK middleware, limiter, retry quota and errors are unmodified;
// only backoff is zeroed so this fixture isolates adaptive request pacing.
package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/smithy-go"
	m "github.com/aws/smithy-go/middleware"
)

type operation struct {
	Codes    []string `json:"codes"`
	GapMS    int      `json:"gap_ms"`
	Attempts []int64  `json:"attempt_ns"`
	Error    bool     `json:"error"`
	Tokens   uint     `json:"tokens"`
}
type row struct {
	Name       string      `json:"name"`
	New        bool        `json:"new"`
	Adaptive   bool        `json:"adaptive"`
	Max        int         `json:"max"`
	Operations []operation `json:"operations"`
}

func run(r *row) {
	_ = os.Setenv("AWS_NEW_RETRIES_2026", map[bool]string{true: "true", false: "false"}[r.New])
	base := time.Unix(1750000000, 125000000)
	now := base
	sdk.NowTime = func() time.Time { return now }
	sdk.SleepWithContext = func(ctx context.Context, d time.Duration) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		// A real clock progresses even if floating-point rounding requests zero.
		if d < time.Nanosecond {
			d = time.Nanosecond
		}
		now = now.Add(d)
		return nil
	}
	quota := ratelimit.NewTokenRateLimit(500)
	opts := func(o *retry.StandardOptions) {
		o.RateLimiter = quota
		o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
	}
	var policy aws.Retryer = retry.NewStandard(opts)
	if r.Adaptive {
		policy = retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) { o.StandardOptions = []func(*retry.StandardOptions){opts} })
	}
	policy = retry.AddWithMaxAttempts(policy, r.Max)
	middleware := retry.NewAttemptMiddleware(policy, func(v interface{}) interface{} { return v })
	for i := range r.Operations {
		o := &r.Operations[i]
		now = now.Add(time.Duration(o.GapMS) * time.Millisecond)
		calls := 0
		_, _, e := middleware.HandleFinalize(context.Background(), m.FinalizeInput{}, m.FinalizeHandlerFunc(func(context.Context, m.FinalizeInput) (m.FinalizeOutput, m.Metadata, error) {
			o.Attempts = append(o.Attempts, now.Sub(base).Nanoseconds())
			code := o.Codes[len(o.Codes)-1]
			if calls < len(o.Codes) {
				code = o.Codes[calls]
			}
			calls++
			var err error
			if code != "" {
				err = &smithy.GenericAPIError{Code: code}
			}
			return m.FinalizeOutput{}, m.Metadata{}, err
		}))
		o.Error = e != nil
		o.Tokens = quota.Remaining()
	}
}
func main() {
	var rows []row
	for _, n := range []bool{false, true} {
		for _, adaptive := range []bool{false, true} {
			for _, max := range []int{1, 2, 4, -1} {
				rows = append(rows, row{Name: "persistent-sequence", New: n, Adaptive: adaptive, Max: max, Operations: []operation{
					{Codes: []string{""}, GapMS: 0}, {Codes: []string{"Throttling", "Throttling", ""}, GapMS: 625},
					{Codes: []string{""}, GapMS: 0}, {Codes: []string{"RequestTimeout", ""}, GapMS: 0},
					{Codes: []string{"Denied"}, GapMS: 700}, {Codes: []string{"Throttling"}, GapMS: 500},
					{Codes: []string{""}, GapMS: 10000}, {Codes: []string{""}, GapMS: 0},
				}})
			}
			rows = append(rows, row{Name: "late-throttle", New: n, Adaptive: adaptive, Max: 4, Operations: []operation{
				{Codes: []string{"RequestTimeout", "Throttling", ""}, GapMS: 750},
				{Codes: []string{""}, GapMS: 0}, {Codes: []string{"Throttling", ""}, GapMS: 0},
				{Codes: []string{""}, GapMS: 0},
			}})
		}
	}
	for i := range rows {
		run(&rows[i])
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(rows); err != nil {
		panic(err)
	}
}
