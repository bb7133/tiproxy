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

// Capture real IMDS default retry request sequences with a fake HTTP client.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type observed struct {
	Method string `json:"method"`
	Token  string `json:"token"`
	TTL    string `json:"ttl"`
}
type row struct {
	After         string     `json:"after"`
	Name          string     `json:"name"`
	New           bool       `json:"new"`
	TokenStatuses []int      `json:"token_statuses"`
	Statuses      []int      `json:"statuses"`
	TTL           string     `json:"ttl"`
	V1Disabled    bool       `json:"v1_disabled"`
	Hang          bool       `json:"hang"`
	Error         bool       `json:"error"`
	SecondError   bool       `json:"second_error"`
	Backoffs      []int      `json:"backoffs"`
	Requests      []observed `json:"requests"`
}

// Preserve the default IMDS retryer exactly; wrap only to record the
// middleware's actual (legacy/2026) RetryDelay argument, not random durations.
type observedRetryer struct {
	aws.Retryer
	row *row
}

func (r observedRetryer) RetryDelay(attempt int, err error) (time.Duration, error) {
	r.row.Backoffs = append(r.row.Backoffs, attempt)
	delay, e := r.Retryer.RetryDelay(attempt, err)
	if e == nil && (delay < 0 || delay > time.Second || (attempt > 0 && delay != time.Second)) {
		panic("unexpected IMDS delay")
	}
	return delay, e
}

type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }
func status(values []int, index int) int {
	if len(values) == 0 {
		return 200
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}
func run(r *row) {
	tokenCount, getCount := 0, 0
	c := imds.New(imds.Options{Endpoint: "http://127.0.0.1", DisableDefaultMaxBackoff: true, Retryer: observedRetryer{retry.AddWithMaxBackoffDelay(retry.NewStandard(), time.Second), r}, EnableFallback: aws.BoolTernary(!r.V1Disabled), HTTPClient: client(func(req *http.Request) (*http.Response, error) {
		// Model net/http's cancellation: an already canceled request makes
		// no wire attempt, including v1 fallback after token timeout.
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}
		r.Requests = append(r.Requests, observed{req.Method, req.Header.Get("X-Aws-Ec2-Metadata-Token"), req.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds")})
		var code int
		body := "metadata"
		header := http.Header{"X-Amz-Retry-After": []string{r.After}}
		if req.Method == "PUT" {
			tokenCount++
			code = status(r.TokenStatuses, tokenCount-1)
			body = fmt.Sprintf("token-%d", tokenCount)
			if r.TTL != "MISSING" {
				header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", r.TTL)
			}
			if r.Hang {
				<-req.Context().Done()
				return nil, req.Context().Err()
			}
		} else {
			getCount++
			code = status(r.Statuses, getCount-1)
		}
		return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})})
	start := time.Now()
	_, err := c.GetMetadata(context.Background(), &imds.GetMetadataInput{Path: "probe"})
	r.Error = err != nil
	if r.New && r.After == "2000" && !strings.Contains(r.Name, "401") && (time.Since(start) < 2*time.Second || time.Since(start) > 3*time.Second) {
		panic("retry-after delay not honored")
	}

	if r.Hang && (time.Since(start) < 4900*time.Millisecond || time.Since(start) > 7*time.Second) {
		panic("IMDS operation deadline outside expected bound")
	}
	if r.Hang {
		_, err = c.GetMetadata(context.Background(), &imds.GetMetadataInput{Path: "probe"})
		r.SecondError = err != nil
	}
}
func main() {
	base := []row{
		{Name: "token-503-recovers", TokenStatuses: []int{503, 200}},
		{Name: "token-503-falls-back", TokenStatuses: []int{503}},
		{Name: "token-503-no-v1", TokenStatuses: []int{503}, V1Disabled: true},
		{Name: "token-400-terminal", TokenStatuses: []int{400}},
		{Name: "token-429-not-retried", TokenStatuses: []int{429}},
		{Name: "token-403-fallback", TokenStatuses: []int{403}},
		{Name: "metadata-503-recovers", Statuses: []int{503, 200}},
		{Name: "metadata-503-exhausted", Statuses: []int{503}},
		{Name: "metadata-429-terminal", Statuses: []int{429}},
		{Name: "metadata-401-refreshes-token", Statuses: []int{401, 200}},
		{Name: "metadata-401-exhausted", Statuses: []int{401}},
		{Name: "v1-401-reenables-token", TokenStatuses: []int{403, 200}, Statuses: []int{401, 200}},
		{Name: "metadata-403-terminal", Statuses: []int{403}},
		{Name: "invalid-token-ttl-no-retry", TTL: "MISSING"},
		{Name: "invalid-token-ttl-no-v1", TTL: "MISSING", V1Disabled: true},
		{Name: "zero-token-ttl-refreshed-on-retry", TTL: "0", Statuses: []int{503, 200}},
		{Name: "five-second-deadline", Hang: true},
		{Name: "token-retry-after", TokenStatuses: []int{503, 200}, After: "2000"},
		{Name: "metadata-retry-after", Statuses: []int{503, 200}, After: "2000"},
		{Name: "metadata-401-no-retry-after", Statuses: []int{401, 200}, After: "2000"},
	}
	var rows []row
	for _, mode := range []bool{false, true} {
		if mode {
			_ = os.Setenv("AWS_NEW_RETRIES_2026", "true")
		} else {
			_ = os.Unsetenv("AWS_NEW_RETRIES_2026")
		}
		start := len(rows)
		for _, r := range base {
			r.New = mode
			if r.TTL == "" {
				r.TTL = "300"
			}
			rows = append(rows, r)
		}
		var wg sync.WaitGroup
		for i := start; i < len(rows); i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); run(&rows[i]) }(i)
		}
		wg.Wait()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		panic(err)
	}
}
