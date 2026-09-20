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

// Capture Go processcreds command construction, output decoding and cache behavior.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
)

type row struct {
	Calls      int      `json:"calls"`
	Name       string   `json:"name"`
	Output     string   `json:"output"`
	Command    string   `json:"command"`
	Program    string   `json:"program"`
	Args       []string `json:"args"`
	Error      bool     `json:"error"`
	Key        string   `json:"key"`
	Token      string   `json:"token"`
	Expiration string   `json:"expiration"`
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func main() {
	valid := `{"Version":1,"AccessKeyId":"process key","SecretAccessKey":"process-secret","SessionToken":"process-token"}`
	cases := []row{
		{Name: "quoted-command", Output: valid},
		{Name: "temporary", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"2099-01-01T00:00:00Z"}`},
		{Name: "already-expired-returned", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"2000-01-01T00:00:00Z"}`},
		{Name: "invalid-expiration", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"not-a-time"}`},
		{Name: "empty-expiration", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":""}`},
		{Name: "space-expiration-rejected", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"2099-01-01 00:00:00Z"}`},
		{Name: "lowercase-expiration-rejected", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"2099-01-01t00:00:00z"}`},
		{Name: "offset-expiration", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"2099-01-01T08:00:00+08:00"}`},
		{Name: "fractional-expiration", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":"2099-01-01T00:00:00.5Z"}`},
		{Name: "null-expiration", Output: strings.TrimSuffix(valid, "}") + `,"Expiration":null}`},
		{Name: "case-insensitive-fields", Output: `{"VERSION":1,"accesskeyid":"case-id","secretaccesskey":"case-secret"}`},
		{Name: "duplicates-in-order-null-keeps", Output: `{"Version":0,"version":1,"AccessKeyId":"first","ACCESSKEYID":"last","AccessKeyId":null,"SecretAccessKey":"secret"}`},
		{Name: "wrong-version", Output: strings.ReplaceAll(valid, `"Version":1`, `"Version":2`)},
		{Name: "wrong-type", Output: strings.ReplaceAll(valid, `"Version":1`, `"Version":"1"`)},
		{Name: "wrong-account-type", Output: strings.TrimSuffix(valid, "}") + `,"AccountId":123}`},
		{Name: "no-key", Output: `{"Version":1,"SecretAccessKey":"secret"}`},
		{Name: "empty-secret", Output: `{"Version":1,"AccessKeyId":"id","SecretAccessKey":""}`},
		{Name: "trailing-json", Output: valid + ` {}`},
		{Name: "nonzero-exit", Output: valid},
		{Name: "empty-command"},
	}
	for i := range cases {
		r := &cases[i]
		r.Command = "printf '%s' " + quote(r.Output)
		if r.Name == "nonzero-exit" {
			r.Command += "; exit 7"
		}
		if r.Name == "empty-command" {
			r.Command = ""
		}
		args := []string{r.Command}
		if r.Command == "" {
			args = nil
		}
		command, err := (processcreds.DefaultNewCommandBuilder{Args: args}).NewCommand(context.Background())
		if err == nil {
			r.Program = filepath.Base(command.Path)
			r.Args = command.Args[1:]
		}
		builder := processcreds.NewCommandBuilderFunc(func(ctx context.Context) (*exec.Cmd, error) {
			cmd, err := (processcreds.DefaultNewCommandBuilder{Args: args}).NewCommand(ctx)
			if err == nil {
				r.Calls++
			}
			return cmd, err
		})
		cache := aws.NewCredentialsCache(processcreds.NewProviderCommand(builder))
		value, err := cache.Retrieve(context.Background())
		r.Error = err != nil
		if err == nil {
			if _, err = cache.Retrieve(context.Background()); err != nil {
				panic(err)
			}
			r.Key = value.AccessKeyID
			r.Token = value.SessionToken
			if value.CanExpire {
				r.Expiration = value.Expires.UTC().Format(time.RFC3339Nano)
			}
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cases); err != nil {
		panic(err)
	}
}
