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

// Capture service retry settings through actual Go config and service constructors.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"os"
	"path/filepath"
)

type row struct {
	Name        string `json:"name"`
	EnvMax      string `json:"env_max"`
	EnvMode     string `json:"env_mode"`
	Profile     string `json:"profile"`
	Credentials string `json:"credentials"`
	Adaptive    bool   `json:"adaptive"`
	Error       bool   `json:"error"`
	Max         int    `json:"max"`
	Mode        string `json:"mode"`
}

func main() {
	dir, e := os.MkdirTemp("", "aws-retry-config-")
	if e != nil {
		panic(e)
	}
	defer os.RemoveAll(dir)
	for _, k := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_MAX_ATTEMPTS", "AWS_RETRY_MODE", "AWS_DEFAULTS_MODE", "AWS_CA_BUNDLE"} {
		_ = os.Unsetenv(k)
	}
	_ = os.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	rows := []row{{Name: "default"}}
	for _, v := range []string{"1", "2", "4", "0", "-1", "+2", " 2", "2 ", "two", "9223372036854775807", "9223372036854775808"} {
		rows = append(rows, row{Name: "env-max-" + v, EnvMax: v}, row{Name: "profile-max-" + v, Profile: "max_attempts = " + v + "\n"})
	}
	for _, v := range []string{"standard", "adaptive", "Standard", "legacy", "invalid", ""} {
		rows = append(rows, row{Name: "env-mode-" + v, EnvMode: v}, row{Name: "profile-mode-" + v, Profile: "retry_mode = " + v + "\n"})
	}
	rows = append(rows, row{Name: "empty-profile-max", Profile: "max_attempts=\n"}, row{Name: "credential-file-overrides", Profile: "max_attempts=4\nretry_mode=adaptive\n", Credentials: "[default]\nmax_attempts=2\nretry_mode=standard\n"}, row{Name: "source-profile-not-global", Profile: "role_arn=arn:aws:iam::123456789012:role/test\nsource_profile=base\nmax_attempts=2\n[profile base]\naws_access_key_id=key\naws_secret_access_key=secret\nmax_attempts=4\nretry_mode=adaptive\n"}, row{Name: "invalid-source-profile", Profile: "role_arn=arn:aws:iam::123456789012:role/test\nsource_profile=base\n[profile base]\naws_access_key_id=key\naws_secret_access_key=secret\nmax_attempts=bad\n"}, row{Name: "env-over-profile", EnvMax: "2", EnvMode: "standard", Profile: "max_attempts=4\nretry_mode=adaptive\n"}, row{Name: "zero-env-falls-back", EnvMax: "0", Profile: "max_attempts=4\n"}, row{Name: "invalid-profile-even-with-env", EnvMax: "2", Profile: "max_attempts=two\n"}, row{Name: "invalid-mode-profile-even-with-env", EnvMode: "standard", Profile: "retry_mode=bad\n"}, row{Name: "bad-inactive-profile", Profile: "max_attempts=2\n[profile inactive]\nmax_attempts=bad\nretry_mode=bad\n"})
	for i := range rows {
		r := &rows[i]
		_ = os.Setenv("AWS_MAX_ATTEMPTS", r.EnvMax)
		_ = os.Setenv("AWS_RETRY_MODE", r.EnvMode)
		if e := os.WriteFile(filepath.Join(dir, "config"), []byte("[default]\n"+r.Profile), 0600); e != nil {
			panic(e)
		}
		if e := os.WriteFile(filepath.Join(dir, "credentials"), []byte(r.Credentials), 0600); e != nil {
			panic(e)
		}
		cfg, e := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"), config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("key", "secret", "")))
		r.Error = e != nil
		if e != nil {
			continue
		}
		a := sts.NewFromConfig(cfg).Options().Retryer
		b := sso.NewFromConfig(cfg).Options().Retryer
		c := ssooidc.NewFromConfig(cfg).Options().Retryer
		r.Adaptive = cfg.RetryMode == aws.RetryModeAdaptive
		r.Max = a.MaxAttempts()
		r.Mode = fmt.Sprintf("%T", a)
		if b.MaxAttempts() != r.Max || c.MaxAttempts() != r.Max || fmt.Sprintf("%T", b) != r.Mode || fmt.Sprintf("%T", c) != r.Mode {
			panic("service disagreement")
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(rows); e != nil {
		panic(e)
	}
}
