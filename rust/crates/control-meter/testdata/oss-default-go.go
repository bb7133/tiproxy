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

// Capture credentials-go NewCredential(nil); every HTTP connection stays local.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- verifies the pinned Alibaba RPC HMAC-SHA1 protocol using fake fixture keys.
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
)

type observation struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Query   map[string]string `json:"query"`
	Body    map[string]string `json:"body"`
	Headers map[string]string `json:"headers"`
}
type example struct {
	Name     string            `json:"name"`
	Env      map[string]string `json:"env"`
	Files    map[string]string `json:"files"`
	Denied   string            `json:"denied"`
	Key      string            `json:"key"`
	Secret   string            `json:"secret"`
	Token    string            `json:"token"`
	Error    bool              `json:"error"`
	Requests []observation     `json:"requests"`
}

func signature(query url.Values, body url.Values, secret string) string {
	params := url.Values{}
	for k, v := range query {
		if k != "Signature" {
			params[k] = v
		}
	}
	for k, v := range body {
		params[k] = v
	}
	canonical := strings.ReplaceAll(params.Encode(), "+", "%20")
	h := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = h.Write([]byte("POST&%2F&" + url.QueryEscape(canonical)))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
func values(q url.Values) map[string]string {
	m := map[string]string{}
	for k := range q {
		m[k] = q.Get(k)
	}
	return m
}
func cli(p string) string { return `{"current":"default","profiles":[` + p + `]}` }
func main() {
	ini := "[default]\ntype=access_key\naccess_key_id=ini-id\naccess_key_secret=ini-secret\n"
	ak := `{"name":"default","mode":"AK","access_key_id":"cli-id","access_key_secret":"cli-secret"}`
	role := `{"name":"default","mode":"RamRoleArn","access_key_id":"base-id","access_key_secret":"base-secret","ram_role_arn":"acs:ram::123:role/test","ram_session_name":"fixed","expired_seconds":1200,"policy":"policy with space","external_id":"external"}`
	oidcEnv := map[string]string{"ALIBABA_CLOUD_OIDC_TOKEN_FILE": "/fixture/token", "ALIBABA_CLOUD_OIDC_PROVIDER_ARN": "provider", "ALIBABA_CLOUD_ROLE_ARN": "acs:ram::123:role/test", "ALIBABA_CLOUD_ROLE_SESSION_NAME": "ignored-by-oidc", "ALIBABA_CLOUD_STS_REGION": "cn-hangzhou", "ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED": "True"}
	rows := []example{
		{Name: "env-before-cli", Env: map[string]string{"ALIBABA_CLOUD_ACCESS_KEY_ID": "env-id", "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "env-secret", "ALIBABA_CLOUD_SECURITY_TOKEN": "env-token"}, Files: map[string]string{"config": cli(ak)}},
		{Name: "partial-env-cli", Env: map[string]string{"ALIBABA_CLOUD_ACCESS_KEY_ID": "partial"}, Files: map[string]string{"config": cli(ak)}},
		{Name: "legacy-alias-ignored", Env: map[string]string{"OSS_ACCESS_KEY_ID": "wrong", "OSS_ACCESS_KEY_SECRET": "wrong", "OSS_SESSION_TOKEN": "wrong"}, Files: map[string]string{"credentials": ini}},
		{Name: "cli-before-ini", Files: map[string]string{"config": cli(ak), "credentials": ini}},
		{Name: "cli-disabled", Env: map[string]string{"ALIBABA_CLOUD_CLI_PROFILE_DISABLED": "TRUE"}, Files: map[string]string{"config": cli(ak), "credentials": ini}},
		{Name: "cli-partial-fills-env", Env: map[string]string{"ALIBABA_CLOUD_ACCESS_KEY_SECRET": "env-secret"}, Files: map[string]string{"config": cli(`{"name":"default","mode":"AK","access_key_id":"cli-id"}`)}},
		{Name: "cli-sts", Files: map[string]string{"config": cli(`{"name":"default","mode":"StsToken","access_key_id":"cli-id","access_key_secret":"cli-secret","sts_token":"cli-token"}`)}},
		{Name: "bad-cli-falls-to-ini", Files: map[string]string{"config": "invalid", "credentials": ini}},
		{Name: "named-ini", Env: map[string]string{"ALIBABA_CLOUD_PROFILE": "target"}, Files: map[string]string{"credentials": strings.Replace(ini, "[default]", "[target]", 1)}},
		{Name: "oidc-before-cli", Env: oidcEnv, Files: map[string]string{"token": "fake token\n", "config": cli(ak)}},
		{Name: "oidc-denied-falls-to-cli", Env: oidcEnv, Denied: "sts", Files: map[string]string{"token": "fake token\n", "config": cli(ak)}},
		{Name: "oidc-file-missing-falls-to-ini", Env: oidcEnv, Files: map[string]string{"credentials": ini}},
		{Name: "cli-role", Files: map[string]string{"config": cli(role)}},
		{Name: "cli-role-generated-session", Files: map[string]string{"config": cli(strings.Replace(role, `,"ram_session_name":"fixed"`, "", 1))}},
		{Name: "cli-role-env-session", Env: map[string]string{"ALIBABA_CLOUD_ROLE_SESSION_NAME": "environment-session"}, Files: map[string]string{"config": cli(strings.Replace(role, `,"ram_session_name":"fixed"`, "", 1))}},
		{Name: "cli-short-role-falls-to-ini", Files: map[string]string{"config": cli(strings.Replace(role, "1200", "899", 1)), "credentials": ini}},
		{Name: "ini-role", Files: map[string]string{"credentials": "[default]\ntype=ram_role_arn\naccess_key_id=base-id\naccess_key_secret=base-secret\nrole_arn=acs:ram::123:role/test\nrole_session_name=fixed\npolicy=policy with space\n"}},
		{Name: "cli-chain-role", Files: map[string]string{"config": cli(`{"name":"default","mode":"ChainableRamRoleArn","source_profile":"base","ram_role_arn":"acs:ram::123:role/outer","ram_session_name":"chain"},{"name":"base","mode":"StsToken","access_key_id":"base-id","access_key_secret":"base-secret","sts_token":"base-token"}`)}},
		{Name: "uri-after-files", Env: map[string]string{"ALIBABA_CLOUD_CREDENTIALS_URI": "http://fixture.invalid/credentials"}},
		{Name: "ecs-before-uri", Env: map[string]string{"ALIBABA_CLOUD_ECS_METADATA_DISABLED": "false", "ALIBABA_CLOUD_CREDENTIALS_URI": "http://fixture.invalid/credentials"}},
		{Name: "ecs-v1-fallback", Env: map[string]string{"ALIBABA_CLOUD_ECS_METADATA_DISABLED": "false", "ALIBABA_CLOUD_ECS_METADATA": "known"}, Denied: "metadata-token"},
		{Name: "ecs-v1-disabled-to-uri", Env: map[string]string{"ALIBABA_CLOUD_ECS_METADATA_DISABLED": "false", "ALIBABA_CLOUD_IMDSV1_DISABLED": "true", "ALIBABA_CLOUD_CREDENTIALS_URI": "http://fixture.invalid/credentials"}, Denied: "metadata-token"},
		{Name: "cli-sso", Files: map[string]string{"config": cli(`{"name":"default","mode":"CloudSSO","cloud_sso_sign_in_url":"https://sso.invalid/sign-in","cloud_sso_account_id":"account","cloud_sso_access_config":"config","access_token":"sso-access","cloud_sso_access_token_expire":4070908800}`)}},

		{Name: "cli-oidc", Files: map[string]string{"config": cli(`{"name":"default","mode":"OIDC","oidc_token_file":"/fixture/token","oidc_provider_arn":"provider","ram_role_arn":"acs:ram::123:role/cli","ram_session_name":"cli-session","expired_seconds":1800,"policy":"space policy","sts_region":"cn-hangzhou"}`), "token": "cli-token\n"}},
		{Name: "cli-ecs", Env: map[string]string{"ALIBABA_CLOUD_ECS_METADATA_DISABLED": "false"}, Files: map[string]string{"config": cli(`{"name":"default","mode":"EcsRamRole","ram_role_name":"cli-role"}`)}},
		{Name: "ini-empty-role-key-no-env-fill", Env: map[string]string{"ALIBABA_CLOUD_ACCESS_KEY_ID": "env-id"}, Files: map[string]string{"credentials": "[default]\ntype=ram_role_arn\naccess_key_id=\naccess_key_secret=base-secret\nrole_arn=acs:ram::123:role/test\nrole_session_name=fixed\n"}},
		{Name: "ini-quotes-backslash-comment", Files: map[string]string{"credentials": "[default]\ntype=access_key\naccess_key_id='quoted-id' ; comment\naccess_key_secret=\"quoted\\path\" # comment\n"}},
		{Name: "ini-duplicate-last-wins", Files: map[string]string{"credentials": ini + "access_key_id=last-id\n"}},
		{Name: "ini-backtick-multiline", Env: map[string]string{}, Files: map[string]string{"credentials": "[default]\ntype=access_key\naccess_key_id=`id;#raw`\naccess_key_secret=\"\"\"line1\nline2\"\"\"\n"}},
		{Name: "ini-continuation", Env: map[string]string{}, Files: map[string]string{"credentials": "[default]\ntype=access_key\naccess_key_id=id\\\n tail\naccess_key_secret=secret\n"}},
		{Name: "ini-interpolation-parent", Env: map[string]string{"ALIBABA_CLOUD_PROFILE": "default.child"}, Files: map[string]string{"credentials": "base=base-id\n[default]\ntype=access_key\naccess_key_id=%(base)s\naccess_key_secret=parent-secret\n[default.child]\naccess_key_id=child-%(base)s\n"}},
		{Name: "oidc-empty-key-does-not-fall-through", Env: oidcEnv, Denied: "empty-sts-key", Files: map[string]string{"token": "fake", "config": cli(ak)}},
		{Name: "no-source", Files: map[string]string{}},
	}
	for i := range rows {
		row := &rows[i]
		for _, kv := range os.Environ() {
			k := strings.SplitN(kv, "=", 2)[0]
			if strings.HasPrefix(k, "ALIBABA_") || strings.HasPrefix(k, "OSS_") {
				_ = os.Unsetenv(k)
			}
		}
		dir, err := os.MkdirTemp("", "oss-default-")
		if err != nil {
			panic(err)
		}
		for name, body := range row.Files {
			if err = os.WriteFile(filepath.Join(dir, name), []byte(strings.ReplaceAll(body, "/fixture/", dir+"/")), 0600); err != nil {
				panic(err)
			}
		}
		_ = os.Setenv("ALIBABA_CLOUD_CONFIG_FILE", filepath.Join(dir, "config"))
		_ = os.Setenv("ALIBABA_CLOUD_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
		_ = os.Setenv("ALIBABA_CLOUD_ECS_METADATA_DISABLED", "true")
		for k, v := range row.Env {
			_ = os.Setenv(k, strings.ReplaceAll(v, "/fixture/", dir+"/"))
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			q := r.URL.Query()
			body, _ := url.ParseQuery(string(raw))
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				var m map[string]string
				if err := json.Unmarshal(raw, &m); err != nil {
					panic(err)
				}
				body = url.Values{}
				for k, v := range m {
					body.Set(k, v)
				}
			}
			if sig := q.Get("Signature"); sig != "" && sig != signature(q, body, "base-secret") {
				panic("Go signature validation failed")
			}
			if stamp := q.Get("Timestamp"); stamp != "" {
				if _, err := time.Parse(time.RFC3339, stamp); err != nil {
					panic(err)
				}
				q.Set("Timestamp", "2026-09-20T00:00:00Z")
			}
			if name := body.Get("RoleSessionName"); strings.HasPrefix(name, "credentials-go-") {
				micros, err := strconv.ParseInt(strings.TrimPrefix(name, "credentials-go-"), 10, 64)
				if err != nil || time.Now().Unix()-micros/1000000 > 60 {
					panic("session format")
				}
				body.Set("RoleSessionName", "fixture-session")
			}
			if q.Get("SignatureNonce") != "" {
				q.Set("SignatureNonce", "fixture-nonce")
				q.Set("Signature", signature(q, body, "base-secret"))
			}
			headers := map[string]string{}
			for _, k := range []string{"Content-Type", "Accept", "Accept-Encoding", "Authorization", "X-Acs-Credentials-Provider", "X-Aliyun-Ecs-Metadata-Token", "X-Aliyun-Ecs-Metadata-Token-Ttl-Seconds"} {
				if v := r.Header.Get(k); v != "" && !(k == "Accept-Encoding" && v == "gzip") {
					headers[strings.ToLower(k)] = v
				}
			}
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			row.Requests = append(row.Requests, observation{r.Method, scheme + "://" + r.Host + r.URL.Path, values(q), values(body), headers})
			if (row.Denied == "sts" && q.Get("Action") != "") || (row.Denied == "metadata-token" && r.URL.Path == "/latest/api/token") {
				w.WriteHeader(403)
				return
			}
			if r.URL.Path == "/latest/api/token" {
				_, _ = io.WriteString(w, "metadata-token")
				return
			}
			if strings.HasSuffix(r.URL.Path, "/security-credentials/") {
				_, _ = io.WriteString(w, "role-name\n")
				return
			}
			id := "uri-id"
			wrapper := ""
			switch {
			case q.Get("Action") == "AssumeRoleWithOIDC":
				id = "oidc-id"
				wrapper = "Credentials"
			case q.Get("Action") == "AssumeRole":
				id = "role-id"
				wrapper = "Credentials"
			case r.URL.Path == "/cloud-credentials":
				id = "sso-id"
				wrapper = "CloudCredential"
			case strings.Contains(r.URL.Path, "security-credentials"):
				id = "ecs-id"
			}
			value := map[string]string{"AccessKeyId": id, "AccessKeySecret": "result-secret", "SecurityToken": "result-token", "Expiration": "2099-01-01T00:00:00Z", "Code": "Success"}
			if row.Denied == "empty-sts-key" && q.Get("Action") != "" {
				value["AccessKeyId"] = ""
			}
			var response any = value
			if wrapper != "" {
				response = map[string]any{wrapper: value}
			}
			_ = json.NewEncoder(w).Encode(response)
		})
		plain := httptest.NewServer(handler)
		secure := httptest.NewTLSServer(handler)
		proxy, _ := url.Parse(plain.URL)
		roots := secure.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		http.DefaultTransport = &http.Transport{DisableKeepAlives: true, Proxy: func(r *http.Request) (*url.URL, error) {
			if r.URL.Scheme == "http" {
				return proxy, nil
			}
			return nil, nil
		}, DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := tls.Dialer{Config: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			return d.DialContext(ctx, network, strings.TrimPrefix(secure.URL, "https://"))
		}}
		provider, err := credentials.NewCredential(nil)
		if err != nil {
			panic(err)
		}
		value, err := provider.GetCredential()
		row.Error = err != nil
		if err == nil {
			row.Key = tea.StringValue(value.AccessKeyId)
			row.Secret = tea.StringValue(value.AccessKeySecret)
			row.Token = tea.StringValue(value.SecurityToken)
		}
		plain.Close()
		secure.Close()
		if err = os.RemoveAll(dir); err != nil {
			panic(err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		panic(fmt.Sprint(err))
	}
}
