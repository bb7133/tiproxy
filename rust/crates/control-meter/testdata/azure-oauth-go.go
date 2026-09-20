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

// Pinned DefaultAzureCredential OAuth requests over an isolated TLS transport.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type guardTransport struct {
	client   *http.Client
	host     string
	endpoint *url.URL
}

func (g guardTransport) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Host != g.host {
		return nil, fmt.Errorf("fixture refuses nonloopback authority")
	}
	local := req.Clone(req.Context())
	cloneURL := *req.URL
	cloneURL.Scheme = g.endpoint.Scheme
	cloneURL.Host = g.endpoint.Host
	local.URL = &cloneURL
	return g.client.Do(local)
}

type step struct {
	Scope  string `json:"scope"`
	Claims string `json:"claims"`
	Error  bool   `json:"error"`
	Token  string `json:"token"`
}
type request struct {
	Grant     string          `json:"grant"`
	Scope     string          `json:"scope"`
	Claims    json.RawMessage `json:"claims"`
	Client    bool            `json:"client"`
	Secret    bool            `json:"secret"`
	Assertion string          `json:"assertion"`
	Username  bool            `json:"username"`
	Password  bool            `json:"password"`
}
type objectStep struct {
	Method    string   `json:"method"`
	Challenge string   `json:"challenge"`
	Tokens    []string `json:"tokens"`
	Error     bool     `json:"error"`
}
type row struct {
	Source    string       `json:"source"`
	Steps     []step       `json:"steps"`
	Requests  []request    `json:"requests"`
	Discovery []string     `json:"discovery"`
	Objects   []objectStep `json:"objects"`
}

func main() {
	dir, e := os.MkdirTemp("", "azure-oauth-probe-")
	if e != nil {
		panic(e)
	}
	defer os.RemoveAll(dir)
	assertionFile := filepath.Join(dir, "assertion")
	if e = os.WriteFile(assertionFile, []byte("fake-workload-assertion"), 0600); e != nil {
		panic(e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		panic(e)
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, e := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if e != nil {
		panic(e)
	}
	certFile := filepath.Join(dir, "certificate.pem")
	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
	if e = os.WriteFile(certFile, certBytes, 0600); e != nil {
		panic(e)
	}
	var rows []row
	for n, source := range []string{"secret", "workload", "password", "certificate"} {
		r := row{Source: source}
		for _, p := range []struct{ scope, claims string }{
			{"https://storage.azure.com/.default", ""}, {"https://storage.azure.com/.default", ""},
			{"https://other.invalid/.default", ""}, {"https://storage.azure.com/.default", `{"access_token":{"synthetic":"yes"}}`},
			{"https://storage.azure.com/.default", ""}, {"https://other.invalid/.default", ""},
			{"https://storage.azure.com/.default", `{}`}, {"https://storage.azure.com/.default", `{"access_token":{"xms_cc":{}}}`},
			{"https://storage.azure.com/.default", `{"access_token":{"xms_cc":{"values":["CP2"]}}}`},
			{"https://storage.azure.com/.default", `{"access_token":7}`}, {"https://storage.azure.com/.default", `[]`},
			{"https://storage.azure.com/.default", `invalid`}, {"https://storage.azure.com/.default", `{"id_token":{"synthetic":true}}`},
		} {
			r.Steps = append(r.Steps, step{Scope: p.scope, Claims: p.claims})
		}
		for _, name := range []string{"AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", "AZURE_CLIENT_CERTIFICATE_PASSWORD", "AZURE_USERNAME", "AZURE_PASSWORD", "AZURE_FEDERATED_TOKEN_FILE"} {
			_ = os.Unsetenv(name)
		}
		client := fmt.Sprintf("fake-client-%d", n)
		tenant := "11111111-1111-1111-1111-111111111111"
		_ = os.Setenv("AZURE_CLIENT_ID", client)
		_ = os.Setenv("AZURE_TENANT_ID", tenant)
		_ = os.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
		switch source {
		case "secret":
			_ = os.Setenv("AZURE_CLIENT_SECRET", "fake-secret")
		case "workload":
			_ = os.Setenv("AZURE_TOKEN_CREDENTIALS", "WorkloadIdentityCredential")
			_ = os.Setenv("AZURE_FEDERATED_TOKEN_FILE", assertionFile)
		case "password":
			_ = os.Setenv("AZURE_USERNAME", "fake@fixture.invalid")
			_ = os.Setenv("AZURE_PASSWORD", "fake-password")
		case "certificate":
			_ = os.Setenv("AZURE_CLIENT_CERTIFICATE_PATH", certFile)
		}
		var authority string
		objectIndex := -1
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if req.URL.Path == "/bucket/blob" {
				if objectIndex < 0 {
					panic("unexpected object request")
				}
				step := &r.Objects[objectIndex]
				if req.Method != step.Method {
					panic("unexpected method")
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					panic(err)
				}
				expected := ""
				if req.Method == "PUT" {
					expected = "payload"
				}
				if string(body) != expected {
					panic("body changed on replay")
				}
				step.Tokens = append(step.Tokens, req.Header.Get("Authorization"))
				if len(step.Tokens) == 1 && step.Challenge != "" {
					w.Header().Set("WWW-Authenticate", step.Challenge)
					w.WriteHeader(401)
				} else if req.Method == "PUT" {
					w.WriteHeader(201)
				}
				return
			}
			if strings.Contains(req.URL.Path, "/discovery/instance") {
				r.Discovery = append(r.Discovery, "instance")
				_ = json.NewEncoder(w).Encode(map[string]any{"tenant_discovery_endpoint": authority + "/" + tenant + "/v2.0/.well-known/openid-configuration", "metadata": []any{map[string]any{"preferred_network": "login.microsoftonline.com", "preferred_cache": "login.windows.net", "aliases": []string{"login.microsoftonline.com", "login.windows.net", "sts.windows.net"}}}})
				return
			}
			if strings.Contains(req.URL.Path, ".well-known") {
				r.Discovery = append(r.Discovery, "openid")
				_ = json.NewEncoder(w).Encode(map[string]string{"authorization_endpoint": authority + "/" + tenant + "/oauth2/v2.0/authorize", "token_endpoint": authority + "/" + tenant + "/oauth2/v2.0/token", "issuer": authority + "/" + tenant + "/v2.0", "jwks_uri": authority + "/keys"})
				return
			}
			if strings.Contains(strings.ToLower(req.URL.Path), "userrealm") {
				r.Discovery = append(r.Discovery, "userrealm")
				_ = json.NewEncoder(w).Encode(map[string]string{"account_type": "Managed", "domain_name": "fixture.invalid", "cloud_instance_name": "microsoftonline.com", "cloud_audience_urn": "urn:federation:MicrosoftOnline"})
				return
			}
			if !strings.HasSuffix(req.URL.Path, "/token") {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"unexpected fixture path"}`))
				return
			}
			if e := req.ParseForm(); e != nil {
				panic(e)
			}
			a := ""
			if assertion := req.Form.Get("client_assertion"); assertion != "" {
				if assertion == "fake-workload-assertion" {
					a = "workload"
				} else {
					parts := strings.Split(assertion, ".")
					if len(parts) != 3 {
						panic("invalid certificate assertion")
					}
					signature, err := base64.RawURLEncoding.DecodeString(parts[2])
					if err != nil {
						panic(err)
					}
					hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
					if err = rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
						panic(err)
					}
					a = "certificate"
				}
			}
			claims := json.RawMessage(req.Form.Get("claims"))
			if len(claims) == 0 {
				claims = json.RawMessage("null")
			}
			r.Requests = append(r.Requests, request{Grant: req.Form.Get("grant_type"), Scope: req.Form.Get("scope"), Claims: claims, Client: req.Form.Get("client_id") == client, Secret: req.Form.Get("client_secret") == "fake-secret", Assertion: a, Username: req.Form.Get("username") == "fake@fixture.invalid", Password: req.Form.Get("password") == "fake-password"})
			idPayload, _ := json.Marshal(map[string]any{"aud": client, "preferred_username": "fake@fixture.invalid", "tid": tenant, "oid": "synthetic", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
			idToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(idPayload) + ".fake"
			response := map[string]any{"access_token": fmt.Sprintf("fake-%d", len(r.Requests)), "expires_in": 3600, "token_type": "Bearer", "scope": req.Form.Get("scope")}
			if source == "password" {
				response["client_info"] = base64.RawURLEncoding.EncodeToString([]byte(`{"uid":"synthetic","utid":"synthetic"}`))
				response["id_token"] = idToken
			}
			_ = json.NewEncoder(w).Encode(response)
		}))
		authority = "https://login.microsoftonline.com"
		_ = os.Setenv("AZURE_AUTHORITY_HOST", authority)
		localEndpoint, e := url.Parse(srv.URL)
		if e != nil {
			panic(e)
		}
		credential, e := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: guardTransport{client: srv.Client(), host: "login.microsoftonline.com", endpoint: localEndpoint}}})
		if e != nil {
			panic(e)
		}
		for i := range r.Steps {
			s := &r.Steps[i]
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			token, e := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{s.Scope}, Claims: s.Claims, EnableCAE: true})
			cancel()
			s.Error = e != nil
			s.Token = token.Token
		}
		r.Objects = []objectStep{
			{Method: "HEAD"},
			{Method: "PUT", Challenge: `Bearer resource_id="https://other.invalid"`},
			{Method: "PUT", Challenge: `Bearer error="insufficient_claims", claims="` + base64.StdEncoding.EncodeToString([]byte(`{"access_token":{"synthetic":"yes"}}`)) + `"`},
			{Method: "HEAD", Challenge: `Bearer resource_id="https://storage.azure.com"`},
		}
		blobClient, err := azblob.NewClient(authority, credential, &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: guardTransport{client: srv.Client(), host: "login.microsoftonline.com", endpoint: localEndpoint}}})
		if err != nil {
			panic(err)
		}
		for i := range r.Objects {
			objectIndex = i
			step := &r.Objects[i]
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if step.Method == "HEAD" {
				_, err = blobClient.ServiceClient().NewContainerClient("bucket").NewBlobClient("blob").GetProperties(ctx, nil)
			} else {
				_, err = blobClient.UploadStream(ctx, "bucket", "blob", bytes.NewBufferString("payload"), nil)
			}
			cancel()
			step.Error = err != nil
		}
		srv.Close()
		rows = append(rows, r)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(rows); e != nil {
		panic(e)
	}
}
