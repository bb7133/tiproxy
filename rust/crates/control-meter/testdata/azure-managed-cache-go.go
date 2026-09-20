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

// Probe the actual Go BearerTokenPolicy -> ManagedIdentityCredential -> MSAL cache.
// Force only the outer policy's first RefreshOn into the past, avoiding a 12-hour
// sleep while leaving the real MSAL cache and token expiration unchanged.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

type cacheTransport struct {
	mu           sync.Mutex
	managedCalls int
}

func (t *cacheTransport) Do(r *http.Request) (*http.Response, error) {
	body := ""
	if r.URL.Host == "169.254.169.254" {
		t.mu.Lock()
		t.managedCalls++
		t.mu.Unlock()
		body = `{"access_token":"fake-cache-token","expires_in":86400,"token_type":"Bearer"}`
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

type cacheCredential struct {
	inner     azcore.TokenCredential
	mu        sync.Mutex
	tokens    []azcore.AccessToken
	refreshed chan struct{}
}

func (c *cacheCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	token, err := c.inner.GetToken(ctx, options)
	if err != nil {
		return token, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens = append(c.tokens, token)
	if len(c.tokens) == 1 {
		token.RefreshOn = time.Now().Add(-time.Second)
	}
	if len(c.tokens) == 2 {
		close(c.refreshed)
	}
	return token, nil
}
func main() {
	for _, key := range []string{"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT", "MSI_ENDPOINT", "MSI_SECRET", "IMDS_ENDPOINT", "AZURE_CLIENT_ID"} {
		_ = os.Unsetenv(key)
	}
	_ = os.Setenv("AZURE_TOKEN_CREDENTIALS", "ManagedIdentityCredential")
	tr := &cacheTransport{}
	mi, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: tr, Retry: policy.RetryOptions{MaxRetries: -1}}})
	if err != nil {
		panic(err)
	}
	credential := &cacheCredential{inner: mi, refreshed: make(chan struct{})}
	client, err := blob.NewClient("https://account.blob.core.windows.net/container/blob", credential, &blob.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: tr}})
	if err != nil {
		panic(err)
	}
	for i := range 2 {
		if i == 1 {
			// The actual azcore temporal cache throttles eager refreshes for 30s.
			time.Sleep(30*time.Second + 100*time.Millisecond)
		}
		if _, err = client.GetProperties(context.Background(), nil); err != nil {
			panic(err)
		}
	}
	select {
	case <-credential.refreshed:
	case <-time.After(time.Second):
		panic("Bearer policy did not refresh")
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	rows := map[string]any{"outer_refresh_forced": true, "credential_calls": len(credential.tokens), "managed_http_calls": tr.managedCalls, "first_refresh_on_nonzero": !credential.tokens[0].RefreshOn.IsZero(), "second_refresh_on_zero": credential.tokens[1].RefreshOn.IsZero(), "same_token": credential.tokens[0].Token == credential.tokens[1].Token, "same_expiration": credential.tokens[0].ExpiresOn.Equal(credential.tokens[1].ExpiresOn)}
	if len(credential.tokens) != 2 || tr.managedCalls != 1 || credential.tokens[0].RefreshOn.IsZero() || !credential.tokens[1].RefreshOn.IsZero() || credential.tokens[0].Token != credential.tokens[1].Token || !credential.tokens[0].ExpiresOn.Equal(credential.tokens[1].ExpiresOn) {
		panic("unexpected cache behavior")
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(rows); err != nil {
		panic(err)
	}
}
