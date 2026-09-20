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

// Run from the repository root. All requests use an in-memory transport.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type managedTransport struct {
	rows []map[string]any
	arc  bool
}

func (t *managedTransport) Do(r *http.Request) (*http.Response, error) {
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	headers := map[string]string{}
	for _, key := range []string{"Metadata", "X-IDENTITY-HEADER", "Secret", "Accept", "Content-Type", "Authorization"} {
		if value := r.Header.Get(key); value != "" {
			headers[strings.ToLower(key)] = value
		}
	}
	t.rows = append(t.rows, map[string]any{"method": r.Method, "url": r.URL.String(), "headers": headers, "body": body})
	status := 200
	payload := `{"access_token":"fake-managed-token","expires_in":60,"token_type":"Bearer"}`
	if t.arc {
		status = 401
		payload = ""
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
}
func main() {
	keys := []string{"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT", "MSI_ENDPOINT", "MSI_SECRET", "IMDS_ENDPOINT", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE", "DEFAULT_IDENTITY_CLIENT_ID", "AZURE_TOKEN_CREDENTIALS"}
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"imds-system", map[string]string{}},
		{"imds-chain", map[string]string{"AZURE_TOKEN_CREDENTIALS": "prod"}},
		{"imds-user", map[string]string{"AZURE_CLIENT_ID": "client"}},
		{"app-service", map[string]string{"IDENTITY_ENDPOINT": "http://identity.test/token?keep=1", "IDENTITY_HEADER": "fake-identity-secret", "AZURE_CLIENT_ID": "client"}},
		{"azure-ml-default", map[string]string{"MSI_ENDPOINT": "http://identity.test/token?keep=1", "MSI_SECRET": "fake-msi-secret", "DEFAULT_IDENTITY_CLIENT_ID": "default-client"}},
		{"azure-ml-user", map[string]string{"MSI_ENDPOINT": "http://identity.test/token?keep=1", "MSI_SECRET": "fake-msi-secret", "DEFAULT_IDENTITY_CLIENT_ID": "default-client", "AZURE_CLIENT_ID": "client"}},
		{"cloud-shell", map[string]string{"MSI_ENDPOINT": "http://identity.test/token?keep=1"}},
		{"service-fabric", map[string]string{"IDENTITY_ENDPOINT": "https://identity.test/token?keep=1", "IDENTITY_HEADER": "fake-identity-secret", "IDENTITY_SERVER_THUMBPRINT": "fake-thumbprint"}},
		{"azure-arc", map[string]string{"IDENTITY_ENDPOINT": "http://identity.test/token?keep=1", "IMDS_ENDPOINT": "configured"}},
	}
	rows := []map[string]any{}
	for _, c := range cases {
		for _, key := range keys {
			_ = os.Unsetenv(key)
		}
		_ = os.Setenv("AZURE_TOKEN_CREDENTIALS", "ManagedIdentityCredential")
		for key, value := range c.env {
			_ = os.Setenv(key, value)
		}
		tr := &managedTransport{arc: c.name == "azure-arc"}
		credential, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: tr, Retry: policy.RetryOptions{MaxRetries: -1}}})
		if err != nil {
			panic(err)
		}
		_, err = credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}})
		if (err != nil) != tr.arc {
			panic(err)
		}
		rows = append(rows, map[string]any{"name": c.name, "env": c.env, "requests": tr.rows})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(rows); err != nil {
		panic(err)
	}
}
