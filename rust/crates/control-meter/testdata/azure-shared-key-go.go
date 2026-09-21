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

// Run from the repository root; output is a real pinned Go SDK request capture.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type fixedHeaders struct{}

func (fixedHeaders) Do(r *policy.Request) (*http.Response, error) {
	// The pinned SDK checks the raw lowercase map key before adding its date.
	// Header.Set canonicalizes it and therefore does not pin the signing date.
	r.Raw().Header["x-ms-date"] = []string{"Tue, 14 Nov 2023 22:13:20 GMT"}
	r.Raw().Header.Set("x-ms-client-request-id", "fixed-request-id")
	return r.Next()
}

type transport struct {
	rows []map[string]any
	key  string
}

func (t *transport) Do(r *http.Request) (*http.Response, error) {
	t.rows = append(t.rows, map[string]any{"key": t.key, "method": r.Method, "url": r.URL.String(), "headers": r.Header})
	status := 200
	if r.Method == "PUT" {
		status = 201
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}
func main() {
	// Fixed entropy is confined to this fake-credential signature probe.
	rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
	key := base64.StdEncoding.EncodeToString([]byte("fake-account-key"))
	credential, err := azblob.NewSharedKeyCredential("account", key)
	if err != nil {
		panic(err)
	}
	tr := &transport{key: key}
	client, err := azblob.NewClientWithSharedKeyCredential("https://account.blob.core.windows.net", credential, &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: tr, PerCallPolicies: []policy.Policy{fixedHeaders{}}}})
	if err != nil {
		panic(err)
	}
	_, err = client.ServiceClient().NewContainerClient("bucket").NewBlobClient("prefix space/%text/key.json.gz").GetProperties(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	_, err = client.UploadBuffer(context.Background(), "bucket", "prefix space/%text/key.json.gz", []byte("payload"), nil)
	if err != nil {
		panic(err)
	}

	_, err = client.ServiceClient().NewContainerClient("bucket").NewBlockBlobClient("prefix space/%text/key.json.gz").UploadStream(context.Background(), bytes.NewReader(bytes.Repeat([]byte{'p'}, 1048577)), nil)
	if err != nil {
		panic(err)
	}

	for _, noncanonical := range []string{"Zh==", "Zm9="} {
		credential, err := azblob.NewSharedKeyCredential("account", noncanonical)
		if err != nil {
			panic(err)
		}
		tr.key = noncanonical
		client, err := azblob.NewClientWithSharedKeyCredential("https://account.blob.core.windows.net", credential, &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: tr, PerCallPolicies: []policy.Policy{fixedHeaders{}}}})
		if err != nil {
			panic(err)
		}
		if _, err = client.ServiceClient().NewContainerClient("bucket").NewBlobClient("key.json.gz").GetProperties(context.Background(), nil); err != nil {
			panic(err)
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(tr.rows); err != nil {
		panic(err)
	}
}
