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

package main

import (
	"encoding/json"
	"fmt"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"io"
	"net/http"
	"strings"
)

type transport struct{}

func (transport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(map[string]any{"body": string(body), "authorization": req.Header.Get("Authorization"), "timestamp": req.Header.Get("X-TC-Timestamp"), "token": req.Header.Get("X-TC-Token")})
	if err != nil {
		return nil, err
	}
	fmt.Println(string(data))
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"Response":{"RequestId":"fake-request"}}`))}, nil
}
func main() {
	p := profile.NewClientProfile()
	p.HttpProfile.Endpoint = "sts.tencentcloudapi.com"
	p.HttpProfile.ReqMethod = "POST"
	client := common.NewCommonClient(common.NewTokenCredential("fake-id", "fake-secret", "fake-token"), "ap-guangzhou", p)
	client.WithHttpTransport(transport{})
	r := tchttp.NewCommonRequest("sts", "2018-08-13", "AssumeRole")
	r.SetHeader(map[string]string{"X-TC-Timestamp": "1700000000"})
	if err := r.SetActionParameters(map[string]interface{}{"RoleArn": "qcs::cam::uin/123:roleName/test", "RoleSessionName": "metering-writer", "DurationSeconds": 7200}); err != nil {
		panic(err)
	}
	if err := client.Send(r, tchttp.NewCommonResponse()); err != nil {
		panic(err)
	}
}
