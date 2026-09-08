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

use super::*;
use crate::metric_collector::tests::{Fixture, TestError, result};
#[test]
fn collector_request_parser_bounds_and_query() {
    for value in ["", "default", "a &b=中+%", "first/second"] {
        let request = format!(
            "GET /api/backend/metrics?cluster={} HTTP/1.1\r\nHost: loopback\r\n\r\n",
            encode_query(value)
        );
        assert_eq!(
            parse_request(request.as_bytes()).as_deref(),
            Some(value),
            "COLLECTOR_QUERY_ROUNDTRIP"
        );
    }
    for request in [
        "POST /api/backend/metrics HTTP/1.1\r\n\r\n",
        "GET http://else/api/backend/metrics HTTP/1.1\r\n\r\n",
        "GET /api/backend/metrics?cluster=%xx HTTP/1.1\r\n\r\n",
        "GET /api/backend/metrics HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET /api/backend/metrics HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
    ] {
        assert!(
            parse_request(request.as_bytes()).is_none(),
            "COLLECTOR_HTTP_BOUNDED_REQUEST"
        );
    }
    assert!(decode_query(&"a".repeat(4097)).is_none());
}
#[tokio::test]
async fn collector_response_retirement_at_write_boundary() -> Result<(), TestError> {
    let f = Fixture::new("127.0.0.1:1").await?;
    let capture = f.capture()?;
    let (collector, _) = f.bound().await?;
    let initial = Response::capture(&collector.shared, "").ok_or("current empty response")?;
    assert!(initial.bytes.is_empty());
    assert!(
        collector
            .shared
            .publish(&capture, "collector-fixture", result(), None)
    );
    let response = Response::capture(&collector.shared, "collector-fixture").ok_or("response")?;
    assert_eq!(&*response.bytes, b"{}");
    assert_eq!(response.with_current(|| 7), Some(7));
    assert!(
        collector
            .shared
            .publish(&capture, "collector-fixture", result(), None)
    );
    assert_eq!(
        response.with_current(|| 7),
        None,
        "COLLECTOR_HTTP_RESULT_REPLACEMENT"
    );
    let response = Response::capture(&collector.shared, "collector-fixture").ok_or("response")?;
    f.routing.revoke_and_clear();
    assert_eq!(
        response.with_current(|| 7),
        None,
        "COLLECTOR_HTTP_FINAL_SOURCE_CHECK"
    );
    assert!(!capture.routing().source_gate().is_live());
    let fresh = Fixture::new("127.0.0.1:1").await?;
    let (bound, _) = fresh.bound().await?;
    let empty = Response::capture(&bound.shared, "unknown").ok_or("empty current response")?;
    assert_eq!(empty.with_current(|| 7), Some(7));
    bound.shared.serving.close();
    assert!(
        fresh.capture()?.still_current(),
        "source fixed across listener close"
    );
    assert_eq!(
        empty.with_current(|| 7),
        None,
        "COLLECTOR_EMPTY_RESPONSE_FINAL_SERVING_CHECK"
    );
    Ok(())
}

mod live;
