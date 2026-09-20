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

//! Go SDK-compatible gzip object export with durable pending-window retry.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::time::Duration;

use flate2::{Compression, write::GzEncoder};
use serde_json::json;

use crate::{Error, ExportWindow, Outbox};

/// Async upload result. Implementations must not include credentials in errors.
pub type UploadFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;

/// Storage seam for one immutable, compressed metering object.
pub trait ObjectStore: Send + Sync {
    /// Refuses an existing object, matching the Go SDK default overwrite policy.
    ///
    /// # Errors
    /// Returns an error if existence checking or upload fails, or the key exists.
    fn put_new<'a>(&'a self, key: &'a str, body: Vec<u8>) -> UploadFuture<'a>;
}

/// One Go SDK-compatible object (`TiProxy` uses the SDK's unpaginated default).
pub struct ExportObject {
    /// Relative object key, before the configured provider prefix.
    pub key: String,
    /// Gzip-compressed JSON envelope.
    pub body: Vec<u8>,
}

/// Encodes the exact Go proxy metering fields and single-part object key.
///
/// # Errors
/// Rejects invalid identity/timestamp or JSON/compression errors.
pub fn encode_window(
    self_id: &str,
    shared_pool_id: &str,
    window: &ExportWindow,
) -> Result<ExportObject, Error> {
    if self_id.is_empty()
        || self_id.contains('-')
        || window.timestamp <= 0
        || window.timestamp % 60 != 0
    {
        return Err(Error::Invalid("export identity or minute timestamp"));
    }
    let pool = if shared_pool_id.is_empty() {
        "default-shared-pool"
    } else {
        shared_pool_id
    };
    let records: Vec<_> = window
        .data
        .iter()
        .map(|record| {
            json!({
                "version":"1", "cluster_id":record.cluster_id, "source_name":"proxy",
                "crossZone_bytes":{"value":record.cross_az_bytes,"unit":"bytes"},
                "private_outBound_bytes":{"value":record.private_response_bytes,"unit":"bytes"},
                "public_outBound_bytes":{"value":record.public_response_bytes,"unit":"bytes"},
            })
        })
        .collect();
    let payload = json!({"timestamp":window.timestamp, "category":"proxy", "self_id":self_id,
        "shared_pool_id":pool, "part":0, "data":records});
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serde_json::to_vec(&payload)?)?;
    Ok(ExportObject {
        key: format!(
            "metering/ru/{}/proxy/{pool}/{self_id}-0.json.gz",
            window.timestamp
        ),
        body: encoder.finish()?,
    })
}

/// Seals/exports one window and durably clears it only after storage succeeds.
///
/// An ambiguous upload failure leaves the original identity and timestamp pending.
/// An existing object is an error, matching Go; it is never silently re-ACKed.
///
/// # Errors
/// Persistence failure fences the outbox. Storage failure or timeout retains the
/// pending window and marks export health false until a later successful retry.
pub async fn flush(
    outbox: &mut Outbox,
    store: &impl ObjectStore,
    shared_pool_id: &str,
    timestamp: i64,
    timeout: Duration,
) -> Result<bool, Error> {
    let Some(window) = outbox.seal(timestamp)? else {
        return Ok(false);
    };
    let result = async {
        let object = encode_window(outbox.self_id(), shared_pool_id, &window)?;
        store.put_new(&object.key, object.body).await
    };
    match tokio::time::timeout(timeout, result).await {
        Ok(Ok(())) => {
            outbox.exported(&window)?;
            Ok(true)
        }
        Ok(Err(error)) => {
            outbox.export_failed();
            Err(error)
        }
        Err(_) => {
            outbox.export_failed();
            Err(Error::Export("upload timeout"))
        }
    }
}
