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

//! Signed object writes for metering. Provider errors never expose credentials.

use std::fmt;
use std::time::Duration;

use control_config::MeteringConfig;
use http::{Method, Request, StatusCode, request::Parts};
use reqsign_core::Context;
use reqwest::{Client, Url};

use crate::Error;
use crate::cloud_context;
use crate::export::{MaintenanceFuture, ObjectStore, UploadFuture};

/// Signed cloud storage transport. No credentials are included in debug output.
pub struct CloudStore {
    client: Client,
    endpoint: Url,
    prefix: String,
    signer: CloudSigner,
}

enum CloudSigner {
    S3(Box<crate::cloud_aws::AwsSigner>),
    Oss(crate::cloud_oss::OssSigner),
    Cos(crate::cloud_cos::CosSigner),
    Azure(crate::cloud_azure::AzureSigner),
}

impl fmt::Debug for CloudStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudStore").finish_non_exhaustive()
    }
}

impl CloudStore {
    /// Creates a cloud store using OS TLS roots and the configured credential chain.
    ///
    /// # Errors
    /// Rejects invalid provider configuration, unavailable OS roots and client setup.
    pub async fn new(config: &MeteringConfig) -> Result<Self, Error> {
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        // Do not enable reqwest's global native-roots feature: it would broaden
        // the trust of other workspace clients that require an explicit CA.
        let roots = rustls_native_certs::load_native_certs();
        if roots.certs.is_empty() {
            return Err(Error::Export("cloud TLS roots unavailable"));
        }
        for cert in roots.certs {
            let cert = reqwest::Certificate::from_der(cert.as_ref())
                .map_err(|_| Error::Export("cloud TLS root invalid"))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|_| Error::Export("cloud client setup failed"))?;
        let context = cloud_context::context(client.clone());
        Self::with_context(config, client, context).await
    }

    async fn with_context(
        config: &MeteringConfig,
        client: Client,
        context: Context,
    ) -> Result<Self, Error> {
        if config.bucket.is_empty() {
            return Err(Error::Invalid("cloud bucket is required"));
        }
        let (endpoint, signer) = match config.provider_type.as_str() {
            "s3" => s3(config, context).await?,
            "oss" => oss(config, context)?,
            "cos" => cos(config, context)?,
            "azure" => {
                let (endpoint, signer) =
                    crate::cloud_azure::build(config, client.clone(), context).await?;
                (endpoint, CloudSigner::Azure(signer))
            }
            _ => return Err(Error::Invalid("unsupported cloud provider")),
        };
        Ok(Self {
            client,
            endpoint,
            prefix: config.prefix.clone(),
            signer,
        })
    }

    fn object_url(&self, key: &str) -> Result<Url, Error> {
        let key = if self.prefix.is_empty() {
            key.to_owned()
        } else {
            format!(
                "{}/{}",
                self.prefix.strip_suffix('/').unwrap_or(&self.prefix),
                key.strip_prefix('/').unwrap_or(key)
            )
        };
        let mut url = self.endpoint.clone();
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| Error::Invalid("invalid cloud endpoint"))?;
        segments.pop_if_empty();
        for segment in key.split('/') {
            // URL clients normalize these segments; refuse rather than write a
            // different object identity than the durable pending window names.
            if matches!(segment, "." | "..") {
                return Err(Error::Invalid("cloud object contains dot path segment"));
            }
            segments.push(segment);
        }
        drop(segments);
        Ok(url)
    }

    async fn request(&self, method: Method, url: &Url, body: Vec<u8>) -> Result<StatusCode, Error> {
        if let CloudSigner::S3(signer) = &self.signer {
            return signer
                .request(method, url, body.into())
                .await
                .map_err(|_| Error::Export("S3 object request failed"));
        }
        let mut parts = Request::builder()
            .method(method)
            .uri(url.as_str())
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(())
            .map_err(|_| Error::Export("invalid cloud request"))?
            .into_parts()
            .0;
        if let CloudSigner::Azure(signer) = &self.signer {
            signer.sign(&mut parts).await?;
            return self.send(parts, body).await;
        }
        match &self.signer {
            CloudSigner::S3(_) => return Err(Error::Export("invalid S3 signer dispatch")),
            CloudSigner::Oss(signer) => signer.sign(&mut parts).await,
            CloudSigner::Cos(signer) => signer.sign(&mut parts).await,
            CloudSigner::Azure(_) => return Err(Error::Export("invalid Azure signer dispatch")),
        }
        .map_err(|_| Error::Export("cloud credential or signing failure"))?;
        self.send(parts, body).await
    }

    async fn send(&self, parts: Parts, body: Vec<u8>) -> Result<StatusCode, Error> {
        self.client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map(|response| response.status())
            .map_err(|_| Error::Export("cloud request failed"))
    }
}

impl ObjectStore for CloudStore {
    fn maintain(&self) -> MaintenanceFuture<'_> {
        match &self.signer {
            CloudSigner::Oss(signer) => Box::pin(signer.maintain()),
            _ => Box::pin(std::future::pending()),
        }
    }

    fn put_new<'a>(&'a self, key: &'a str, body: Vec<u8>) -> UploadFuture<'a> {
        Box::pin(async move {
            let url = self.object_url(key)?;
            match self.request(Method::HEAD, &url, Vec::new()).await? {
                StatusCode::NOT_FOUND => (),
                status if status.is_success() => {
                    return Err(Error::Export("object already exists"));
                }
                _ => return Err(Error::Export("cloud existence check failed")),
            }
            if self.request(Method::PUT, &url, body).await?.is_success() {
                Ok(())
            } else {
                Err(Error::Export("cloud object upload failed"))
            }
        })
    }
}

fn endpoint(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| Error::Invalid("invalid cloud endpoint"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("invalid cloud endpoint"));
    }
    Ok(url)
}

fn bucket_host(url: &mut Url, bucket: &str) -> Result<(), Error> {
    let host = url
        .host_str()
        .ok_or(Error::Invalid("invalid cloud endpoint"))?;
    if !host.starts_with(&format!("{bucket}.")) {
        url.set_host(Some(&format!("{bucket}.{host}")))
            .map_err(|_| Error::Invalid("invalid bucket hostname"))?;
    }
    Ok(())
}

async fn s3(config: &MeteringConfig, context: Context) -> Result<(Url, CloudSigner), Error> {
    let region = aws_region(config, &context).await?;
    let domain = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    let fallback = format!("https://s3.{region}.{domain}");
    let mut url = endpoint(if config.endpoint.is_empty() {
        &fallback
    } else {
        &config.endpoint
    })?;
    let cfg = config.aws.clone().unwrap_or_default();
    if cfg.s3_force_path_style
        || !dns_bucket(&config.bucket)
        || url
            .host_str()
            .is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok())
        || (url.scheme() == "https" && config.bucket.contains('.'))
    {
        url.path_segments_mut()
            .map_err(|()| Error::Invalid("invalid cloud endpoint"))?
            .pop_if_empty()
            .push(&config.bucket);
    } else {
        bucket_host(&mut url, &config.bucket)?;
    }
    let sts_endpoint = if config.endpoint.is_empty() {
        None
    } else {
        Some(endpoint(&config.endpoint)?)
    };
    let signer = crate::cloud_aws::AwsSigner::new(&cfg, region, sts_endpoint, context)
        .await
        .map_err(|_| Error::Invalid("invalid AWS credential configuration"))?;
    Ok((url, CloudSigner::S3(Box::new(signer))))
}

fn dns_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket.parse::<std::net::IpAddr>().is_err()
        && bucket.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

async fn aws_region(config: &MeteringConfig, ctx: &Context) -> Result<String, Error> {
    if !config.region.is_empty() {
        return Ok(config.region.clone());
    }
    if let Some(region) = ctx
        .env_var("AWS_REGION")
        .or_else(|| ctx.env_var("AWS_DEFAULT_REGION"))
        && !region.is_empty()
    {
        return Ok(region);
    }
    let path = ctx.env_var("AWS_CONFIG_FILE").or_else(|| {
        ctx.home_dir()
            .map(|home| home.join(".aws/config").to_string_lossy().into_owned())
    });
    if let Some(path) = path
        && let Ok(data) = ctx.file_read(&path).await
    {
        let text = String::from_utf8(data).map_err(|_| Error::Invalid("invalid AWS profile"))?;
        let ini =
            ini::Ini::load_from_str(&text).map_err(|_| Error::Invalid("invalid AWS profile"))?;
        let profile = ctx
            .env_var("AWS_PROFILE")
            .unwrap_or_else(|| "default".to_owned());
        let section = if profile == "default" {
            profile
        } else {
            format!("profile {profile}")
        };
        if let Some(region) = ini
            .section(Some(section))
            .and_then(|section| section.get("region"))
            && !region.is_empty()
        {
            return Ok(region.to_owned());
        }
    }
    Err(Error::Invalid("AWS region is required"))
}

fn oss(config: &MeteringConfig, context: Context) -> Result<(Url, CloudSigner), Error> {
    if config.region.is_empty() {
        return Err(Error::Invalid("OSS region is required"));
    }
    let raw = if config.endpoint.is_empty() {
        format!("https://oss-{}.aliyuncs.com", config.region)
    } else if config.endpoint.contains("://") {
        config.endpoint.clone()
    } else {
        format!("https://{}", config.endpoint)
    };
    let mut url = endpoint(&raw)?;
    bucket_host(&mut url, &config.bucket)?;
    let cfg = config.oss.clone().unwrap_or_default();
    let signer = crate::cloud_oss::OssSigner::new(&cfg, &config.region, &config.bucket, context);
    Ok((url, CloudSigner::Oss(signer)))
}

fn cos(config: &MeteringConfig, context: Context) -> Result<(Url, CloudSigner), Error> {
    let raw = if config.endpoint.is_empty() {
        if config.region.is_empty() {
            return Err(Error::Invalid("COS region is required"));
        }
        format!(
            "https://{}.cos.{}.myqcloud.com",
            config.bucket, config.region
        )
    } else if config.endpoint.contains("://") {
        config.endpoint.clone()
    } else {
        format!("https://{}", config.endpoint)
    };
    let mut url = endpoint(&raw)?;
    bucket_host(&mut url, &config.bucket)?;
    let cfg = config.cos.clone().unwrap_or_default();
    Ok((
        url,
        CloudSigner::Cos(crate::cloud_cos::CosSigner::new(&cfg, context)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_config::{AwsMeteringConfig, AzureMeteringConfig, CloudMeteringConfig};
    use reqsign_core::StaticEnv;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve(listener: TcpListener, statuses: Vec<u16>) -> Vec<(String, Vec<u8>)> {
        let mut requests = Vec::new();
        for status in statuses {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(
                    stream
                        .read_u8()
                        .await
                        .unwrap_or_else(|e| unreachable!("{e}")),
                );
            }
            let head = String::from_utf8(head).unwrap_or_else(|e| unreachable!("{e}"));
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream
                .read_exact(&mut body)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            requests.push((head, body));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
        requests
    }

    async fn fixture(
        provider: &str,
        statuses: Vec<u16>,
    ) -> (CloudStore, tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| unreachable!("{e}"));
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("bucket.store.invalid", addr)
            .build()
            .unwrap_or_else(|e| unreachable!("{e}"));
        let config = MeteringConfig {
            provider_type: provider.into(),
            bucket: "bucket".into(),
            region: "region".into(),
            endpoint: format!("http://store.invalid:{}", addr.port()),
            prefix: "prefix space/%text/".into(),
            aws: Some(AwsMeteringConfig {
                access_key: "fake-id".into(),
                secret_access_key: "fake-secret".into(),
                session_token: "fake-token".into(),
                ..Default::default()
            }),
            oss: Some(CloudMeteringConfig {
                access_key: "fake-id".into(),
                secret_access_key: "fake-secret".into(),
                session_token: "fake-token".into(),
                ..Default::default()
            }),
            cos: Some(CloudMeteringConfig {
                access_key: "fake-id".into(),
                secret_access_key: "fake-secret".into(),
                session_token: "fake-token".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let context = cloud_context::context(client.clone()).with_env(StaticEnv::default());
        let store = CloudStore::with_context(&config, client, context)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        (store, tokio::spawn(serve(listener, statuses)))
    }

    #[tokio::test]
    async fn signed_cloud_writes_preserve_key_payload_and_session_token() {
        for (provider, auth, token) in [
            ("s3", "AWS4-HMAC-SHA256", "x-amz-security-token"),
            ("oss", "OSS4-HMAC-SHA256", "x-oss-security-token"),
            ("cos", "q-sign-algorithm=sha1", "x-cos-security-token"),
        ] {
            let (store, server) = fixture(provider, vec![404, 200]).await;
            store
                .put_new("metering/ru/60/proxy/pool/id-0.json.gz", vec![1, 2, 3])
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let requests = server.await.unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(requests.len(), 2);
            for (index, (head, body)) in requests.iter().enumerate() {
                let method = if index == 0 { "HEAD" } else { "PUT" };
                assert!(head.starts_with(&format!("{method} /prefix%20space/%25text/metering/ru/60/proxy/pool/id-0.json.gz HTTP/1.1")), "{provider}: incorrect path");
                assert!(
                    head.contains(&format!("authorization: {auth}")),
                    "{provider}: missing signature"
                );
                assert!(
                    head.contains(&format!("{token}: fake-token")),
                    "{provider}: missing session token"
                );
                assert_eq!(
                    body.as_slice(),
                    if index == 0 { &[] } else { &[1, 2, 3][..] }
                );
            }
            let debug = format!("{store:?}");
            assert!(!debug.contains("fake-"));
        }
    }

    #[tokio::test]
    async fn s3_retries_each_operation_without_repeating_the_existence_check() {
        let (store, server) = fixture("s3", vec![503, 404, 503, 200]).await;
        store
            .put_new("object", vec![1, 2, 3])
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        let requests = server.await.unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(requests.len(), 4);
        for (index, (head, body)) in requests.iter().enumerate() {
            let method = if index < 2 { "HEAD" } else { "PUT" };
            assert!(head.starts_with(&format!("{method} /prefix%20space/%25text/object HTTP/1.1")));
            assert_eq!(
                body.as_slice(),
                if index < 2 { &[] } else { &[1, 2, 3][..] }
            );
            assert!(head.contains("authorization: AWS4-HMAC-SHA256"));
        }
    }

    #[tokio::test]
    async fn existing_or_denied_objects_are_never_uploaded() {
        for status in [200, 403, 500, 307] {
            let (store, server) =
                fixture("s3", vec![status; if status == 500 { 3 } else { 1 }]).await;
            let result = store.put_new("object", vec![1]).await;
            assert!(result.is_err());
            let requests = server.await.unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(requests.len(), if status == 500 { 3 } else { 1 });
            assert!(requests.iter().all(|r| r.0.starts_with("HEAD ")));
        }
    }
    #[tokio::test]
    async fn azure_shared_key_and_sas_write_real_requests() {
        for sas in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|e| unreachable!("{e}"));
            let client = Client::builder()
                .no_proxy()
                .build()
                .unwrap_or_else(|e| unreachable!("{e}"));
            let config = MeteringConfig {
                provider_type: "azure".into(),
                endpoint: format!("http://{addr}/account"),
                bucket: "bucket".into(),
                prefix: "prefix space/%text".into(),
                azure: Some(AzureMeteringConfig {
                    account_name: "account".into(),
                    account_key: if sas {
                        String::new()
                    } else {
                        reqsign_core::hash::base64_encode(b"fake-account-key")
                    },
                    sas_token: "?sv=2025-11-05&sig=fake%2Bsignature".into(),
                }),
                ..Default::default()
            };
            let ctx = cloud_context::context(client.clone()).with_env(StaticEnv::default());
            let store = CloudStore::with_context(&config, client, ctx)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let server = tokio::spawn(serve(listener, vec![404, 201]));
            store
                .put_new("metering/ru/60/key.json.gz", vec![1, 2, 3])
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let rows = server.await.unwrap_or_else(|e| unreachable!("{e}"));
            for (i, (head, body)) in rows.iter().enumerate() {
                assert!(
                    head.contains(
                        "/account/bucket/prefix%20space/%25text/metering/ru/60/key.json.gz"
                    )
                );
                assert!(head.contains("x-ms-version: 2025-11-05"));
                assert_eq!(head.contains("authorization: SharedKey account:"), !sas);
                assert_eq!(head.contains("?sv=2025-11-05&sig=fake%2Bsignature"), sas);
                assert_eq!(head.contains("x-ms-blob-type: BlockBlob"), i == 1);
                assert_eq!(body.as_slice(), if i == 0 { &[] } else { &[1, 2, 3][..] });
            }
        }
    }

    #[tokio::test]
    async fn s3_addressing_matches_pinned_go_sdk_requests() {
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../testdata/s3-addressing-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 9);
        for row in rows {
            let config = MeteringConfig {
                provider_type: "s3".into(),
                region: "us-east-1".into(),
                endpoint: row["endpoint"].as_str().unwrap_or_default().into(),
                bucket: row["bucket"].as_str().unwrap_or_default().into(),
                prefix: "prefix space/%text".into(),
                aws: Some(AwsMeteringConfig {
                    access_key: "fake-id".into(),
                    secret_access_key: "fake-secret".into(),
                    s3_force_path_style: row["force"].as_bool().unwrap_or(false),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let client = Client::new();
            let ctx = cloud_context::context(client.clone()).with_env(StaticEnv::default());
            let store = CloudStore::with_context(&config, client, ctx)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                store
                    .object_url("key")
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .as_str(),
                row["url"].as_str().unwrap_or_default()
            );
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RoleFixture(std::sync::Arc<std::sync::Mutex<Vec<Request<bytes::Bytes>>>>);
    impl reqsign_core::HttpSend for RoleFixture {
        async fn http_send(
            &self,
            request: Request<bytes::Bytes>,
        ) -> reqsign_core::Result<http::Response<bytes::Bytes>> {
            let aws = request
                .uri()
                .host()
                .is_some_and(|host| host.contains("amazonaws"));
            self.0
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .push(request);
            let body = if aws {
                r"<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE0000000000</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"
            } else {
                r#"{"Credentials":{"AccessKeyId":"role-id","AccessKeySecret":"role-secret","SecurityToken":"role-token","Expiration":"2099-01-01T00:00:00Z"}}"#
            };
            Ok(http::Response::builder()
                .status(200)
                .body(bytes::Bytes::from_static(body.as_bytes()))?)
        }
    }

    #[tokio::test]
    async fn aws_and_oss_assume_role_replace_static_credentials_and_cache_results() {
        for provider in ["s3", "oss"] {
            let io = RoleFixture::default();
            let ctx = Context::new()
                .with_env(StaticEnv::default())
                .with_http_send(io.clone());
            let config = MeteringConfig {
                provider_type: provider.into(),
                bucket: "bucket".into(),
                region: "us-east-1".into(),
                aws: Some(AwsMeteringConfig {
                    access_key: "base-id".into(),
                    secret_access_key: "base-secret".into(),
                    session_token: "base-token".into(),
                    assume_role_arn: "arn:aws:iam::123456789012:role/metering".into(),
                    ..Default::default()
                }),
                oss: Some(CloudMeteringConfig {
                    access_key: "base-id".into(),
                    secret_access_key: "base-secret".into(),
                    session_token: "base-token".into(),
                    assume_role_arn: "acs:ram::123456789012:role/metering".into(),
                }),
                ..Default::default()
            };
            let (url, signer) = if provider == "s3" {
                s3(&config, ctx)
                    .await
                    .unwrap_or_else(|e| unreachable!("{e}"))
            } else {
                oss(&config, ctx).unwrap_or_else(|e| unreachable!("{e}"))
            };
            for _ in 0..2 {
                let mut parts = Request::head(url.as_str())
                    .body(())
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .into_parts()
                    .0;
                match &signer {
                    CloudSigner::S3(signer) => signer.sign(&mut parts).await,
                    CloudSigner::Oss(signer) => signer.sign(&mut parts).await,
                    CloudSigner::Cos(_) | CloudSigner::Azure(_) => unreachable!(),
                }
                .unwrap_or_else(|e| unreachable!("{e}"));
                assert!(
                    parts.headers["authorization"]
                        .to_str()
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .contains(if provider == "s3" {
                            "ASIAEXAMPLE0000000000"
                        } else {
                            "role-id"
                        })
                );
            }
            assert_eq!(io.0.lock().unwrap_or_else(|e| unreachable!("{e}")).len(), 1);
        }
    }
}
