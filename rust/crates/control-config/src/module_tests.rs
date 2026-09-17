// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{
    ConfigModule, ConfigModuleOptions, NAMESPACE_CONFIG_PREFIX, NamespaceUpdate, PROXY_CONFIG_KEY,
    RawCandidate, join_reader, persistent_candidate_rejection_log,
};
use crate::{ConfigNamespaceSource, NamespaceConfig, StoreError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn module() -> Result<ConfigModule, StoreError> {
    ConfigModule::load(ConfigModuleOptions {
        config_file: None,
        advertise_addr: None,
        current_dir: PathBuf::from("/tmp"),
        etcd: None,
        election: None,
        persistence_factory: None,
    })
    .map(|(module, _handle)| module)
}

#[tokio::test]
async fn an_observed_reader_completion_is_not_polled_again_during_finish() -> TestResult {
    let mut module = module()?;
    let mut reader = Some(tokio::spawn(async { Ok(()) }));

    // Force the same ordering as run_inner's reader-completed shutdown branch:
    // observe the join result, then pass the remaining reader to normal finish.
    let completed = join_reader(&mut reader).await.ok_or("reader missing")?;
    assert_eq!(completed?, Ok(()));
    Box::pin(module.finish(reader.take(), None)).await?;
    Ok(())
}

#[tokio::test]
async fn cancelling_a_pending_join_keeps_the_reader_owned_until_finish() -> TestResult {
    let mut module = module()?;
    let (release, held) = tokio::sync::oneshot::channel();
    let mut reader = Some(tokio::spawn(async move {
        held.await.map_err(|_| "reader release dropped")
    }));

    // Poll the blocked join first, then deterministically select the ready
    // sibling branch. Cancellation must not detach the still-running reader.
    tokio::select! {
        biased;
        _ = join_reader(&mut reader) => panic!("reader completed before release"),
        () = std::future::ready(()) => {}
    }
    assert!(reader.is_some(), "a pending join remains module-owned");
    release
        .send(())
        .map_err(|()| "reader stopped before release")?;
    Box::pin(module.finish(reader.take(), None)).await?;
    Ok(())
}

#[test]
fn proxy_only_candidate_preserves_seeded_namespace_and_explicit_delete_stays_empty() -> TestResult {
    let mut module = module()?;
    let default = NamespaceConfig {
        namespace: "default".to_owned(),
        ..NamespaceConfig::default()
    };
    module
        .source
        .bootstrap_namespaces_if_empty(vec![default], Path::new("/tmp"))?;
    let seeded = module.source.current();
    let incarnation = seeded
        .namespace_incarnation("default")
        .ok_or("seeded namespace has no incarnation")?;

    let mut proxy_only_entries = BTreeMap::from([(
        PROXY_CONFIG_KEY.as_bytes().to_vec(),
        br#"{"max-connections":20}"#.to_vec(),
    )]);
    proxy_only_entries.insert(
        format!("{NAMESPACE_CONFIG_PREFIX}rejected").into_bytes(),
        b"not-json".to_vec(),
    );
    module.apply_raw_candidate(RawCandidate {
        revision: 1,
        entries: proxy_only_entries,
        namespace_update: NamespaceUpdate::Preserve,
    })?;
    let proxy_only = module.source.current();
    assert_eq!(proxy_only.namespaces().len(), 1);
    assert!(
        proxy_only
            .namespace_incarnation("default")
            .is_some_and(|current| current.same_as(&incarnation)),
        "an unrelated persistent update preserves the exact namespace incarnation"
    );
    assert_eq!(proxy_only.effective().serving()?.max_connections, 20);

    assert!(
        module
            .apply_raw_candidate(RawCandidate {
                revision: 2,
                entries: BTreeMap::from([(
                    format!("{NAMESPACE_CONFIG_PREFIX}rejected").into_bytes(),
                    b"not-json".to_vec(),
                )]),
                namespace_update: NamespaceUpdate::Replace,
            })
            .is_err(),
        "a namespace operation still decodes and rejects malformed material"
    );
    assert!(
        Arc::ptr_eq(&proxy_only, &module.source.current()),
        "a rejected namespace replacement publishes nothing"
    );

    module.apply_raw_candidate(RawCandidate {
        revision: 3,
        entries: BTreeMap::from([(
            PROXY_CONFIG_KEY.as_bytes().to_vec(),
            br#"{"max-connections":20}"#.to_vec(),
        )]),
        namespace_update: NamespaceUpdate::Replace,
    })?;
    assert!(module.source.current().namespaces().is_empty());
    assert!(
        module
            .source
            .bootstrap_namespaces_if_empty(
                vec![NamespaceConfig {
                    namespace: "default".to_owned(),
                    ..NamespaceConfig::default()
                }],
                Path::new("/tmp"),
            )?
            .is_none(),
        "an explicit delete cannot revive the consumed startup-only seed"
    );
    assert!(module.source.current().namespaces().is_empty());
    Ok(())
}

#[test]
fn malformed_namespace_rejection_log_names_the_exact_key_without_value() {
    let error = StoreError::PersistentNamespace {
        key: "/config/ns/rejected".to_owned(),
        class: "json_decode_failed",
    };
    let log = persistent_candidate_rejection_log(42, &error)
        .unwrap_or_else(|| unreachable!("persistent namespace rejection is logged"));
    let parsed: serde_json::Value =
        serde_json::from_str(&log).unwrap_or_else(|error| unreachable!("valid JSON: {error}"));
    assert_eq!(parsed["component"], "control-config");
    assert_eq!(parsed["event"], "persistent_candidate_rejected");
    assert_eq!(parsed["revision"], 42);
    assert_eq!(parsed["key"], "/config/ns/rejected");
    assert_eq!(parsed["error_class"], "json_decode_failed");
    assert!(!log.contains("not-json"), "persisted values stay redacted");
}
