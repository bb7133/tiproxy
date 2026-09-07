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

use std::path::PathBuf;

use super::{ConfigModule, ConfigModuleOptions, join_reader};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn module() -> Result<ConfigModule, crate::StoreError> {
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
