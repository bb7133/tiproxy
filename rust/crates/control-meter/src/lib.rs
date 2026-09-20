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

//! In-process absolute metering, durable deduplication, and immutable export windows.
//!
//! This module owns no wire protocol. Its persistence remains compatible with
//! the Go consumer and outbox during the staged ownership handoff.

mod cloud_aws;
mod cloud_aws_container;
mod cloud_aws_identity;
mod cloud_aws_imds;
mod cloud_aws_process;
mod cloud_aws_retry;
mod cloud_aws_sso;
mod cloud_azure;
mod cloud_azure_identity;
mod cloud_azure_managed;
mod cloud_context;
mod cloud_cos;
mod cloud_oss;
mod cloud_oss_identity;
pub mod cloud_store;
mod consumer;
pub mod export;
mod local_store;
mod outbox;
mod persistence;
pub mod runtime;
pub mod service;
mod types;

pub use consumer::Consumer;
pub use local_store::LocalStore;
pub use outbox::{ExportRecord, ExportWindow, Outbox};
pub use types::{
    Batch, Checkpoint, Delta, DisabledSink, DurableSink, Error, Intake, Snapshot, SourceBaseline,
    SourceKey,
};
