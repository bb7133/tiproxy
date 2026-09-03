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

//! Process-local control-plane foundation for the single Rust `TiProxy` binary.
//!
//! This crate owns Rust domain types, unique-owner fencing, versioned
//! config/TLS views, lifecycle/shutdown phases, and bounded logs/metrics. It is
//! intentionally independent of `control-proto`: the legacy bridge is an outer
//! migration adapter, never the internal domain model.

#![forbid(unsafe_code)]

pub mod config;
pub mod ownership;
pub mod runtime;

pub use config::{
    ConfigError, ConfigSource, ConfigStore, ControlConfig, LogLevel, MetricsPolicy, TlsPolicy,
    TlsSource,
};
pub use ownership::{OwnerError, OwnerLease, OwnerScope, OwnerToken, OwnershipRegistry};
pub use runtime::{
    ControlModule, ControlModuleSet, ControlRuntime, EventSink, JsonStderrSink, LifecyclePhase,
    LifecycleSnapshot, ModuleContext, ModuleError, ModuleExit, ModuleFuture, ModuleSetError,
    RuntimeError, RuntimeEvent, RuntimeEventKind, RuntimeHandle, RuntimeMetrics,
    RuntimeMetricsSnapshot, ShutdownReason,
};
