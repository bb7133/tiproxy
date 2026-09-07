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

//! CP-ROUTE normalized observation producer over the production Rust source.

use std::env;
use std::path::Path;

use control_config::{
    ConfigNamespaceSource, ConfigNamespaceStore, EffectiveConfig, RoutingBalancePolicy,
    RoutingConfig, RoutingNamespace, RoutingRule, RoutingSelectionPolicy, SourceRevision,
};
use serde::Serialize;

type AnyError = Box<dyn std::error::Error>;

#[derive(Serialize)]
struct Pair {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct Factor {
    migrations_per_second: String,
}

#[derive(Serialize)]
struct ConnectionFactor {
    migrations_per_second: String,
    count_ratio_threshold: String,
}

#[derive(Serialize)]
struct ConfigObservation {
    label_name: String,
    routing_rule: &'static str,
    balance_policy: &'static str,
    selection_policy: &'static str,
    status: Factor,
    health: Factor,
    memory: Factor,
    cpu: Factor,
    location: Factor,
    connection: ConnectionFactor,
    proxy_labels: Vec<Pair>,
    failed_backends: Vec<String>,
    failover_timeout_seconds: u64,
}

#[derive(Serialize)]
struct TlsObservation {
    ca_path: String,
    certificate_path: String,
    private_key_path: String,
    minimum_version: String,
    skip_ca_verification: bool,
    allowed_common_names: Vec<String>,
}

#[derive(Serialize)]
struct NamespaceObservation {
    name: String,
    users: Vec<String>,
    backend_instances: Vec<String>,
    backend_tls: TlsObservation,
}

#[derive(Serialize)]
struct Observation {
    config: ConfigObservation,
    namespaces: Vec<NamespaceObservation>,
}

fn number(value: f64) -> String {
    format!("{value}")
}

fn path(value: Option<&Path>) -> String {
    value.map_or_else(String::new, |value| value.to_string_lossy().into_owned())
}

fn project_config(value: &RoutingConfig) -> ConfigObservation {
    ConfigObservation {
        label_name: value.label_name.to_string(),
        routing_rule: match value.routing_rule {
            RoutingRule::MatchAll => "match_all",
            RoutingRule::ClientCidr => "client_cidr",
            RoutingRule::ProxyCidr => "proxy_cidr",
            RoutingRule::ListenerPort => "listener_port",
        },
        balance_policy: match value.balance_policy {
            RoutingBalancePolicy::Resource => "resource",
            RoutingBalancePolicy::Location => "location",
            RoutingBalancePolicy::Connection => "connection",
        },
        selection_policy: match value.selection_policy {
            RoutingSelectionPolicy::PreferIdle => "prefer-idle",
            RoutingSelectionPolicy::Random => "random",
        },
        status: Factor {
            migrations_per_second: number(value.status.migrations_per_second),
        },
        health: Factor {
            migrations_per_second: number(value.health.migrations_per_second),
        },
        memory: Factor {
            migrations_per_second: number(value.memory.migrations_per_second),
        },
        cpu: Factor {
            migrations_per_second: number(value.cpu.migrations_per_second),
        },
        location: Factor {
            migrations_per_second: number(value.location.migrations_per_second),
        },
        connection: ConnectionFactor {
            migrations_per_second: number(value.connection.migrations_per_second),
            count_ratio_threshold: number(value.connection.count_ratio_threshold),
        },
        proxy_labels: value
            .proxy_labels
            .iter()
            .map(|(name, value)| Pair {
                name: name.to_string(),
                value: value.to_string(),
            })
            .collect(),
        failed_backends: value
            .failed_backends
            .iter()
            .map(ToString::to_string)
            .collect(),
        failover_timeout_seconds: value.failover_timeout_seconds,
    }
}

fn project_namespace(value: &RoutingNamespace) -> NamespaceObservation {
    NamespaceObservation {
        name: value.name.to_string(),
        users: value.users.iter().map(ToString::to_string).collect(),
        backend_instances: value
            .backend_instances
            .iter()
            .map(ToString::to_string)
            .collect(),
        backend_tls: TlsObservation {
            ca_path: path(value.backend_tls.ca_path.as_deref()),
            certificate_path: path(value.backend_tls.certificate_path.as_deref()),
            private_key_path: path(value.backend_tls.private_key_path.as_deref()),
            minimum_version: value.backend_tls.minimum_version.to_string(),
            skip_ca_verification: value.backend_tls.skip_ca_verification,
            allowed_common_names: value
                .backend_tls
                .allowed_common_names
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
    }
}

fn main() -> Result<(), AnyError> {
    let current_dir = env::current_dir()?;
    let is_default = env::var("CPROUTE_MODE").as_deref() == Ok("default");
    let data = if is_default {
        Vec::new()
    } else {
        std::fs::read("tests/controlplane/cproute/testdata/routing.toml")?
    };
    let base = ConfigNamespaceStore::from_toml(&data, None, &current_dir)?;
    let values = if is_default {
        Vec::new()
    } else {
        vec![
            (
                "b",
                br#"{"namespace":"b","frontend":{},"backend":{"instances":["b:4000"]}}"#.as_slice(),
            ),
            (
                "a",
                br#"{"namespace":"a","frontend":{"user":"user-a"},"backend":{"instances":["a:4000","a2:4000"],"security":{"ca":"/backend-ca","cert":"/backend-cert","key":"/backend-key","min-tls-version":"1.2","skip-ca":true,"cert-allowed-cn":[" b ","a","a"]}}}"#.as_slice(),
            ),
        ]
    };
    let namespaces = values
        .into_iter()
        .map(|(name, value)| control_config::source::decode_namespace(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    let store = ConfigNamespaceStore::new(
        EffectiveConfig::clone(base.current().effective()),
        namespaces,
        SourceRevision::default(),
        &current_dir,
    )?;
    let current = store.current();
    let mut config = project_config(&current.effective().routing()?);
    if env::var_os("CPROUTE_MUTATE_POLICY").is_some() {
        config.balance_policy = "connection";
    }
    let observation = Observation {
        config,
        namespaces: current
            .namespaces()
            .iter()
            .map(control_config::NamespaceConfig::routing)
            .map(|namespace| project_namespace(&namespace))
            .collect(),
    };
    print!("{}", serde_json::to_string(&observation)?);
    Ok(())
}
