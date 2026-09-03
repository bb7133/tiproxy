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

//! CP-CFG/NS observation producer over the production Rust source.

use std::env;

use control_config::{
    ConfigNamespaceSource, ConfigNamespaceStore, EffectiveConfig, SourceRevision,
    encode_canonical_config,
};

type AnyError = Box<dyn std::error::Error>;

const PARTIAL_TOML: &[u8] = br#"
[proxy]
max-connections = 23

[proxy.frontend-keepalive]
enabled = true
idle = "1h2m3.004s"
cnt = 7
intvl = "2500us"
timeout = "4.5s"

[log]
level = "warn"
"#;

fn main() -> Result<(), AnyError> {
    let current_dir = env::current_dir()?;
    if env::var_os("CP004_DUMP_NAMESPACE").is_some() {
        let namespaces = [
            (
                "b",
                br#"{"namespace":"b","frontend":{"user":"user-b"},"backend":{"instances":["b:4000"]}}"#.as_slice(),
            ),
            (
                "a",
                br#"{"namespace":"a","frontend":{"user":"user-a","security":{"cert":"/cert","key":"/key","ca":"/ca","min-tls-version":"1.3","cert-allowed-cn":["b","a"],"auto-certs":true,"rsa-key-size":2048,"autocert-expire-duration":"24h","skip-ca":true}},"backend":{"instances":["a:4000"],"security":{"ca":"/backend-ca","min-tls-version":"1.2","skip-ca":true}}}"#.as_slice(),
            ),
        ]
        .into_iter()
        .map(|(name, value)| control_config::source::decode_namespace(name, value))
        .collect::<Result<Vec<_>, _>>()?;
        let store = ConfigNamespaceStore::new(
            EffectiveConfig::default(),
            namespaces,
            SourceRevision::default(),
            &current_dir,
        )?;
        let encoded = serde_json::to_string(store.current().namespaces())?;
        print!("{encoded}");
        return Ok(());
    }
    let mode = env::var("CP004_DUMP_TOML").unwrap_or_default();
    let initial = if mode == "full" {
        std::fs::read("tests/controlplane/cp004/testdata/full.toml")?
    } else {
        Vec::new()
    };
    let store = ConfigNamespaceStore::from_toml(&initial, None, &current_dir)?;
    if mode == "partial" {
        let _ = store.apply_toml(PARTIAL_TOML, None, 2, &current_dir)?;
    }
    let current = store.current();
    let mut encoded = encode_canonical_config(current.effective())?;
    if env::var_os("CP004_MUTATE_SKIP_PROJECTION").is_some() {
        encoded = encoded.replacen("level = \"debug\"", "level = \"info\"", 1);
    }
    print!("{encoded}");
    Ok(())
}
