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

//! Local filesystem implementation of the Go metering SDK storage contract.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::Error;
use crate::export::{ObjectStore, UploadFuture};

/// Filesystem object store with the Go provider's prefix/directory/mode options.
pub struct LocalStore {
    root: PathBuf,
    prefix: String,
    create_dirs: bool,
    permissions: u32,
}

impl LocalStore {
    /// Creates the optional base directory, with mode 0755 for an invalid mode.
    ///
    /// `create_dirs` must use the effective Go config value (true when the entire
    /// localfs section is absent, false for an explicitly empty section).
    ///
    /// # Errors
    /// Returns an I/O error if the configured base directory cannot be created.
    pub fn new(
        root: &Path,
        prefix: &str,
        create_dirs: bool,
        permissions: &str,
    ) -> Result<Self, Error> {
        let permissions = if permissions.starts_with('0') && permissions.len() > 1 {
            u32::from_str_radix(permissions, 8).unwrap_or(0o755)
        } else {
            0o755
        };
        let root = if root.as_os_str().is_empty() {
            PathBuf::from("./metering-data")
        } else {
            root.to_owned()
        };
        if create_dirs {
            mkdir(&root, permissions)?;
        }
        Ok(Self {
            root,
            prefix: prefix.into(),
            create_dirs,
            permissions,
        })
    }
}

impl ObjectStore for LocalStore {
    fn put_new<'a>(&'a self, key: &'a str, body: Vec<u8>) -> UploadFuture<'a> {
        let path = self
            .root
            .join(self.prefix.trim_matches('/'))
            .join(key.trim_start_matches('/'));
        let create_dirs = self.create_dirs;
        let permissions = self.permissions;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                match fs::metadata(&path) {
                    Ok(_) => return Err(Error::Export("object already exists")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                }
                if create_dirs && let Some(parent) = path.parent() {
                    mkdir(parent, permissions)?;
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?;
                // The Go LocalFS provider treats chmod failure as non-fatal.
                let _ = file.set_permissions(fs::Permissions::from_mode(permissions));
                file.write_all(&body)?;
                Ok(())
            })
            .await
            .map_err(|_| Error::Export("filesystem worker failed"))?
        })
    }
}

fn mkdir(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    DirBuilder::new().recursive(true).mode(mode).create(path)
}
