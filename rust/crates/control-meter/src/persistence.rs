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

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use control_plane::ownership::OwnerToken;
use serde::{Serialize, de::DeserializeOwned};

use crate::Error;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

pub(crate) struct StateFile {
    path: PathBuf,
    owner: OwnerToken,
}

impl StateFile {
    pub(crate) fn new(path: PathBuf, owner: OwnerToken) -> Result<Self, Error> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(Error::Invalid("state path must be an absolute file"));
        }
        let file = Self { path, owner };
        file.check_owner()?;
        Ok(file)
    }

    pub(crate) fn check_owner(&self) -> Result<(), Error> {
        if self.owner.is_current() {
            Ok(())
        } else {
            Err(Error::Retired)
        }
    }

    pub(crate) fn load<T: DeserializeOwned>(&self) -> Result<Option<T>, Error> {
        self.check_owner()?;
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid("state must be a private regular file"));
        }
        let mut bytes = Vec::new();
        File::open(&self.path)?.read_to_end(&mut bytes)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub(crate) fn persist<T: Serialize>(&self, value: &T) -> Result<(), Error> {
        self.check_owner()?;
        let parent = self
            .path
            .parent()
            .ok_or(Error::Invalid("state directory missing"))?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let temporary = temporary_path(&self.path);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(&serde_json::to_vec(value)?)?;
            file.sync_all()?;
            self.check_owner()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(name)
}
