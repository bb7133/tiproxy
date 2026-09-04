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

//! Safe TLS-material (PEM) reads in the composition root.
//!
//! This is the single read that binds a TLS file's bytes into a generation's
//! prepared artifact, so it must not be tricked into reading a different file
//! than the one validated. It opens the exact configured path with
//! `O_NOFOLLOW` — a symlink final component is rejected outright, even one that
//! points back inside an allowed root — then binds every later step (regular-
//! file and size checks, and the read itself) to that open file descriptor, so
//! a swap or unlink after the open cannot redirect the read to another inode.
//! The allowed-root confinement is checked without reopening the file.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Upper bound on one TLS material file, matching CP-CFG's serving reader.
const MAX_TLS_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Reads one TLS material file safely and returns its bytes.
///
/// The path must be absolute, must open without following a final symlink, must
/// resolve inside one of `allowed_roots`, and must be a regular file no larger
/// than 16 MiB. The read is bound to the opened descriptor.
///
/// # Errors
///
/// Returns a bounded, payload-free reason (never the path or the material) when
/// any of those conditions fails.
pub fn read_tls_material(path: &Path, allowed_roots: &[PathBuf]) -> Result<Vec<u8>, &'static str> {
    if !path.is_absolute() {
        return Err("tls material path is not absolute");
    }
    // Open the exact configured path without following a final symlink, so a
    // link (even one resolving back inside an allowed root) is rejected here
    // rather than silently followed.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "tls material is unavailable or is a symlink")?;
    // Confine to an allowed root. This canonicalizes the path (and each root)
    // for the containment check only; the bytes are still read from the
    // descriptor opened above, so a post-check swap cannot redirect the read.
    let canonical = std::fs::canonicalize(path).map_err(|_| "tls material is unavailable")?;
    let contained = allowed_roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .is_ok_and(|canonical_root| canonical.starts_with(canonical_root))
    });
    if !contained {
        return Err("tls material is outside the configured TLS roots");
    }
    read_bounded_regular_file(&mut file)
}

/// Reads a bounded regular file from an already-opened descriptor. The
/// regular-file and size checks and the read all use this descriptor, so they
/// observe the same inode that was opened.
fn read_bounded_regular_file(file: &mut File) -> Result<Vec<u8>, &'static str> {
    let metadata = file.metadata().map_err(|_| "tls material is unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_TLS_FILE_BYTES {
        return Err("tls material must be a regular file no larger than 16 MiB");
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| "tls material is too large")?;
    let mut contents = Vec::with_capacity(capacity);
    file.read_to_end(&mut contents)
        .map_err(|_| "tls material cannot be read")?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_TLS_FILE_BYTES {
        return Err("tls material is too large");
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::read_tls_material;
    use std::io::Write;
    use std::path::PathBuf;

    fn unique_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cptopo-tls-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| unreachable!("create dir: {error}"));
        dir
    }

    fn write(path: &std::path::Path, bytes: &[u8]) {
        let mut file =
            std::fs::File::create(path).unwrap_or_else(|error| unreachable!("create: {error}"));
        file.write_all(bytes)
            .unwrap_or_else(|error| unreachable!("write: {error}"));
    }

    #[test]
    fn a_regular_file_inside_an_allowed_root_reads() {
        let dir = unique_dir("ok");
        let path = dir.join("ca.pem");
        write(&path, b"ca-bytes");
        let roots = vec![dir.clone()];
        let bytes =
            read_tls_material(&path, &roots).unwrap_or_else(|error| unreachable!("read: {error}"));
        assert_eq!(bytes, b"ca-bytes");
    }

    #[test]
    fn a_relative_path_is_rejected() {
        assert!(read_tls_material(std::path::Path::new("ca.pem"), &[]).is_err());
    }

    #[test]
    fn a_file_outside_the_allowed_roots_is_rejected() {
        let dir = unique_dir("outside");
        let path = dir.join("ca.pem");
        write(&path, b"ca-bytes");
        // An unrelated (empty) allowed root.
        let roots = vec![std::env::temp_dir().join("cptopo-tls-nonesuch")];
        assert!(read_tls_material(&path, &roots).is_err());
    }

    #[test]
    fn a_same_root_final_symlink_is_rejected() {
        // The regression CodexM5 flagged: a symlink whose target is itself
        // inside the allowed root must still be rejected — canonicalize-then-open
        // would wrongly accept it.
        let dir = unique_dir("symlink");
        let real = dir.join("real.pem");
        write(&real, b"ca-bytes");
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&real, &link)
            .unwrap_or_else(|error| unreachable!("symlink: {error}"));
        let roots = vec![dir.clone()];
        assert!(
            read_tls_material(&link, &roots).is_err(),
            "a same-root final symlink must be rejected"
        );
        // The real file still reads.
        assert!(read_tls_material(&real, &roots).is_ok());
    }

    #[test]
    fn a_directory_is_rejected_as_non_regular() {
        let dir = unique_dir("dir");
        let roots = vec![dir.clone()];
        assert!(read_tls_material(&dir, &roots).is_err());
    }
}
