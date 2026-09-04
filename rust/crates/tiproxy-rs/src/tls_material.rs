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
//! than the one validated.
//!
//! `allowed_roots` are canonicalized once at startup and frozen (see
//! [`canonicalize_tls_roots`]). A read then: canonicalizes the configured path
//! and confines it to a frozen root *before* opening; opens the exact path with
//! `O_NOFOLLOW` so a symlink final component is rejected even when it points
//! back inside a root; binds the opened descriptor to the root-checked target by
//! comparing their `(dev, ino)` (a parent-component swap between the check and
//! the open opens a different inode, which this rejects); and reads a bounded
//! prefix from that descriptor so a concurrent grow cannot cause an unbounded
//! read. `unsafe`-free, so it uses the `(dev, ino)` binding rather than
//! per-segment `openat`.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Upper bound on one TLS material file, matching CP-CFG's serving reader.
const MAX_TLS_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Canonicalizes and freezes the allowed TLS roots once, at startup. A root that
/// cannot be canonicalized (missing or unreadable) is dropped, so later reads
/// compare against a stable, symlink-free set rather than re-resolving roots on
/// every read.
#[must_use]
pub fn canonicalize_tls_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect()
}

/// Reads one TLS material file safely and returns its bytes.
///
/// `canonical_allowed_roots` must already be canonicalized (see
/// [`canonicalize_tls_roots`]).
///
/// # Errors
///
/// Returns a bounded, payload-free reason (never the path or the material) when
/// the path is not absolute, resolves outside the roots, is a symlink, changed
/// during open, is not a regular file, or exceeds 16 MiB.
pub fn read_tls_material(
    path: &Path,
    canonical_allowed_roots: &[PathBuf],
) -> Result<Vec<u8>, &'static str> {
    if !path.is_absolute() {
        return Err("tls material path is not absolute");
    }
    // Resolve and confine the configured path to a frozen root *before* opening,
    // so the root decision is made against the exact target the read is then
    // bound to.
    let canonical = std::fs::canonicalize(path).map_err(|_| "tls material is unavailable")?;
    if !canonical_allowed_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        return Err("tls material is outside the configured TLS roots");
    }
    let target = std::fs::metadata(&canonical).map_err(|_| "tls material is unavailable")?;
    if !target.is_file() {
        return Err("tls material must be a regular file");
    }
    // Open the exact configured path without following a final symlink.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "tls material is unavailable or is a symlink")?;
    let opened = file.metadata().map_err(|_| "tls material is unavailable")?;
    // Bind the opened descriptor to the root-checked target: if a parent
    // component was swapped between the containment check and the open, the open
    // resolved a different inode, which this rejects. Every later step reads
    // from this descriptor.
    if !opened.is_file() || opened.dev() != target.dev() || opened.ino() != target.ino() {
        return Err("tls material changed during open");
    }
    read_bounded_prefix(&mut file)
}

/// Reads at most `MAX_TLS_FILE_BYTES + 1` bytes from an already-opened
/// descriptor, so a file that grows after its size was observed cannot cause an
/// unbounded read; a full `MAX + 1` bytes means the file is too large.
fn read_bounded_prefix(file: &mut File) -> Result<Vec<u8>, &'static str> {
    let mut contents = Vec::new();
    file.take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|_| "tls material cannot be read")?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_TLS_FILE_BYTES {
        return Err("tls material is larger than 16 MiB");
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::{MAX_TLS_FILE_BYTES, canonicalize_tls_roots, read_tls_material};
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
        let roots = canonicalize_tls_roots(&[dir]);
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
        let dir = unique_dir("outside-file");
        let path = dir.join("ca.pem");
        write(&path, b"ca-bytes");
        // An allowed root that exists but does not contain the file.
        let roots = canonicalize_tls_roots(&[unique_dir("outside-root")]);
        assert!(read_tls_material(&path, &roots).is_err());
    }

    #[test]
    fn a_same_root_final_symlink_is_rejected() {
        // A symlink whose target is itself inside the allowed root must still be
        // rejected: opening the original path with O_NOFOLLOW fails.
        let dir = unique_dir("symlink");
        let real = dir.join("real.pem");
        write(&real, b"ca-bytes");
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&real, &link)
            .unwrap_or_else(|error| unreachable!("symlink: {error}"));
        let roots = canonicalize_tls_roots(&[dir]);
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
        let roots = canonicalize_tls_roots(std::slice::from_ref(&dir));
        assert!(read_tls_material(&dir, &roots).is_err());
    }

    #[test]
    fn a_file_larger_than_the_limit_is_rejected() {
        let dir = unique_dir("toobig");
        let path = dir.join("ca.pem");
        // A sparse file one byte over the limit; the bounded read stops at
        // MAX + 1 rather than allocating the whole file.
        let file =
            std::fs::File::create(&path).unwrap_or_else(|error| unreachable!("create: {error}"));
        file.set_len(MAX_TLS_FILE_BYTES + 2)
            .unwrap_or_else(|error| unreachable!("set_len: {error}"));
        let roots = canonicalize_tls_roots(&[dir]);
        assert!(read_tls_material(&path, &roots).is_err());
    }
}
