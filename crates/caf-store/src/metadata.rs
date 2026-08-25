//! Chain-tip markers and the `.metadata/all` aggregate.
//!
//! Each generation run ends by writing an empty marker file named after
//! the chain tip's hex digest under `.metadata/roots`, then recomputing
//! `.metadata/all` as the BLAKE2b-160 hex digest of the sorted marker
//! names concatenated as ASCII. A temporary file and rename make the
//! `all` replacement atomic, so an interrupted run cannot
//! leave a partial file. Concurrent updates remain unsupported and can
//! leave stale aggregate metadata.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;

use caf_format::{Digest, MetadataDigest, MetadataHasher};

use crate::env::Env;
use crate::generate::GenerateError;
use crate::temp::TempFile;

/// Store-metadata directory, a direct child of the store root.
pub(crate) const METADATA_DIR: &str = ".metadata";
/// Chain-tip marker directory inside [`METADATA_DIR`].
pub(crate) const ROOTS_DIR: &str = "roots";
/// Aggregate file inside [`METADATA_DIR`].
pub(crate) const ALL_FILE: &str = "all";

/// Writes the empty chain-tip marker for `tip` under `.metadata/roots`.
///
/// An existing marker with the same name is truncated without error.
pub(crate) fn write_chain_tip(
    env: &Env,
    store_root: &Path,
    tip: Digest,
) -> Result<(), GenerateError> {
    let roots_dir = store_root.join(METADATA_DIR).join(ROOTS_DIR);
    env.create_dir_all(&roots_dir).map_err(|source| {
        GenerateError::io("creating the chain-tip directory", &roots_dir, source)
    })?;
    let marker = roots_dir.join(tip.to_hex());
    env.create(&marker)
        .map_err(|source| GenerateError::io("writing the chain-tip marker", &marker, source))?;
    Ok(())
}

/// Recomputes `.metadata/all` from the current chain-tip markers and
/// replaces it atomically. Returns the aggregate digest.
///
/// Marker names are sorted byte-wise. Generated names are ASCII hex, so
/// this is also their lexical order.
pub(crate) fn update_all(env: &Env, store_root: &Path) -> Result<MetadataDigest, GenerateError> {
    let metadata_dir = store_root.join(METADATA_DIR);
    let roots_dir = metadata_dir.join(ROOTS_DIR);

    let entries = env
        .read_dir(&roots_dir)
        .map_err(|source| GenerateError::io("listing the chain-tip markers", &roots_dir, source))?;
    let mut names: Vec<OsString> = entries
        .into_iter()
        .map(crate::env::DirEntry::into_file_name)
        .collect();
    names.sort_unstable();

    let mut hasher = MetadataHasher::new();
    for name in &names {
        hasher.update(name.as_encoded_bytes());
    }
    let digest = hasher.finalize();

    let mut temp = TempFile::create(env, &metadata_dir, "all.tmp-").map_err(|source| {
        GenerateError::io(
            "creating the aggregate temporary file",
            &metadata_dir,
            source,
        )
    })?;
    temp.file_mut()
        .write_all(digest.to_hex().as_bytes())
        .map_err(|source| GenerateError::io("writing the aggregate", temp.path(), source))?;
    // Flush to stable storage before the rename so a power loss cannot
    // surface an empty `all`; a kill between write and rename is already
    // covered by the rename's atomicity.
    temp.file_mut()
        .sync_all()
        .map_err(|source| GenerateError::io("syncing the aggregate", temp.path(), source))?;
    let all_path = metadata_dir.join(ALL_FILE);
    temp.persist(&all_path)
        .map_err(|source| GenerateError::io("replacing the aggregate", &all_path, source))?;
    Ok(digest)
}
