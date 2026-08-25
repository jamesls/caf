//! Mapping between file identities and sharded on-disk store paths.
//!
//! CAF stores a file under the lowercase hex form of its v2 digest or v3
//! file ID, split
//! into three two-character shard directories and a 34-character basename:
//! `aa/bb/cc/<34-character basename>`. Parsing is case-insensitive and
//! rejects any path with a `.metadata` component. Generation always writes
//! lowercase.

use std::backtrace::Backtrace;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::path::{Component, Path, PathBuf};

use crate::digest::Digest;
use crate::hex::{self, ParseHexError};
use crate::merkle::FileId;

/// Number of two-character shard directories in a store path.
const SHARD_LEVELS: usize = 3;
/// Hex characters per shard directory.
const SHARD_CHARS: usize = 2;
/// Digest bytes each shard directory encodes.
const SHARD_BYTES: usize = SHARD_CHARS / 2;
/// Hex characters in the basename after the shards.
const BASENAME_CHARS: usize = Digest::SIZE * 2 - SHARD_LEVELS * SHARD_CHARS;
/// Digest bytes the basename encodes.
const BASENAME_BYTES: usize = BASENAME_CHARS / 2;
/// Hex characters in a full digest.
const DIGEST_CHARS: usize = Digest::SIZE * 2;
/// The metadata directory name; never part of a data-file path.
const METADATA_DIR: &str = ".metadata";

/// Returns the store-relative path for `digest`.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
///
/// use caf_format::{Digest, hash_to_relpath};
///
/// let digest = Digest::from_hex("f46b7e6f7eee7921da61a4779774a118aac54e98")?;
/// let expected: PathBuf =
///     ["f4", "6b", "7e", "6f7eee7921da61a4779774a118aac54e98"]
///         .iter()
///         .collect();
/// assert_eq!(hash_to_relpath(digest), expected);
/// # Ok::<(), caf_format::ParseHexError>(())
/// ```
#[must_use]
pub fn hash_to_relpath(digest: Digest) -> PathBuf {
    identity_to_relpath(digest.as_bytes())
}

/// Returns the store-relative path for a CAF v3 `file_id`.
#[must_use]
pub fn file_id_to_relpath(file_id: FileId) -> PathBuf {
    identity_to_relpath(file_id.as_bytes())
}

fn identity_to_relpath(identity: &[u8; Digest::SIZE]) -> PathBuf {
    // Generation and verification call this once per file, so the hex
    // form goes to the stack and only the returned path allocates.
    let mut buffer = [0_u8; DIGEST_CHARS];
    let hex = hex::encode_into(identity, &mut buffer);
    let mut path = PathBuf::with_capacity(hex.len() + SHARD_LEVELS);
    let mut rest = hex;
    for _ in 0..SHARD_LEVELS {
        let (shard, tail) = rest.split_at(SHARD_CHARS);
        path.push(shard);
        rest = tail;
    }
    path.push(rest);
    path
}

/// Returns the full path for `digest` under a store `root`.
#[must_use]
pub fn hash_to_path(root: impl AsRef<Path>, digest: Digest) -> PathBuf {
    root.as_ref().join(hash_to_relpath(digest))
}

/// Returns the full path for a CAF v3 `file_id` under a store `root`.
#[must_use]
pub fn file_id_to_path(root: impl AsRef<Path>, file_id: FileId) -> PathBuf {
    root.as_ref().join(file_id_to_relpath(file_id))
}

/// Extracts the digest from an on-disk path with the CAF layout.
///
/// The last four components must be three two-character hex shards and a
/// 34-character hex basename; anything before them (such as the store
/// root) is ignored and may be non-UTF-8. Matching is case-insensitive.
///
/// # Errors
///
/// Returns a [`ParsePathError`] for any other shape, including four-level
/// legacy layouts and paths containing a `.metadata` component. The error
/// says which check failed and, for a malformed shard or basename, which
/// component it was and why it is not hex.
///
/// # Examples
///
/// ```
/// use caf_format::parse_hash_from_path;
///
/// let digest = parse_hash_from_path(
///     "store/f4/6b/7e/6f7eee7921da61a4779774a118aac54e98",
/// )?;
/// assert_eq!(digest.to_hex(), "f46b7e6f7eee7921da61a4779774a118aac54e98");
///
/// // "not" is where the three-shard layout first fails to match.
/// let err = parse_hash_from_path("store/not/a/caf/path").unwrap_err();
/// assert!(err.is_invalid_component());
/// assert_eq!(err.component_index(), Some(0));
/// # Ok::<(), caf_format::ParsePathError>(())
/// ```
pub fn parse_hash_from_path(path: impl AsRef<Path>) -> Result<Digest, ParsePathError> {
    parse_identity_from_path(path).map(Digest::from_bytes)
}

/// Extracts a CAF v3 file ID from an on-disk path with the CAF layout.
///
/// This applies the same version-agnostic path validation as
/// [`parse_hash_from_path`] while keeping the result distinct from a v2
/// `BLAKE2b` digest.
///
/// # Errors
///
/// Returns [`ParsePathError`] when the path does not have the CAF layout.
pub fn parse_file_id_from_path(path: impl AsRef<Path>) -> Result<FileId, ParsePathError> {
    parse_identity_from_path(path).map(FileId::from_bytes)
}

fn parse_identity_from_path(path: impl AsRef<Path>) -> Result<[u8; Digest::SIZE], ParsePathError> {
    // Only the last four components decide the layout, so the walk keeps
    // a rolling window of them instead of collecting the whole path.
    let mut window = [OsStr::new(""); SHARD_LEVELS + 1];
    let mut seen = 0_usize;
    for component in path.as_ref().components() {
        let part = match component {
            Component::Normal(part) => part,
            // `..` is a path element like any other to the layout match;
            // it can never be hex, but it counts toward the last four.
            Component::ParentDir => OsStr::new(".."),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => continue,
        };
        if part == OsStr::new(METADATA_DIR) {
            return Err(ParsePathError::new(ParsePathErrorKind::MetadataComponent));
        }
        window.rotate_left(1);
        window[SHARD_LEVELS] = part;
        seen += 1;
    }
    if seen < window.len() {
        return Err(ParsePathError::new(ParsePathErrorKind::TooFewComponents {
            count: seen,
        }));
    }

    let [s1, s2, s3, basename] = window;
    let mut bytes = [0_u8; Digest::SIZE];
    let (shards, tail) = bytes.split_at_mut(SHARD_LEVELS * SHARD_BYTES);
    for (index, (shard, slot)) in [s1, s2, s3]
        .into_iter()
        .zip(shards.chunks_exact_mut(SHARD_BYTES))
        .enumerate()
    {
        slot.copy_from_slice(&decode_component::<SHARD_BYTES>(shard, index)?);
    }
    tail.copy_from_slice(&decode_component::<BASENAME_BYTES>(basename, SHARD_LEVELS)?);
    Ok(bytes)
}

/// Decodes the component at layout position `index` as the `N` bytes its
/// hex characters encode.
fn decode_component<const N: usize>(part: &OsStr, index: usize) -> Result<[u8; N], ParsePathError> {
    let part = part
        .to_str()
        .ok_or_else(|| ParsePathError::new(ParsePathErrorKind::NonUtf8Component { index }))?;
    hex::decode(part).map_err(|source| {
        ParsePathError::new(ParsePathErrorKind::InvalidComponent { index, source })
    })
}

/// Error parsing a store path into a v2 [`Digest`] or v3 [`FileId`].
///
/// Produced by [`parse_hash_from_path`] and [`parse_file_id_from_path`]. The
/// `is_*` methods identify the failed check; for a malformed shard or basename,
/// [`ParsePathError::component_index`] locates it and
/// [`ParsePathError::hex_error`] says whether its length or its
/// characters were wrong.
#[derive(Debug)]
pub struct ParsePathError {
    inner: Box<ParsePathErrorInner>,
}

/// Boxed so successful path parsing stays small; a rejected component carries
/// its own hex error.
#[derive(Debug)]
struct ParsePathErrorInner {
    kind: ParsePathErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum ParsePathErrorKind {
    MetadataComponent,
    TooFewComponents { count: usize },
    NonUtf8Component { index: usize },
    InvalidComponent { index: usize, source: ParseHexError },
}

impl ParsePathError {
    fn new(kind: ParsePathErrorKind) -> Self {
        Self {
            inner: Box::new(ParsePathErrorInner {
                kind,
                backtrace: Backtrace::capture(),
            }),
        }
    }

    /// Returns `true` if the path has a `.metadata` component, which is
    /// never part of a data-file path.
    #[must_use]
    pub fn is_metadata_component(&self) -> bool {
        matches!(self.inner.kind, ParsePathErrorKind::MetadataComponent)
    }

    /// Returns `true` if the path has fewer components than the layout
    /// needs, as a four-level legacy path does after its shards.
    #[must_use]
    pub fn is_too_few_components(&self) -> bool {
        matches!(self.inner.kind, ParsePathErrorKind::TooFewComponents { .. })
    }

    /// Returns `true` if a shard or basename component is not UTF-8.
    #[must_use]
    pub fn is_non_utf8_component(&self) -> bool {
        matches!(self.inner.kind, ParsePathErrorKind::NonUtf8Component { .. })
    }

    /// Returns `true` if a shard or basename component is not the hex
    /// the layout requires.
    #[must_use]
    pub fn is_invalid_component(&self) -> bool {
        matches!(self.inner.kind, ParsePathErrorKind::InvalidComponent { .. })
    }

    /// Returns the position of the component at fault, counting the
    /// shard directories from 0 and ending at the basename, when a
    /// single component is what failed.
    #[must_use]
    pub fn component_index(&self) -> Option<usize> {
        match self.inner.kind {
            ParsePathErrorKind::NonUtf8Component { index }
            | ParsePathErrorKind::InvalidComponent { index, .. } => Some(index),
            ParsePathErrorKind::MetadataComponent | ParsePathErrorKind::TooFewComponents { .. } => {
                None
            }
        }
    }

    /// Returns why a component was not hex, if that is what failed.
    #[must_use]
    pub fn hex_error(&self) -> Option<&ParseHexError> {
        match &self.inner.kind {
            ParsePathErrorKind::InvalidComponent { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Display for ParsePathError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner.kind {
            ParsePathErrorKind::MetadataComponent => {
                write!(f, "path contains a {METADATA_DIR} component")
            }
            ParsePathErrorKind::TooFewComponents { count } => write!(
                f,
                "path has {count} components, fewer than the {} of the CAF layout",
                SHARD_LEVELS + 1
            ),
            ParsePathErrorKind::NonUtf8Component { index } => {
                write_component(f, *index)?;
                f.write_str(" is not valid UTF-8")
            }
            ParsePathErrorKind::InvalidComponent { index, source } => {
                write_component(f, *index)?;
                if source.is_bad_length() {
                    f.write_str(" has the wrong length")
                } else {
                    f.write_str(" is not hex")
                }
            }
        }
    }
}

impl Error for ParsePathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.hex_error().map(|source| source as &dyn Error)
    }
}

/// Names the component at layout position `index` for error messages.
fn write_component(f: &mut Formatter<'_>, index: usize) -> fmt::Result {
    if index < SHARD_LEVELS {
        write!(f, "shard {} of the path", index + 1)
    } else {
        f.write_str("the path basename")
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        SHARD_LEVELS, file_id_to_path, file_id_to_relpath, hash_to_path, hash_to_relpath,
        parse_file_id_from_path, parse_hash_from_path,
    };
    use crate::{Digest, FileId};

    const HEX: &str = "f46b7e6f7eee7921da61a4779774a118aac54e98";

    fn digest() -> Digest {
        Digest::from_hex(HEX).unwrap()
    }

    fn relpath(parts: &[&str]) -> PathBuf {
        parts.iter().collect()
    }

    #[test]
    fn relpath_shards_the_lowercase_hex() {
        let expected = relpath(&["f4", "6b", "7e", "6f7eee7921da61a4779774a118aac54e98"]);
        assert_eq!(hash_to_relpath(digest()), expected);
    }

    #[test]
    fn full_path_joins_the_store_root() {
        let path = hash_to_path("/store/root", digest());
        assert_eq!(
            path,
            Path::new("/store/root").join(hash_to_relpath(digest()))
        );
    }

    #[test]
    fn parse_round_trips_generated_paths() {
        assert_eq!(
            parse_hash_from_path(hash_to_relpath(digest())).unwrap(),
            digest()
        );
        assert_eq!(
            parse_hash_from_path(hash_to_path("/some/store", digest())).unwrap(),
            digest(),
        );
    }

    #[test]
    fn v3_file_id_paths_round_trip_without_a_digest_conversion() {
        let file_id = FileId::from_hex(HEX).unwrap();
        assert_eq!(file_id_to_relpath(file_id), hash_to_relpath(digest()));
        assert_eq!(
            file_id_to_path("/some/store", file_id),
            hash_to_path("/some/store", digest()),
        );
        assert_eq!(
            parse_file_id_from_path(file_id_to_relpath(file_id)).unwrap(),
            file_id,
        );
    }

    #[test]
    fn parse_is_case_insensitive() {
        // Uppercase paths parse and are lowercased.
        let upper = relpath(&["F4", "6B", "7E", "6F7EEE7921DA61A4779774A118AAC54E98"]);
        assert_eq!(parse_hash_from_path(upper).unwrap(), digest());
    }

    #[test]
    fn parse_rejects_four_level_layout() {
        // Only aa/bb/cc/<34 chars> is a CAF path.
        let four_level = relpath(&["f4", "6b", "7e", "6f", "7eee7921da61a4779774a118aac54e98"]);
        let err = parse_hash_from_path(four_level).unwrap_err();
        assert!(err.is_invalid_component());
        assert_eq!(err.component_index(), Some(SHARD_LEVELS));
    }

    #[test]
    fn parse_rejects_metadata_component() {
        let inside_metadata = Path::new(".metadata")
            .join("roots")
            .join(hash_to_relpath(digest()));
        let err = parse_hash_from_path(inside_metadata).unwrap_err();
        assert!(err.is_metadata_component());
        assert_eq!(err.to_string(), "path contains a .metadata component");
    }

    #[test]
    fn parse_reports_why_a_component_is_not_hex() {
        // Each shape fails a different check, and the error says which.
        let long_shard = relpath(&["f46b", "7e", "6f", "7eee7921da61a4779774a118aac54e98"]);
        let err = parse_hash_from_path(&long_shard).unwrap_err();
        assert_eq!(err.component_index(), Some(0));
        assert!(err.hex_error().unwrap().is_bad_length());

        let short_basename = relpath(&["f4", "6b", "7e", "6f7eee7921da61a4779774a118aac54e9"]);
        let err = parse_hash_from_path(&short_basename).unwrap_err();
        assert_eq!(err.component_index(), Some(SHARD_LEVELS));
        assert!(err.hex_error().unwrap().is_bad_length());

        let not_hex = relpath(&["f4", "6b", "7e", "zz7eee7921da61a4779774a118aac54e98"]);
        let err = parse_hash_from_path(&not_hex).unwrap_err();
        assert_eq!(err.component_index(), Some(SHARD_LEVELS));
        assert!(err.hex_error().unwrap().is_bad_char());
        assert_eq!(err.to_string(), "the path basename is not hex");

        let too_short = relpath(&["f4", "6b", "7e"]);
        let err = parse_hash_from_path(&too_short).unwrap_err();
        assert!(err.is_too_few_components());
        assert_eq!(err.component_index(), None);
    }

    #[test]
    fn parse_ignores_current_dir_components() {
        let path = Path::new("./f4/6b/7e/6f7eee7921da61a4779774a118aac54e98");
        assert_eq!(parse_hash_from_path(path).unwrap(), digest());
    }

    #[test]
    fn parent_dir_components_count_toward_the_layout() {
        // `a/../f4/...` still parses (the `..` sits outside the last four
        // components); `f4/6b/../<basename>` does not.
        let ok = Path::new("a/../f4/6b/7e/6f7eee7921da61a4779774a118aac54e98");
        assert_eq!(parse_hash_from_path(ok).unwrap(), digest());
        let bad = Path::new("f4/6b/7e/../6f7eee7921da61a4779774a118aac54e98");
        assert!(
            parse_hash_from_path(bad)
                .unwrap_err()
                .is_invalid_component()
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_allows_non_utf8_store_roots() {
        // Only the shard and basename components must
        // be hex; the store root is arbitrary platform bytes.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let root = OsStr::from_bytes(b"sto\xffre");
        let path = Path::new(root).join(hash_to_relpath(digest()));
        assert_eq!(parse_hash_from_path(&path).unwrap(), digest());

        let bad_basename =
            Path::new("f4/6b/7e").join(OsStr::from_bytes(b"6f7eee7921da61a4779774a118aac54e\xff"));
        let err = parse_hash_from_path(&bad_basename).unwrap_err();
        assert!(err.is_non_utf8_component());
        assert_eq!(err.component_index(), Some(SHARD_LEVELS));
    }
}
