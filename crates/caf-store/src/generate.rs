//! One-chain store generation.
//!
//! [`Generator`] appends one backward-linked chain to a store. The first
//! file has a zero parent, every later file names the preceding file's
//! digest, and the last file's hex digest becomes the run's chain-tip
//! marker. Both stopping
//! conditions are checked before each file, sizes below
//! the 60-byte header are silently clamped up, content is written
//! through a temporary file in the store root and renamed into its
//! hash-derived location, and the run ends by writing the chain-tip
//! marker and atomically replacing `.metadata/all`.
//!
//! Concurrent generation runs against one store and verifying while a
//! writer is active are unsupported. A killed process can
//! leave a temporary file in the store root or a chain without a tip
//! marker; verification reports both conditions.

use std::backtrace::Backtrace;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use caf_format::{
    BLOCK_SIZE, ContentReader, ContentSeed, Digest, HEADER_SIZE, Hasher, Header, hash_to_path,
};

use crate::env::Env;
use crate::metadata;
use crate::size::{SampleError, SizeChooser};
use crate::temp::TempFile;

/// Default size of generated files in bytes when none is configured.
///
/// The CLI uses 4096 bytes by default.
pub const DEFAULT_FILE_SIZE: u64 = 4096;

/// Every file is at least its own 60-byte header; smaller requested
/// sizes are silently clamped up.
const MIN_FILE_SIZE: u64 = HEADER_SIZE as u64;

/// Generates one chain of content-addressable files in a store.
///
/// Create one with [`Generator::new`] for the defaults, or configure the
/// optional limits and size selection through [`Generator::builder`],
/// then call [`Generator::generate`]. With no limits set, generation
/// continues until the size chooser fails or the disk fills. The CLI
/// default of 100 files when no stopping option is given belongs to
/// the CLI, not this library.
///
/// # Examples
///
/// ```
/// use caf_store::{Generator, SizeChooser};
///
/// let store = tempfile::tempdir()?;
/// let report = Generator::builder(store.path())
///     .max_files(3)
///     .file_sizes(SizeChooser::fixed(4096))
///     .build()
///     .generate()?;
/// assert_eq!(report.files_created(), 3);
/// assert_eq!(report.bytes_written(), 3 * 4096);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Generator {
    env: Env,
    root: PathBuf,
    max_files: Option<u64>,
    max_disk_usage: Option<u64>,
    sizes: SizeChooser,
}

impl Generator {
    /// Creates a generator for the store at `root`, with every optional
    /// setting left at its default.
    ///
    /// The root and any missing metadata directories are created when
    /// generation runs. File sizes default to [`DEFAULT_FILE_SIZE`];
    /// both stopping conditions default to unbounded.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::builder(root).build()
    }

    /// Starts configuring a generator for the store at `root`.
    #[must_use]
    pub fn builder(root: impl Into<PathBuf>) -> GeneratorBuilder {
        GeneratorBuilder::with_env(Env::native(), root)
    }

    /// Starts configuring a generator that writes to an in-memory
    /// filesystem and draws deterministic randomness, and returns the
    /// controller for both.
    ///
    /// Nothing reaches the real filesystem: the store lands in the
    /// returned [`MockCtrl`](crate::MockCtrl), which can also seed
    /// content and inject I/O failures before the run.
    #[cfg(feature = "test-util")]
    #[must_use]
    pub fn builder_mocked(root: impl Into<PathBuf>) -> (GeneratorBuilder, crate::MockCtrl) {
        let (env, ctrl) = Env::mocked();
        (GeneratorBuilder::with_env(env, root), ctrl)
    }

    /// Generates the chain and updates the store metadata.
    ///
    /// # Errors
    ///
    /// Returns a [`GenerateError`] if a filesystem operation fails, the
    /// operating-system random source fails, or the size chooser reports
    /// a non-finite sample. Data files already renamed into place stay
    /// in the store, but a failed run writes no chain-tip marker, which
    /// verification reports.
    pub fn generate(mut self) -> Result<GenerationReport, GenerateError> {
        self.env
            .create_dir_all(&self.root)
            .map_err(|source| GenerateError::io("creating the store root", &self.root, source))?;

        let max_files = self.max_files.unwrap_or(u64::MAX);
        let max_disk_usage = self.max_disk_usage.unwrap_or(u64::MAX);
        let mut buffer = vec![0_u8; BLOCK_SIZE];
        let mut created_dirs = HashSet::new();
        let mut parent = Digest::ZERO;
        let mut files_created: u64 = 0;
        let mut bytes_written: u64 = 0;

        while files_created < max_files && bytes_written < max_disk_usage {
            let requested = self
                .sizes
                .next_size()
                .map_err(GenerateError::size_selection)?;
            let file_size = requested.max(MIN_FILE_SIZE);
            parent = write_file(
                &self.env,
                &self.root,
                parent,
                file_size,
                &mut buffer,
                &mut created_dirs,
            )?;
            files_created += 1;
            bytes_written = bytes_written.saturating_add(file_size);
        }

        metadata::write_chain_tip(&self.env, &self.root, parent)?;
        let all_digest = metadata::update_all(&self.env, &self.root)?;
        Ok(GenerationReport {
            files_created,
            bytes_written,
            chain_tip: parent,
            all_digest,
        })
    }
}

/// Configures a [`Generator`]; created by [`Generator::builder`].
///
/// All three settings are optional: unset limits leave generation
/// unbounded and unset sizes use [`DEFAULT_FILE_SIZE`].
#[derive(Debug)]
pub struct GeneratorBuilder {
    generator: Generator,
}

impl GeneratorBuilder {
    pub(crate) fn with_env(env: Env, root: impl Into<PathBuf>) -> Self {
        Self {
            generator: Generator {
                env,
                root: root.into(),
                max_files: None,
                max_disk_usage: None,
                sizes: SizeChooser::fixed(DEFAULT_FILE_SIZE),
            },
        }
    }

    /// Stops after `count` files. Zero generates no data files but still
    /// writes the all-zero chain-tip marker.
    #[must_use]
    pub fn max_files(mut self, count: u64) -> Self {
        self.generator.max_files = Some(count);
        self
    }

    /// Stops once `bytes` of content have been written. The budget is
    /// checked before each file, so the final file may overshoot the
    /// requested byte budget.
    #[must_use]
    pub fn max_disk_usage(mut self, bytes: u64) -> Self {
        self.generator.max_disk_usage = Some(bytes);
        self
    }

    /// Draws each file's size from `sizes`.
    #[must_use]
    pub fn file_sizes(mut self, sizes: SizeChooser) -> Self {
        self.generator.sizes = sizes;
        self
    }

    /// Returns the configured generator.
    #[must_use]
    pub fn build(self) -> Generator {
        self.generator
    }
}

/// Writes one file: header, deterministic content, and hash-derived
/// placement. Returns the file's digest (the next file's parent).
fn write_file(
    env: &Env,
    root: &Path,
    parent: Digest,
    file_size: u64,
    buffer: &mut [u8],
    created_dirs: &mut HashSet<PathBuf>,
) -> Result<Digest, GenerateError> {
    let seed = ContentSeed::from_bytes(env.random_array().map_err(GenerateError::randomness)?);
    let header =
        Header::new(parent, seed, file_size).expect("file size is clamped to the header minimum");

    // The temporary file lives in the store root so the final rename
    // stays on one filesystem. The name uses the parent digest prefix;
    // it is not part of the format contract.
    let mut temp = TempFile::create(env, root, &parent.to_hex()[..16])
        .map_err(|source| GenerateError::io("creating a temporary file", root, source))?;

    let mut hasher = Hasher::new();
    let encoded = header.encode();
    temp.file_mut()
        .write_all(&encoded)
        .map_err(|source| GenerateError::io("writing the header", temp.path(), source))?;
    hasher.update(encoded);

    // One reusable block-sized buffer streams SHAKE generation, file
    // writing, and BLAKE2b hashing; the reader squeezes only the bytes
    // the file needs.
    let mut reader = ContentReader::new(seed);
    let mut remaining = header.content_length();
    while remaining > 0 {
        let take = usize::try_from(remaining.min(BLOCK_SIZE as u64))
            .expect("chunk length is at most one block");
        let chunk = &mut buffer[..take];
        reader
            .read_exact(chunk)
            .expect("the content stream is infinite and never fails");
        temp.file_mut()
            .write_all(chunk)
            .map_err(|source| GenerateError::io("writing content", temp.path(), source))?;
        hasher.update(chunk);
        remaining -= take as u64;
    }

    let digest = hasher.finalize();
    let final_path = hash_to_path(root, digest);
    let shard_dir = final_path
        .parent()
        .expect("hash paths always have shard directories");
    if !created_dirs.contains(shard_dir) {
        env.create_dir_all(shard_dir).map_err(|source| {
            GenerateError::io("creating the shard directory", shard_dir, source)
        })?;
        created_dirs.insert(shard_dir.to_owned());
    }
    temp.persist(&final_path)
        .map_err(|source| GenerateError::io("placing the content file", &final_path, source))?;
    Ok(digest)
}

/// Structured results of one generation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationReport {
    files_created: u64,
    bytes_written: u64,
    chain_tip: Digest,
    all_digest: Digest,
}

impl GenerationReport {
    /// Number of data files created by this run.
    #[must_use]
    pub fn files_created(&self) -> u64 {
        self.files_created
    }

    /// Total bytes of file content written by this run.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Digest of the last file in the chain ([`Digest::ZERO`] when no
    /// files were generated); its hex form names the chain-tip marker.
    #[must_use]
    pub fn chain_tip(&self) -> Digest {
        self.chain_tip
    }

    /// The aggregate digest written to `.metadata/all`.
    #[must_use]
    pub fn all_digest(&self) -> Digest {
        self.all_digest
    }
}

/// Error generating a store.
///
/// Produced by [`Generator::generate`]. The `is_*` methods identify the
/// failed operation; [`GenerateError::path`] names the file or
/// directory involved, when there is one. The payload is boxed so
/// `Result<_, GenerateError>` stays one pointer wide on the success
/// path.
#[derive(Debug)]
pub struct GenerateError {
    inner: Box<GenerateErrorInner>,
}

#[derive(Debug)]
struct GenerateErrorInner {
    kind: GenerateErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum GenerateErrorKind {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Randomness {
        source: io::Error,
    },
    SizeSelection {
        source: SampleError,
    },
}

impl GenerateError {
    pub(crate) fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::new(GenerateErrorKind::Io {
            action,
            path: path.into(),
            source,
        })
    }

    pub(crate) fn randomness(source: io::Error) -> Self {
        Self::new(GenerateErrorKind::Randomness { source })
    }

    pub(crate) fn size_selection(source: SampleError) -> Self {
        Self::new(GenerateErrorKind::SizeSelection { source })
    }

    fn new(kind: GenerateErrorKind) -> Self {
        Self {
            inner: Box::new(GenerateErrorInner {
                kind,
                backtrace: Backtrace::capture(),
            }),
        }
    }

    /// Returns `true` for a filesystem failure.
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self.inner.kind, GenerateErrorKind::Io { .. })
    }

    /// Returns `true` if the operating-system random source failed.
    #[must_use]
    pub fn is_randomness(&self) -> bool {
        matches!(self.inner.kind, GenerateErrorKind::Randomness { .. })
    }

    /// Returns `true` if the size chooser reported an error.
    #[must_use]
    pub fn is_size_selection(&self) -> bool {
        matches!(self.inner.kind, GenerateErrorKind::SizeSelection { .. })
    }

    /// Returns the file or directory involved in a filesystem failure.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match &self.inner.kind {
            GenerateErrorKind::Io { path, .. } => Some(path),
            GenerateErrorKind::Randomness { .. } | GenerateErrorKind::SizeSelection { .. } => None,
        }
    }
}

impl Display for GenerateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner.kind {
            GenerateErrorKind::Io { action, path, .. } => {
                write!(f, "{action} at {}", path.display())
            }
            GenerateErrorKind::Randomness { .. } => {
                f.write_str("operating-system random source failed")
            }
            GenerateErrorKind::SizeSelection { .. } => {
                f.write_str("selecting the next file size failed")
            }
        }
    }
}

impl std::error::Error for GenerateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.inner.kind {
            GenerateErrorKind::Io { source, .. } | GenerateErrorKind::Randomness { source } => {
                Some(source)
            }
            GenerateErrorKind::SizeSelection { source } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GenerateError, GenerationReport, Generator};
    use crate::size::{ParseSizeError, SampleError, SizeSpecError};

    #[test]
    fn errors_are_safe_to_move_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GenerateError>();
        assert_send_sync::<ParseSizeError>();
        assert_send_sync::<SizeSpecError>();
        assert_send_sync::<SampleError>();
        assert_send_sync::<GenerationReport>();
    }

    #[test]
    fn io_errors_carry_the_path() {
        let err = GenerateError::io(
            "creating the store root",
            "/nowhere",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(err.is_io());
        assert_eq!(err.path(), Some(std::path::Path::new("/nowhere")));
        assert_eq!(err.to_string(), "creating the store root at /nowhere");
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn generator_debug_shows_the_configuration() {
        let generator = Generator::builder("/store").max_files(2).build();
        let debug = format!("{generator:?}");
        assert!(debug.contains("max_files: Some(2)"), "{debug}");
    }
}
