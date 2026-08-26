//! One-chain store generation.
//!
//! [`Generator`] appends one backward-linked chain to a store. The first
//! file has a zero parent, every later file names the preceding file's
//! identity, and the last file's hex identity becomes the run's chain-tip
//! marker. Both stopping
//! conditions are checked before each file, sizes below
//! the 60-byte header are silently clamped up, content is written
//! through a temporary file in the store root and renamed into its
//! hash-derived location, and the run ends by writing the chain-tip
//! marker and atomically replacing `.metadata/all`.
//!
//! The chain serializes file creation — each header embeds the previous
//! file's identity — so parallelism lives inside a single file:
//! [`GeneratorBuilder::jobs`] hands large files to
//! [`parallel_write`](crate::parallel_write), which produces the same
//! bytes and the same identity as the sequential path.
//!
//! Concurrent generation runs against one store and verifying while a
//! writer is active are unsupported. A killed process can
//! leave a temporary file in the store root or a chain without a tip
//! marker; verification reports both conditions.

use std::backtrace::Backtrace;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use caf_format::{
    BLOCK_SIZE, ContentReader, ContentSeed, Digest, FileId, Format, HEADER_SIZE, Hasher, Header,
    MerkleHash, MetadataDigest, fill_block_prefix_with_format, hash_to_path,
    v3_file_id_from_leaves, v3_leaf_hash,
};

use crate::env::Env;
use crate::size::{SampleError, SizeChooser};
use crate::temp::TempFile;
use crate::{MAX_JOBS, metadata, parallel_write};

/// Default size of generated files in bytes when none is configured.
///
/// The CLI uses 4096 bytes by default.
pub const DEFAULT_FILE_SIZE: u64 = 4096;

/// Writer threads the parallel path uses when none is configured.
///
/// Writers hand filled pages to the kernel rather than doing CPU work,
/// so the useful count is a small constant: it does not scale with the
/// core count the way [`GeneratorBuilder::jobs`] does.
const DEFAULT_WRITE_THREADS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

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
    format: Format,
    max_files: Option<u64>,
    max_disk_usage: Option<u64>,
    sizes: SizeChooser,
    jobs: NonZeroUsize,
    write_threads: NonZeroUsize,
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
            parent = self.write_file(parent, file_size, &mut buffer, &mut created_dirs)?;
            files_created += 1;
            bytes_written = bytes_written.saturating_add(file_size);
        }

        metadata::write_chain_tip(&self.env, &self.root, parent)?;
        let all_digest = metadata::update_all(&self.env, &self.root)?;
        Ok(GenerationReport {
            format: self.format,
            files_created,
            bytes_written,
            chain_tip: parent,
            all_digest,
        })
    }

    /// Writes one file: header, deterministic content, and hash-derived
    /// placement. Returns the file's identity (the next file's parent).
    fn write_file(
        &self,
        parent: Digest,
        file_size: u64,
        buffer: &mut [u8],
        created_dirs: &mut HashSet<PathBuf>,
    ) -> Result<Digest, GenerateError> {
        let seed =
            ContentSeed::from_bytes(self.env.random_array().map_err(GenerateError::randomness)?);
        let header = match self.format {
            Format::V2 => Header::new(parent, seed, file_size),
            Format::V3 => Header::new_v3(FileId::from_bytes(parent.into_inner()), seed, file_size),
        }
        .expect("file size is clamped to the header minimum");

        // The temporary file lives in the store root so the final rename
        // stays on one filesystem. The name uses the parent digest prefix;
        // it is not part of the format contract.
        let mut temp = TempFile::create(&self.env, &self.root, &parent.to_hex()[..16])
            .map_err(|source| GenerateError::io("creating a temporary file", &self.root, source))?;

        // Both paths produce the same bytes and the same identity; only
        // the thread count differs.
        let digest = if use_parallel_path(file_size, self.jobs) {
            parallel_write::write_content(&temp, &header, self.jobs, self.write_threads)?
        } else {
            write_content_serial(&mut temp, &header, buffer)?
        };

        let final_path = hash_to_path(&self.root, digest);
        let shard_dir = final_path
            .parent()
            .expect("hash paths always have shard directories");
        if !created_dirs.contains(shard_dir) {
            self.env.create_dir_all(shard_dir).map_err(|source| {
                GenerateError::io("creating the shard directory", shard_dir, source)
            })?;
            created_dirs.insert(shard_dir.to_owned());
        }
        temp.persist(&final_path)
            .map_err(|source| GenerateError::io("placing the content file", &final_path, source))?;
        Ok(digest)
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
                format: Format::V3,
                max_files: None,
                max_disk_usage: None,
                sizes: SizeChooser::fixed(DEFAULT_FILE_SIZE),
                jobs: NonZeroUsize::MIN,
                write_threads: DEFAULT_WRITE_THREADS,
            },
        }
    }

    /// Selects the on-disk format for every file in this generated chain.
    ///
    /// Version 3 is the default. Selecting [`Format::V2`] preserves the
    /// original whole-file `BLAKE2b` identity and v2 content domain.
    #[must_use]
    pub fn format(mut self, format: Format) -> Self {
        self.generator.format = format;
        self
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

    /// Generates each file's content on `count` threads (default 1,
    /// sequential).
    ///
    /// The store is identical to a sequential run: every file has the
    /// same content, digest, and path at any worker count, so this is
    /// purely a speed setting. It applies within one file — the chain
    /// serializes file creation, since each header embeds the previous
    /// file's identity — so it only speeds up large files. Files with
    /// fewer than two 1 MiB blocks per worker are written sequentially
    /// whatever the count is.
    ///
    /// Peak memory grows with the worker count and, for v3, with the
    /// transient 32-byte Merkle leaf stored for each 1 MiB file block.
    /// Values above [`MAX_JOBS`] clamp to it. The CLI rejects values below
    /// one as a usage error.
    #[must_use]
    pub fn jobs(mut self, count: NonZeroUsize) -> Self {
        self.generator.jobs = count.min(MAX_JOBS);
        self
    }

    /// Writes parallel-generated content on `count` threads (default 4).
    ///
    /// Writer threads submit filled blocks to the operating system and
    /// do no CPU work, so the useful count is a small constant that does
    /// not track the core count; [`GeneratorBuilder::jobs`] is the
    /// setting that does. Values above [`MAX_JOBS`] clamp to it. Has no
    /// effect on files written sequentially.
    #[must_use]
    pub fn write_threads(mut self, count: NonZeroUsize) -> Self {
        self.generator.write_threads = count.min(MAX_JOBS);
        self
    }

    /// Returns the configured generator.
    #[must_use]
    pub fn build(self) -> Generator {
        self.generator
    }
}

/// Whether a file of `file_size` bytes is worth generating in parallel.
///
/// Below two blocks per worker the threads have nothing to divide, and
/// the sequential path is one pass over one buffer with no coordination
/// at all. The output is the same either way, so this is only about
/// where the crossover sits.
fn use_parallel_path(file_size: u64, jobs: NonZeroUsize) -> bool {
    jobs > NonZeroUsize::MIN && parallel_write::total_blocks(file_size) >= 2 * jobs.get() as u64
}

/// Writes the header and content sequentially, hashing as it goes, and
/// returns the file's identity.
fn write_content_serial(
    temp: &mut TempFile,
    header: &Header,
    buffer: &mut [u8],
) -> Result<Digest, GenerateError> {
    if header.format() == Format::V3 {
        return write_v3_content_serial(temp, header, buffer);
    }

    let mut hasher = Hasher::new();
    let encoded = header.encode();
    temp.file_mut()
        .write_all(&encoded)
        .map_err(|source| GenerateError::io("writing the header", temp.path(), source))?;
    hasher.update(encoded);

    // One reusable block-sized buffer streams SHAKE generation, file
    // writing, and BLAKE2b hashing; the reader squeezes only the bytes
    // the file needs.
    let mut reader = ContentReader::new(header.content_seed());
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
    Ok(hasher.finalize())
}

/// Writes and hashes a v3 file one physical block at a time.
fn write_v3_content_serial(
    temp: &mut TempFile,
    header: &Header,
    buffer: &mut [u8],
) -> Result<Digest, GenerateError> {
    debug_assert_eq!(header.format(), Format::V3);
    let encoded = header.encode();
    let block_count = parallel_write::total_blocks(header.file_length());
    let leaf_count = usize::try_from(block_count).map_err(|_error| {
        GenerateError::io(
            "allocating v3 file hashes",
            temp.path(),
            io::Error::new(io::ErrorKind::FileTooLarge, "too many v3 file blocks"),
        )
    })?;
    let mut leaves: Vec<MerkleHash> = Vec::new();
    leaves.try_reserve_exact(leaf_count).map_err(|_source| {
        GenerateError::io(
            "allocating v3 file hashes",
            temp.path(),
            io::Error::from(io::ErrorKind::OutOfMemory),
        )
    })?;

    for index in 0..block_count {
        let offset = index * BLOCK_SIZE as u64;
        let len = usize::try_from((header.file_length() - offset).min(BLOCK_SIZE as u64))
            .expect("a physical block is at most BLOCK_SIZE bytes");
        let block = &mut buffer[..len];
        if index == 0 {
            let (header_bytes, content) = block.split_at_mut(HEADER_SIZE);
            header_bytes.copy_from_slice(&encoded);
            fill_block_prefix_with_format(Format::V3, header.content_seed(), 0, content);
        } else {
            fill_block_prefix_with_format(Format::V3, header.content_seed(), index, block);
        }
        leaves.push(v3_leaf_hash(index, &*block));
        temp.file_mut()
            .write_all(block)
            .map_err(|source| GenerateError::io("writing content", temp.path(), source))?;
    }

    Ok(Digest::from_bytes(
        v3_file_id_from_leaves(header.file_length(), leaves).into_inner(),
    ))
}

/// Structured results of one generation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationReport {
    format: Format,
    files_created: u64,
    bytes_written: u64,
    chain_tip: Digest,
    all_digest: MetadataDigest,
}

impl GenerationReport {
    /// CAF format used for every file in this generated chain.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

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

    /// Version-agnostic 20-byte representation of the last file identity.
    ///
    /// The all-zero value is returned when no files were generated. Its hex
    /// form names the chain-tip marker. For a typed v3 result, use
    /// [`GenerationReport::chain_tip_file_id`].
    #[must_use]
    pub fn chain_tip(&self) -> Digest {
        self.chain_tip
    }

    /// Typed chain-tip file ID for a v3 generation run.
    ///
    /// Returns `None` for a v2 run.
    #[must_use]
    pub fn chain_tip_file_id(&self) -> Option<FileId> {
        (self.format == Format::V3).then(|| FileId::from_bytes(self.chain_tip.into_inner()))
    }

    /// The aggregate digest written to `.metadata/all`.
    #[must_use]
    pub fn all_digest(&self) -> MetadataDigest {
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
    use std::num::NonZeroUsize;

    use caf_format::BLOCK_SIZE;

    use super::{GenerateError, GenerationReport, Generator, MAX_JOBS, use_parallel_path};
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

    #[test]
    fn worker_counts_clamp_to_the_maximum() {
        let generator = Generator::builder("/store")
            .jobs(NonZeroUsize::MAX)
            .write_threads(NonZeroUsize::MAX)
            .build();
        assert_eq!(generator.jobs, MAX_JOBS);
        assert_eq!(generator.write_threads, MAX_JOBS);
    }

    /// Below two blocks per worker the threads have nothing to divide,
    /// so the file is written sequentially however high `jobs` is.
    #[test]
    fn the_parallel_path_needs_two_blocks_per_worker() {
        let block = BLOCK_SIZE as u64;
        let jobs = |count| NonZeroUsize::new(count).expect("positive");
        assert!(!use_parallel_path(1 << 30, NonZeroUsize::MIN));
        assert!(!use_parallel_path(7 * block, jobs(4)));
        assert!(use_parallel_path(8 * block, jobs(4)));
        assert!(!use_parallel_path(block + 1, jobs(2)));
        assert!(use_parallel_path(4 * block, jobs(2)));
    }
}

#[cfg(all(test, feature = "test-util"))]
mod mocked_tests {
    use std::num::NonZeroUsize;
    use std::path::Path;

    use caf_format::BLOCK_SIZE;

    use crate::{Generator, SizeChooser};

    fn jobs(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("the tests use positive counts")
    }

    /// Eight blocks over four workers: past the dispatch threshold, so
    /// these runs really do take the parallel path.
    const PARALLEL_FILE_SIZE: u64 = 8 * BLOCK_SIZE as u64;

    /// A store generated in parallel is the store generated serially.
    /// The mocked random source is deterministic, so two runs draw the
    /// same seeds and must produce the same files at the same paths.
    #[test]
    fn a_parallel_run_produces_the_same_store_as_a_serial_run() {
        let store = |count| {
            let (builder, ctrl) = Generator::builder_mocked("/store");
            builder
                .max_files(2)
                .file_sizes(SizeChooser::fixed(PARALLEL_FILE_SIZE))
                .jobs(count)
                .build()
                .generate()
                .expect("mocked generation succeeds");
            let files: Vec<(std::path::PathBuf, Vec<u8>)> = ctrl
                .paths()
                .into_iter()
                .filter_map(|path| Some((path.clone(), ctrl.read_file(&path).ok()?)))
                .collect();
            files
        };

        let serial = store(NonZeroUsize::MIN);
        let parallel = store(jobs(4));
        assert_eq!(
            serial.len(),
            4,
            "two data files, a marker, and the aggregate"
        );
        assert_eq!(
            serial.iter().map(|(path, _)| path).collect::<Vec<_>>(),
            parallel.iter().map(|(path, _)| path).collect::<Vec<_>>(),
        );
        assert!(serial == parallel, "parallel generation changed the bytes");
    }

    /// A write failure mid-file fails the run, leaves no temporary file
    /// behind, and writes no chain-tip marker — the same surface a
    /// killed process leaves, which `verify` already reports.
    #[test]
    fn a_write_failure_leaves_no_temporary_and_no_chain_tip() {
        let (builder, ctrl) = Generator::builder_mocked("/store");
        // Fail one block in the middle of the file, not the first.
        ctrl.fail_write_at(3 * BLOCK_SIZE as u64, std::io::ErrorKind::PermissionDenied);

        let err = builder
            .max_files(1)
            .file_sizes(SizeChooser::fixed(PARALLEL_FILE_SIZE))
            .jobs(jobs(4))
            .build()
            .generate()
            .expect_err("the injected write failure fails the run");
        assert!(err.is_io());
        assert!(
            err.path().is_some_and(|path| path.starts_with("/store")),
            "{err:?}",
        );

        let files: Vec<_> = ctrl
            .paths()
            .into_iter()
            .filter(|path| ctrl.read_file(path).is_ok())
            .collect();
        assert!(
            files.is_empty(),
            "a file survived the failed run: {files:?}"
        );
        assert!(!ctrl.exists(Path::new("/store/.metadata/roots")));
    }

    /// A failed preallocation is the other pre-flight failure and has
    /// the same outcome.
    #[test]
    fn a_failed_preallocation_fails_the_run() {
        let (builder, ctrl) = Generator::builder_mocked("/store");
        ctrl.fail_set_len(std::io::ErrorKind::StorageFull);
        let err = builder
            .max_files(1)
            .file_sizes(SizeChooser::fixed(PARALLEL_FILE_SIZE))
            .jobs(jobs(4))
            .build()
            .generate()
            .expect_err("preallocation fails");
        assert!(err.is_io());
        let files: Vec<_> = ctrl
            .paths()
            .into_iter()
            .filter(|path| ctrl.read_file(path).is_ok())
            .collect();
        assert!(
            files.is_empty(),
            "a file survived the failed run: {files:?}"
        );
    }
}
