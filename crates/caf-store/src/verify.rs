//! Store verification: file, parent, root, and orphan checks.
//!
//! [`Verifier`] walks data files in sorted order. Only the
//! `.metadata` directory that is a direct child of the store root is
//! skipped. Directory symlinks are not followed, while file symlinks are.
//! Header validation uses the shared
//! [`Header::parse`] implementation, which validates version dispatch,
//! the format-specific checksum and descriptor, and the minimum length.
//!
//! Clean files cost one complete read: header parse, size check, and a
//! version-specific identity pass. CAF v2 uses ordered BLAKE2b-160; CAF v3
//! computes physical-block Merkle leaves and checks canonical content in the
//! same pass. Expected v2 content is regenerated for
//! [corruption analysis](crate::CorruptionReport) only after its digest fails.
//! Results are structured ([`VerificationReport`], [`Diagnostic`]); nothing
//! here prints or renders.
//!
//! [`Verifier::jobs`] is a global verification-worker budget. Contended
//! stores use the existing bounded file pipeline; when lanes outnumber
//! unstarted files, spare lanes read and analyze segments within large
//! files. Serial and parallel runs produce identical reports: per-file
//! work is order-independent, and collectors fold results back in sorted
//! file order before the store-level checks run. A worker thread the OS
//! refuses narrows a stage to the threads that did start, down to the
//! calling thread alone; thread-resource pressure never fails a run.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use caf_format::{
    BLOCK_SIZE, Digest, Format, HEADER_SIZE, Hasher, Header, HeaderError, MetadataDigest,
    MetadataHasher, hash_to_path, hash_to_relpath, parse_hash_from_path,
};

use crate::analysis::{self, CorruptionReport, read_full};
use crate::env::{DirEntry, Env, FileHandle};
use crate::metadata::{ALL_FILE, METADATA_DIR, ROOTS_DIR};
use crate::{MAX_JOBS, default_jobs, parallel_verify, pipeline};

/// Default corruption-analysis chunk size in bytes.
pub const DEFAULT_ANALYSIS_CHUNK_SIZE: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

/// Largest corruption-analysis chunk size honored, in bytes (64 MiB).
///
/// A resource bound rather than a semantic one: analysis allocates two
/// buffers of this size at most, and granularity this coarse already
/// tells a reader nothing. [`Verifier::analysis_chunk_size`] clamps
/// larger requests instead of attempting the allocation.
pub const MAX_ANALYSIS_CHUNK_SIZE: NonZeroUsize = NonZeroUsize::new(64 * 1024 * 1024).unwrap();

/// Directories nested more than this many levels below the store root
/// stop the walk with a structured error.
///
/// Valid stores are three levels deep (`aa/bb/cc`); the bound exists so
/// a pathological tree yields [`VerifyError::is_excessive_nesting`]
/// instead of unbounded work or a stack overflow.
const MAX_WALK_DEPTH: usize = 64;

/// Verifies every file and the metadata of a CAF store.
///
/// This is a configuration builder: set the optional analysis chunk
/// size and worker count, then call [`Verifier::verify`]. Verification
/// never modifies the store.
///
/// # Examples
///
/// ```
/// use caf_store::{Generator, SizeChooser, Verifier};
///
/// let store = tempfile::tempdir()?;
/// Generator::builder(store.path())
///     .max_files(2)
///     .file_sizes(SizeChooser::fixed(1024))
///     .build()
///     .generate()?;
///
/// let report = Verifier::new(store.path()).verify()?;
/// assert!(report.success());
/// assert_eq!(report.files_checked(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Verifier {
    env: Env,
    root: PathBuf,
    analysis_chunk_size: NonZeroUsize,
    jobs: NonZeroUsize,
}

impl Verifier {
    /// Creates a verifier for the store at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_env(Env::native(), root)
    }

    /// Creates a verifier that reads an in-memory filesystem, plus the
    /// controller that seeds and inspects it.
    ///
    /// Nothing reaches the real filesystem: seed a store through the
    /// returned [`MockCtrl`](crate::MockCtrl) (or generate one with
    /// [`Generator::builder_mocked`](crate::Generator::builder_mocked) and pass
    /// its controller's store on), then verify it. The mocked
    /// filesystem is thread-safe, so [`Verifier::jobs`] works as usual.
    #[cfg(feature = "test-util")]
    #[must_use]
    pub fn new_mocked(root: impl Into<PathBuf>) -> (Self, crate::MockCtrl) {
        let (env, ctrl) = Env::mocked();
        (Self::with_env(env, root), ctrl)
    }

    pub(crate) fn with_env(env: Env, root: impl Into<PathBuf>) -> Self {
        Self {
            env,
            root: root.into(),
            analysis_chunk_size: DEFAULT_ANALYSIS_CHUNK_SIZE,
            jobs: default_jobs(),
        }
    }

    /// Compares corrupted files against regenerated content in chunks of
    /// `bytes` (default [`DEFAULT_ANALYSIS_CHUNK_SIZE`]).
    ///
    /// Chunks are aligned to absolute file offsets. Smaller chunks give
    /// finer-grained corruption regions. The chunk size never affects
    /// whether verification succeeds, only the granularity of
    /// [`CorruptionReport`] regions. Values above
    /// [`MAX_ANALYSIS_CHUNK_SIZE`] clamp to it. The CLI rejects values
    /// below one as a usage error.
    #[must_use]
    pub fn analysis_chunk_size(mut self, bytes: NonZeroUsize) -> Self {
        self.analysis_chunk_size = bytes.min(MAX_ANALYSIS_CHUNK_SIZE);
        self
    }

    /// Sets the store-wide verification worker limit.
    ///
    /// The default is [`default_jobs`]. Different files run concurrently.
    /// When the worker budget exceeds
    /// the remaining file count, large files receive spare workers for
    /// positional reads and corruption analysis. The report is identical
    /// to a serial run: results are folded back in sorted file order and
    /// store-level checks run after every file. Peak memory grows with the
    /// worker count and, for v3, with the transient 32-byte Merkle leaf
    /// stored for each 1 MiB file block. It does not grow with the number
    /// of queued files. Values above [`MAX_JOBS`] clamp to it. The CLI
    /// rejects values below one as a usage error. The count is a budget,
    /// not a demand: if the OS refuses a worker thread, verification
    /// proceeds on the threads that did start — down to the calling
    /// thread alone — instead of failing.
    #[must_use]
    pub fn jobs(mut self, count: NonZeroUsize) -> Self {
        self.jobs = count.min(MAX_JOBS);
        self
    }

    /// Verifies the store and returns the structured report.
    ///
    /// Diagnostics appear in deterministic order: per-file
    /// findings in sorted data-file order (byte-wise on the path), then
    /// orphaned files in the same order, then the chain-tip aggregate
    /// check. The order does not depend on the [`Verifier::jobs`] count.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifyError`] when the store root has no
    /// `.metadata/roots` directory, when a filesystem operation fails
    /// (an unreadable file or directory, or a missing `.metadata/all`),
    /// or when store directories nest deeper than the walk supports.
    /// Detected corruption is never an error: it is reported through
    /// [`VerificationReport::diagnostics`].
    pub fn verify(&self) -> Result<VerificationReport, VerifyError> {
        let roots_dir = self.root.join(METADATA_DIR).join(ROOTS_DIR);
        match self.env.metadata(&roots_dir) {
            Ok(metadata) if metadata.is_dir() => {}
            // Absent, or present as something other than a directory:
            // this is what makes a path "not a store". Any other
            // failure is a filesystem error and keeps its cause.
            Ok(_) => return Err(self.not_a_store()),
            Err(err) if is_absent(&err) => return Err(self.not_a_store()),
            Err(source) => {
                return Err(VerifyError::io(
                    "reading the chain-tip directory",
                    &roots_dir,
                    source,
                ));
            }
        }
        let root_markers = read_marker_names(&self.env, &roots_dir)?;
        let marker_set = marker_digests(&root_markers);

        let files = collect_data_files(&self.env, &self.root)?;
        let files_checked = files.len() as u64;
        let mut checks = StoreChecks::new(files.len());
        let analysis_memory = analysis::AnalysisMemory::new();

        if self.jobs == NonZeroUsize::MIN {
            let mut scratch = parallel_verify::ScanBuffers::new();
            for path in files {
                checks.absorb(self.validate_file(path, 1, &mut scratch, &analysis_memory)?);
            }
        } else {
            self.validate_files_parallel(&files, &mut checks, &analysis_memory)?;
        }

        let mut diagnostics = checks.into_diagnostics(&marker_set, &self.root);
        self.check_roots_aggregate(root_markers, &mut diagnostics)?;

        Ok(VerificationReport {
            files_checked,
            diagnostics,
        })
    }

    fn not_a_store(&self) -> VerifyError {
        VerifyError::new(VerifyErrorKind::NotAStore {
            root: self.root.clone(),
        })
    }

    /// Runs the contended file pipeline, then lends all lanes across the
    /// final set of fewer-than-`jobs` files. The prefix keeps persistent
    /// worker buffers and performs no metadata planning, preserving the
    /// small-file path; tail outcomes are still folded in path order.
    fn validate_files_parallel(
        &self,
        files: &[PathBuf],
        checks: &mut StoreChecks,
        analysis_memory: &analysis::AnalysisMemory,
    ) -> Result<(), VerifyError> {
        let jobs = self.jobs.get();
        let contended = parallel_verify::contended_prefix_len(files.len(), jobs);

        if contended > 0 {
            self.validate_contended_files(&files[..contended], checks, analysis_memory)?;
        }
        self.validate_tail_files(&files[contended..], checks, analysis_memory)
    }

    /// The existing file-level regime: fixed workers, no length planning,
    /// and four claims of run-ahead per requested job.
    fn validate_contended_files(
        &self,
        files: &[PathBuf],
        checks: &mut StoreChecks,
        analysis_memory: &analysis::AnalysisMemory,
    ) -> Result<(), VerifyError> {
        pipeline::run(
            files.len(),
            self.jobs,
            || {
                let mut scratch = parallel_verify::ScanBuffers::new();
                move |index: usize| {
                    self.validate_file(files[index].clone(), 1, &mut scratch, analysis_memory)
                }
            },
            |outcome| checks.absorb(outcome),
        )
    }

    /// Plans and runs the remaining files when the free lanes outnumber
    /// them. Planning metadata failures deliberately give that path width
    /// one and are retried by normal validation, preserving its existing
    /// open/metadata error and sorted-error behavior.
    fn validate_tail_files(
        &self,
        files: &[PathBuf],
        checks: &mut StoreChecks,
        analysis_memory: &analysis::AnalysisMemory,
    ) -> Result<(), VerifyError> {
        if files.is_empty() {
            return Ok(());
        }
        let lengths: Vec<u64> = files
            .iter()
            .map(|path| self.env.metadata(path).map_or(0, crate::env::Metadata::len))
            .collect();
        let widths = parallel_verify::allocate_widths(&lengths, self.jobs.get());
        let mut start_order: Vec<usize> = (0..files.len()).collect();
        start_order.sort_unstable_by(|&left, &right| {
            lengths[right]
                .cmp(&lengths[left])
                .then_with(|| left.cmp(&right))
        });

        let (sender, receiver) = mpsc::channel();
        // One file group's whole task, shared by the spawned path and
        // the inline fallback when the OS refuses a thread.
        let run_group = |index: usize, sender: &mpsc::Sender<TailMessage>| {
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                let mut scratch = parallel_verify::ScanBuffers::new();
                self.validate_file(
                    files[index].clone(),
                    widths[index],
                    &mut scratch,
                    analysis_memory,
                )
            }));
            let message = match result {
                Ok(result) => TailMessage::Outcome { index, result },
                Err(payload) => TailMessage::Panic(payload),
            };
            let _ignored = sender.send(message);
        };
        let (mut outcomes, panic_payload) = thread::scope(|scope| {
            for index in start_order {
                let group_sender = sender.clone();
                let run_group = &run_group;
                let spawned = thread::Builder::new()
                    .spawn_scoped(scope, move || run_group(index, &group_sender));
                if spawned.is_err() {
                    // The OS refused a thread; run this file's group on
                    // the calling thread so resource pressure degrades
                    // to serial work instead of a panic.
                    run_group(index, &sender);
                }
            }
            drop(sender);

            let mut outcomes = BTreeMap::new();
            let mut panic_payload = None;
            for message in receiver {
                match message {
                    TailMessage::Outcome { index, result } => {
                        outcomes.insert(index, result);
                    }
                    TailMessage::Panic(payload) => {
                        if panic_payload.is_none() {
                            panic_payload = Some(payload);
                        }
                    }
                }
            }
            (outcomes, panic_payload)
        });

        if let Some(payload) = panic_payload {
            panic::resume_unwind(payload);
        }
        for index in 0..files.len() {
            checks.absorb(
                outcomes
                    .remove(&index)
                    .expect("every tail group returns an outcome unless it panics")?,
            );
        }
        Ok(())
    }

    /// Validates one data file and returns everything it contributes to
    /// the report. Self-contained per file, so serial and parallel runs
    /// produce identical outcomes.
    fn validate_file(
        &self,
        path: PathBuf,
        width: usize,
        scratch: &mut parallel_verify::ScanBuffers,
        analysis_memory: &analysis::AnalysisMemory,
    ) -> Result<FileOutcome, VerifyError> {
        let mut diagnostics = Vec::new();
        let Ok(digest_from_path) = parse_hash_from_path(&path) else {
            diagnostics.push(Diagnostic::InvalidPathLayout { path: path.clone() });
            return Ok(FileOutcome {
                record: FileRecord {
                    path,
                    digest: None,
                    canonical_path: false,
                    parent: None,
                    format: None,
                },
                diagnostics,
            });
        };
        let canonical_path = is_canonical_path(&path, &self.root, digest_from_path);

        let mut file = self
            .env
            .open(&path)
            .map_err(|source| VerifyError::io("opening a data file", &path, source))?;
        let actual_size = file
            .metadata()
            .map_err(|source| VerifyError::io("reading data-file metadata", &path, source))?
            .len();

        let mut header_bytes = [0_u8; HEADER_SIZE];
        let header_len = read_full(&mut file, &mut header_bytes)
            .map_err(|source| VerifyError::io("reading a data-file header", &path, source))?;
        let header = match Header::parse(&header_bytes[..header_len]) {
            Ok(header) => header,
            Err(source) => {
                diagnostics.push(Diagnostic::InvalidHeader {
                    path: path.clone(),
                    source,
                });
                return Ok(FileOutcome {
                    record: FileRecord {
                        path,
                        digest: Some(digest_from_path),
                        canonical_path,
                        parent: None,
                        format: None,
                    },
                    diagnostics,
                });
            }
        };

        if actual_size != header.file_length() {
            diagnostics.push(Diagnostic::SizeMismatch {
                path: path.clone(),
                expected: header.file_length(),
                actual: actual_size,
            });
        }

        // Reapply the cap to the opened file's size. Planning metadata
        // normally matches it, but this keeps a failed/stale planning
        // read from ever creating more lanes than the crossover allows.
        let width = width.min(parallel_verify::width_cap(actual_size));
        let (actual_digest, content_matches) = hash_validated_file(
            &mut file,
            &header,
            &header_bytes[..header_len],
            actual_size,
            width,
            scratch,
        )
        .map_err(|source| VerifyError::io("reading a data file", &path, source))?;

        if actual_digest != digest_from_path || !content_matches {
            let regions = analyze_mismatch(
                &mut file,
                &header,
                actual_size,
                self.analysis_chunk_size,
                width,
                analysis_memory,
            )
            .map_err(|source| VerifyError::io("analyzing a corrupted file", &path, source))?;
            diagnostics.push(Diagnostic::DigestMismatch {
                report: CorruptionReport {
                    path: path.clone(),
                    format: header.format(),
                    expected: digest_from_path,
                    actual: actual_digest,
                    actual_size,
                    expected_size: header.file_length(),
                    content_seed: header.content_seed(),
                    regions,
                },
            });
        }

        let parent = if header.is_root() {
            None
        } else {
            Some(header.parent())
        };
        Ok(FileOutcome {
            record: FileRecord {
                path,
                digest: Some(digest_from_path),
                canonical_path,
                parent,
                format: Some(header.format()),
            },
            diagnostics,
        })
    }

    /// Recomputes the chain-tip aggregate and compares `.metadata/all`.
    fn check_roots_aggregate(
        &self,
        mut root_markers: Vec<OsString>,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<(), VerifyError> {
        root_markers.sort_unstable();
        let mut hasher = MetadataHasher::new();
        for name in &root_markers {
            hasher.update(name.as_encoded_bytes());
        }
        let computed = hasher.finalize();

        let all_path = self.root.join(METADATA_DIR).join(ALL_FILE);
        let stored = self.env.read(&all_path).map_err(|source| {
            VerifyError::io("reading the chain-tip aggregate", &all_path, source)
        })?;
        if stored != computed.to_hex().as_bytes() {
            diagnostics.push(Diagnostic::RootsMismatch {
                path: all_path,
                stored,
                computed,
            });
        }
        Ok(())
    }
}

/// Computes the version-specific identity and strict-content result.
fn hash_validated_file(
    file: &mut FileHandle,
    header: &Header,
    header_bytes: &[u8],
    actual_size: u64,
    width: usize,
    scratch: &mut parallel_verify::ScanBuffers,
) -> io::Result<(Digest, bool)> {
    match header.format() {
        Format::V2 => {
            let digest = if width >= 2 {
                parallel_verify::hash_file(file, header_bytes, actual_size, width)
            } else {
                // A previous v3 file may have left the block buffer
                // shorter; whole-file reads want the full block.
                if scratch.block.len() < BLOCK_SIZE {
                    scratch.block.resize(BLOCK_SIZE, 0);
                }
                hash_whole_file(file, header_bytes, &mut scratch.block)
            }?;
            Ok((digest, true))
        }
        Format::V3 => {
            let result =
                parallel_verify::hash_v3_file(file, header, actual_size, width.max(1), scratch)?;
            Ok((result.digest, result.content_matches))
        }
    }
}

fn analyze_mismatch(
    file: &mut FileHandle,
    header: &Header,
    actual_size: u64,
    chunk_size: NonZeroUsize,
    width: usize,
    memory: &analysis::AnalysisMemory,
) -> io::Result<Vec<analysis::CorruptionRegion>> {
    if width >= 2 {
        analysis::analyze_parallel(file, header, actual_size, chunk_size, width, memory)
    } else {
        analysis::analyze(file, header, actual_size, chunk_size)
    }
}

enum TailMessage {
    Outcome {
        index: usize,
        result: Result<FileOutcome, VerifyError>,
    },
    Panic(Box<dyn std::any::Any + Send>),
}

/// What one data file contributed to the store-level checks.
struct FileRecord {
    path: PathBuf,
    /// The digest the path claims, when the path has the CAF layout.
    digest: Option<Digest>,
    /// Whether the path is exactly the canonical lowercase store path
    /// for its digest below the store root, rather than another
    /// spelling or depth that decodes to the same digest.
    canonical_path: bool,
    /// The parent link from a validated non-root header.
    parent: Option<Digest>,
    /// Parsed format of this file, absent when its header is invalid.
    format: Option<Format>,
}

/// Everything one file's validation contributes to the report: its
/// diagnostics (in intra-file order) and its store-level record.
struct FileOutcome {
    record: FileRecord,
    diagnostics: Vec<Diagnostic>,
}

/// Folds per-file outcomes, absorbed in sorted file order, into the
/// store-level state shared by the serial and parallel paths.
struct StoreChecks {
    referenced: HashSet<Digest>,
    outcomes: Vec<FileOutcome>,
}

impl StoreChecks {
    fn new(file_count: usize) -> Self {
        Self {
            referenced: HashSet::new(),
            outcomes: Vec::with_capacity(file_count),
        }
    }

    /// Absorbs one file's outcome; call in sorted file order.
    fn absorb(&mut self, outcome: FileOutcome) {
        if let Some(parent) = outcome.record.parent {
            self.referenced.insert(parent);
        }
        self.outcomes.push(outcome);
    }

    /// Runs the store-level checks and returns all diagnostics.
    ///
    /// Each file's chain-format finding joins its own diagnostics, so
    /// per-file findings stay in sorted path order; orphan findings
    /// follow in the same order. A file is orphaned when nothing
    /// references it and it is not a chain tip. Files outside the
    /// layout have no digest and are always orphans. Marker names are
    /// compared as exact lowercase hex.
    fn into_diagnostics(
        mut self,
        marker_set: &HashSet<Digest>,
        store_root: &Path,
    ) -> Vec<Diagnostic> {
        let chain_findings = self.chain_findings(store_root);
        let mut diagnostics = Vec::new();
        for (outcome, finding) in self.outcomes.iter_mut().zip(chain_findings) {
            diagnostics.append(&mut outcome.diagnostics);
            diagnostics.extend(finding);
        }
        for outcome in self.outcomes {
            let record = outcome.record;
            let is_referenced = match record.digest {
                Some(digest) => self.referenced.contains(&digest) || marker_set.contains(&digest),
                None => false,
            };
            if !is_referenced {
                diagnostics.push(Diagnostic::OrphanedFile { path: record.path });
            }
        }
        diagnostics
    }

    /// Computes each file's missing-parent and cross-version findings,
    /// index-aligned with the outcomes.
    ///
    /// Every data path has already been walked and validated, so parent
    /// presence and format are resolved from digest-keyed records
    /// without a redundant metadata syscall, `PathBuf` construction, or
    /// full-path hash per child. Only records at their canonical path
    /// enter the map, so another accepted path that decodes to the same
    /// digest can never stand in for the parent.
    fn chain_findings(&self, store_root: &Path) -> Vec<Option<Diagnostic>> {
        let records: HashMap<Digest, Option<Format>> = self
            .outcomes
            .iter()
            .filter_map(|outcome| {
                let record = &outcome.record;
                if !record.canonical_path {
                    return None;
                }
                Some((record.digest?, record.format))
            })
            .collect();
        self.outcomes
            .iter()
            .map(|outcome| {
                let record = &outcome.record;
                let parent = record.parent?;
                let Some(parent_format) = records.get(&parent) else {
                    return Some(Diagnostic::MissingParent {
                        path: record.path.clone(),
                        parent,
                        parent_path: hash_to_path(store_root, parent),
                    });
                };
                match (record.format, *parent_format) {
                    (Some(child_format), Some(parent_format)) if child_format != parent_format => {
                        Some(Diagnostic::ChainFormatMismatch {
                            path: record.path.clone(),
                            parent,
                            parent_path: hash_to_path(store_root, parent),
                            child_format,
                            parent_format,
                        })
                    }
                    _ => None,
                }
            })
            .collect()
    }
}

/// Returns `true` when `path` is exactly the canonical store path for
/// `digest`: the lowercase sharded spelling directly below `root`.
///
/// Layout parsing accepts any hex case, so on a case-sensitive
/// filesystem a mixed-case spelling can decode to a digest whose
/// canonical path holds no file. Only the exact spelling may satisfy a
/// parent link or supply a parent's format.
fn is_canonical_path(path: &Path, root: &Path, digest: Digest) -> bool {
    path.strip_prefix(root)
        .is_ok_and(|relative| relative == hash_to_relpath(digest))
}

/// Returns `true` when a metadata failure means "nothing usable is
/// there", rather than a filesystem problem worth reporting: the path is
/// missing, or a component of it is not a directory.
fn is_absent(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Hashes the already-read header bytes plus the rest of `file` through
/// BLAKE2b-160 in one sequential pass.
fn hash_whole_file(
    mut file: impl Read,
    header_bytes: &[u8],
    buffer: &mut [u8],
) -> io::Result<Digest> {
    let mut hasher = Hasher::new();
    hasher.update(header_bytes);
    loop {
        let n = match file.read(buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize())
}

/// Reads the chain-tip marker names from `.metadata/roots`.
fn read_marker_names(env: &Env, roots_dir: &Path) -> Result<Vec<OsString>, VerifyError> {
    let entries = env
        .read_dir(roots_dir)
        .map_err(|source| VerifyError::io("listing the chain-tip markers", roots_dir, source))?;
    Ok(entries.into_iter().map(DirEntry::into_file_name).collect())
}

/// Parses exact lowercase digest marker names once, avoiding a hex-string
/// allocation for every data file during orphan checks.
fn marker_digests(names: &[OsString]) -> HashSet<Digest> {
    names
        .iter()
        .filter_map(|name| {
            let text = name.to_str()?;
            let digest = Digest::from_hex(text).ok()?;
            (digest.to_hex() == text).then_some(digest)
        })
        .collect()
}

/// Returns every data file under `root` in byte-wise path order.
///
/// The walk uses an explicit worklist, never recursion, so store
/// nesting cannot translate into stack depth; directories deeper than
/// [`MAX_WALK_DEPTH`] produce a structured error.
fn collect_data_files(env: &Env, root: &Path) -> Result<Vec<PathBuf>, VerifyError> {
    // (directory, its depth below the store root); the root is depth 0.
    let mut pending: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut files = Vec::new();
    while let Some((dir, depth)) = pending.pop() {
        let entries = env
            .read_dir(&dir)
            .map_err(|source| VerifyError::io("listing a store directory", &dir, source))?;
        for entry in entries {
            let file_type = entry.file_type();
            if file_type.is_symlink() {
                // Directory symlinks are invisible; file
                // symlinks (and broken ones) verify like regular files.
                match env.metadata(entry.path()) {
                    Ok(target) if target.is_dir() => {}
                    _ => files.push(entry.into_path()),
                }
            } else if file_type.is_dir() {
                // Skip exactly the `.metadata` directory
                // that is a direct child of the store root.
                if depth == 0 && entry.file_name() == OsStr::new(METADATA_DIR) {
                    continue;
                }
                if depth >= MAX_WALK_DEPTH {
                    return Err(VerifyError::new(VerifyErrorKind::ExcessiveNesting {
                        path: entry.into_path(),
                    }));
                }
                pending.push((entry.into_path(), depth + 1));
            } else {
                files.push(entry.into_path());
            }
        }
    }
    files.sort_unstable_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    Ok(files)
}

/// Severity of a [`Diagnostic`].
///
/// `Display` yields the uppercase prefix `ERROR`, `CORRUPTION`, or
/// `ORPHAN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// The store layout is malformed (not corruption of a valid file).
    Error,
    /// File content, a header, a link, or metadata fails validation.
    Corruption,
    /// A file exists that nothing references.
    Orphan,
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "ERROR",
            Self::Corruption => "CORRUPTION",
            Self::Orphan => "ORPHAN",
        })
    }
}

/// One verification finding, in deterministic report order.
///
/// The CLI renders every variant as a diagnostic line. Any diagnostic
/// means verification
/// failed ([`VerificationReport::success`] is `false`).
#[derive(Debug)]
#[non_exhaustive]
pub enum Diagnostic {
    /// A file's path does not follow the `aa/bb/cc/<34-character>`
    /// store layout (severity `ERROR`).
    InvalidPathLayout {
        /// The offending file.
        path: PathBuf,
    },
    /// The 60-byte header failed validation; the file cannot be
    /// checked further (severity `CORRUPTION`). Includes unknown or
    /// unsupported descriptors and file lengths below the header size.
    InvalidHeader {
        /// The offending file.
        path: PathBuf,
        /// The failed header check.
        source: HeaderError,
    },
    /// The size on disk differs from the header's file length
    /// (severity `CORRUPTION`).
    SizeMismatch {
        /// The offending file.
        path: PathBuf,
        /// The file length recorded in the header.
        expected: u64,
        /// The size on disk.
        actual: u64,
    },
    /// The version-specific file identity does not match the path, or v3
    /// content is noncanonical (severity `CORRUPTION`); carries the full
    /// corruption analysis.
    DigestMismatch {
        /// The corruption analysis for the file.
        report: CorruptionReport,
    },
    /// A validated file names a parent that is not in the store
    /// (severity `CORRUPTION`).
    MissingParent {
        /// The file whose header names the parent.
        path: PathBuf,
        /// The missing parent's digest.
        parent: Digest,
        /// Where the parent would live in this store.
        parent_path: PathBuf,
    },
    /// A child and its resolved parent use different CAF versions
    /// (severity `ERROR`). Stores may contain both versions, but one
    /// chain must be homogeneous.
    ChainFormatMismatch {
        /// The child file containing the invalid link.
        path: PathBuf,
        /// The parent identifier stored in the child header.
        parent: Digest,
        /// The resolved parent path.
        parent_path: PathBuf,
        /// Format parsed from the child header.
        child_format: Format,
        /// Format parsed from the parent header.
        parent_format: Format,
    },
    /// No file references this file and it is not a chain tip
    /// (severity `ORPHAN`).
    OrphanedFile {
        /// The unreferenced file.
        path: PathBuf,
    },
    /// `.metadata/all` does not match the digest of the sorted
    /// chain-tip marker names (severity `CORRUPTION`).
    RootsMismatch {
        /// The aggregate file (`.metadata/all`).
        path: PathBuf,
        /// The bytes stored in the aggregate file.
        stored: Vec<u8>,
        /// The digest recomputed from the marker names.
        computed: MetadataDigest,
    },
}

impl Diagnostic {
    /// Returns the severity classification.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidPathLayout { .. } | Self::ChainFormatMismatch { .. } => Severity::Error,
            Self::InvalidHeader { .. }
            | Self::SizeMismatch { .. }
            | Self::DigestMismatch { .. }
            | Self::MissingParent { .. }
            | Self::RootsMismatch { .. } => Severity::Corruption,
            Self::OrphanedFile { .. } => Severity::Orphan,
        }
    }

    /// Returns the file this diagnostic is about.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::InvalidPathLayout { path }
            | Self::InvalidHeader { path, .. }
            | Self::SizeMismatch { path, .. }
            | Self::MissingParent { path, .. }
            | Self::ChainFormatMismatch { path, .. }
            | Self::OrphanedFile { path }
            | Self::RootsMismatch { path, .. } => path,
            Self::DigestMismatch { report } => report.path(),
        }
    }
}

/// Structured results of one verification run.
///
/// Verification succeeds exactly when there are no diagnostics.
#[derive(Debug)]
pub struct VerificationReport {
    files_checked: u64,
    diagnostics: Vec<Diagnostic>,
}

impl VerificationReport {
    /// Returns `true` when the store verified cleanly.
    #[must_use]
    pub fn success(&self) -> bool {
        self.diagnostics.is_empty()
    }

    /// Number of data files examined (including files that failed).
    #[must_use]
    pub fn files_checked(&self) -> u64 {
        self.files_checked
    }

    /// Returns all findings in deterministic report order.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Returns the corruption analyses, in diagnostic order.
    pub fn corruption_reports(&self) -> impl Iterator<Item = &CorruptionReport> {
        self.diagnostics.iter().filter_map(|diagnostic| {
            if let Diagnostic::DigestMismatch { report } = diagnostic {
                Some(report)
            } else {
                None
            }
        })
    }
}

/// Error verifying a store.
///
/// Produced by [`Verifier::verify`] for conditions that stop
/// verification. Detected corruption is a [`Diagnostic`], never an
/// error. The `is_*` methods identify the
/// failure; [`VerifyError::path`] names the file or directory involved.
#[derive(Debug)]
pub struct VerifyError {
    inner: Box<VerifyErrorInner>,
}

#[derive(Debug)]
struct VerifyErrorInner {
    kind: VerifyErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum VerifyErrorKind {
    NotAStore {
        root: PathBuf,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    ExcessiveNesting {
        path: PathBuf,
    },
}

impl VerifyError {
    fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::new(VerifyErrorKind::Io {
            action,
            path: path.into(),
            source,
        })
    }

    fn new(kind: VerifyErrorKind) -> Self {
        Self {
            inner: Box::new(VerifyErrorInner {
                kind,
                backtrace: Backtrace::capture(),
            }),
        }
    }

    /// Returns `true` if the root has no `.metadata/roots` directory.
    #[must_use]
    pub fn is_not_a_store(&self) -> bool {
        matches!(self.inner.kind, VerifyErrorKind::NotAStore { .. })
    }

    /// Returns `true` for a filesystem failure.
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self.inner.kind, VerifyErrorKind::Io { .. })
    }

    /// Returns `true` if store directories nest deeper than the walk
    /// supports (a pathological tree, never a generated store).
    #[must_use]
    pub fn is_excessive_nesting(&self) -> bool {
        matches!(self.inner.kind, VerifyErrorKind::ExcessiveNesting { .. })
    }

    /// Returns the file or directory involved in the failure.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match &self.inner.kind {
            VerifyErrorKind::NotAStore { root } => Some(root),
            VerifyErrorKind::Io { path, .. } | VerifyErrorKind::ExcessiveNesting { path } => {
                Some(path)
            }
        }
    }
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner.kind {
            VerifyErrorKind::NotAStore { root } => write!(
                f,
                "{} is not a valid CAF store (missing {METADATA_DIR}/{ROOTS_DIR} directory)",
                root.display(),
            ),
            VerifyErrorKind::Io { action, path, .. } => {
                write!(f, "{action} at {}", path.display())
            }
            VerifyErrorKind::ExcessiveNesting { path } => write!(
                f,
                "store directories nest more than {MAX_WALK_DEPTH} levels deep at {}",
                path.display(),
            ),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.inner.kind {
            VerifyErrorKind::NotAStore { .. } | VerifyErrorKind::ExcessiveNesting { .. } => None,
            VerifyErrorKind::Io { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::num::NonZeroUsize;

    use super::{
        Diagnostic, MAX_ANALYSIS_CHUNK_SIZE, MAX_JOBS, Severity, VerificationReport, Verifier,
        VerifyError, marker_digests,
    };
    use caf_format::Digest;

    #[test]
    fn errors_and_results_are_safe_to_move_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VerifyError>();
        assert_send_sync::<VerificationReport>();
        assert_send_sync::<Diagnostic>();
    }

    #[test]
    fn severity_displays_the_frozen_prefixes() {
        assert_eq!(Severity::Error.to_string(), "ERROR");
        assert_eq!(Severity::Corruption.to_string(), "CORRUPTION");
        assert_eq!(Severity::Orphan.to_string(), "ORPHAN");
    }

    #[test]
    fn only_exact_lowercase_root_markers_resolve_to_digests() {
        let digest = Digest::from_bytes([0xab; Digest::SIZE]);
        let markers = [
            OsString::from(digest.to_hex()),
            OsString::from(digest.to_hex().to_uppercase()),
            OsString::from("not-a-digest"),
        ];
        assert_eq!(marker_digests(&markers), HashSet::from([digest]));
    }

    /// Oversized settings clamp to the documented resource bounds
    /// instead of reaching an allocation or a thread spawn that fails.
    #[test]
    fn oversized_settings_clamp_to_the_maximums() {
        let verifier = Verifier::new("/store")
            .analysis_chunk_size(NonZeroUsize::MAX)
            .jobs(NonZeroUsize::MAX);
        assert_eq!(verifier.analysis_chunk_size, MAX_ANALYSIS_CHUNK_SIZE);
        assert_eq!(verifier.jobs, MAX_JOBS);
    }

    #[test]
    fn missing_metadata_is_not_a_store() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let err = Verifier::new(dir.path())
            .verify()
            .expect_err("an empty directory is not a store");
        assert!(err.is_not_a_store());
        assert!(!err.is_io());
        assert_eq!(err.path(), Some(dir.path()));
        assert!(err.to_string().contains("not a valid CAF store"));
    }
}
