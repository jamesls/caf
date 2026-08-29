//! Corruption analysis: regeneration, pattern classification, merging.
//!
//! When a file's identity does not match its path, or v3 content is not
//! canonical, the verifier regenerates the expected content from the
//! header's seed and compares it in `analysis_chunk_size` chunks aligned to
//! absolute file offsets. Differing chunks become [`CorruptionRegion`]s,
//! contiguous regions with an identical pattern merge, and size deltas
//! append `truncated` / `extra-bytes` regions.
//! The v2 clean path never runs any of this; v3 verification performs its
//! canonical-content comparison while computing Merkle leaves and retains
//! only whether a mismatch occurred.

use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use caf_format::{ContentReader, ContentSeed, Digest, Format, HEADER_SIZE, Header};

use crate::env::FileHandle;

/// A chunk is `sparse` when fewer than this fraction of its bytes differ.
const SPARSE_RATE: f64 = 0.1;
/// Common I/O boundaries checked for the `aligned` pattern, in order.
const ALIGNMENT_BOUNDARIES: [usize; 4] = [512, 1024, 4096, 8192];
/// Only the first this-many differing positions are alignment-checked.
const ALIGNMENT_POSITIONS: usize = 5;
/// Target bytes compared by one independently scheduled task.
const ANALYSIS_TASK_BYTES: usize = 8 * 1024 * 1024;
/// Aggregate actual-plus-expected task buffers allowed per verification.
const ANALYSIS_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// Shared task-buffer budget for one verification run.
#[derive(Debug)]
pub(crate) struct AnalysisMemory {
    used: Mutex<usize>,
    available: Condvar,
    limit: usize,
}

impl AnalysisMemory {
    pub(crate) fn new() -> Self {
        Self::with_limit(ANALYSIS_MEMORY_BYTES)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            used: Mutex::new(0),
            available: Condvar::new(),
            limit,
        }
    }

    fn lock(&self) -> MutexGuard<'_, usize> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserves actual-plus-expected bytes before either task buffer is
    /// allocated. A panic aborts blocked sibling tasks; an I/O error only
    /// stops new claims, so already-claimed lower-offset tasks still run
    /// and can supply the deterministic first error.
    fn acquire<'memory>(
        &'memory self,
        bytes: usize,
        gate: &AnalysisGate,
    ) -> Option<AnalysisMemoryPermit<'memory>> {
        debug_assert!(bytes <= self.limit, "one task fits the analysis budget");
        let mut used = self.lock();
        loop {
            if gate.aborted() {
                return None;
            }
            if bytes <= self.limit - *used {
                *used += bytes;
                return Some(AnalysisMemoryPermit {
                    memory: self,
                    bytes,
                });
            }
            used = self
                .available
                .wait(used)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

struct AnalysisMemoryPermit<'memory> {
    memory: &'memory AnalysisMemory,
    bytes: usize,
}

impl Drop for AnalysisMemoryPermit<'_> {
    fn drop(&mut self) {
        *self.memory.lock() -= self.bytes;
        self.memory.available.notify_all();
    }
}

/// The kind of corruption observed in one region of a file.
///
/// Classes and their triggers are evaluated in
/// this order per analysis chunk: [`ZeroFilled`], [`RepeatedByte`],
/// [`Sparse`], [`Aligned`], then [`Random`]. [`Truncated`] and
/// [`ExtraBytes`] come from the difference between the actual file size
/// and the header's file length, not from chunk comparison. Positions
/// used for the sparse rate and alignment check are relative to the
/// analysis chunk, not the file.
///
/// Every payload here has a documented domain (a rate in `0.0..=1.0`, a
/// boundary from a fixed set, a nonzero repeated byte), so the analyzer
/// is the only constructor: the payload-carrying variants are
/// `#[non_exhaustive]` and cannot be built outside this crate. Reading
/// them through a `match` works as usual, with a trailing `..` in the
/// pattern and a wildcard arm for classes added later.
///
/// [`ZeroFilled`]: CorruptionPattern::ZeroFilled
/// [`RepeatedByte`]: CorruptionPattern::RepeatedByte
/// [`Sparse`]: CorruptionPattern::Sparse
/// [`Aligned`]: CorruptionPattern::Aligned
/// [`Random`]: CorruptionPattern::Random
/// [`Truncated`]: CorruptionPattern::Truncated
/// [`ExtraBytes`]: CorruptionPattern::ExtraBytes
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum CorruptionPattern {
    /// All bytes in the region are `0x00`.
    ZeroFilled,
    /// All bytes in the region are the same nonzero value.
    #[non_exhaustive]
    RepeatedByte {
        /// The repeated byte value.
        value: u8,
    },
    /// Less than 10 percent of the region's bytes are corrupted.
    #[non_exhaustive]
    Sparse {
        /// Number of differing bytes in the first analysis chunk of the
        /// region.
        corrupted_count: u64,
    },
    /// Corruption aligns to a common I/O boundary within the chunk.
    #[non_exhaustive]
    Aligned {
        /// The matched boundary in bytes (512, 1024, 4096, or 8192).
        boundary: u64,
    },
    /// Unstructured corruption with a high corruption rate.
    #[non_exhaustive]
    Random {
        /// Fraction of the chunk's bytes that differ, in `0.0..=1.0`.
        corruption_rate: f64,
    },
    /// The file is shorter than the header's file length.
    #[non_exhaustive]
    Truncated {
        /// Bytes missing from the end of the file.
        missing_bytes: u64,
    },
    /// The file has data beyond the header's file length.
    #[non_exhaustive]
    ExtraBytes {
        /// Unexpected bytes past the expected end of the file.
        extra_count: u64,
    },
}

impl CorruptionPattern {
    /// Returns the kebab-case class name for this pattern.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ZeroFilled => "zero-filled",
            Self::RepeatedByte { .. } => "repeated-byte",
            Self::Sparse { .. } => "sparse",
            Self::Aligned { .. } => "aligned",
            Self::Random { .. } => "random",
            Self::Truncated { .. } => "truncated",
            Self::ExtraBytes { .. } => "extra-bytes",
        }
    }
}

/// One corrupted byte range of a file.
///
/// Offsets are absolute file offsets. Region granularity is the
/// verifier's analysis chunk size, aligned to absolute file offsets; the
/// first content region can be shorter because the header occupies the
/// beginning of its chunk. Contiguous chunks with an identical pattern
/// merge into one region (the pattern of the first chunk is kept).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CorruptionRegion {
    offset: u64,
    size: u64,
    pattern: CorruptionPattern,
}

impl CorruptionRegion {
    fn new(offset: u64, size: u64, pattern: CorruptionPattern) -> Self {
        Self {
            offset,
            size,
            pattern,
        }
    }

    /// Returns the file offset where the region starts.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the region length in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the file offset just past the region.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset + self.size
    }

    /// Returns the corruption pattern of the region.
    #[must_use]
    pub fn pattern(&self) -> CorruptionPattern {
        self.pattern
    }
}

/// How a digest mismatch is classified overall.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CorruptionClass {
    /// The file's bytes differ from the regenerated expected content.
    Content,
    /// The content is valid but stored at a path for a different digest
    /// (zero corrupted bytes and matching sizes).
    PathMismatch,
}

/// Detailed report for one file whose digest does not match its path.
///
/// Produced only for files with a valid header, after the whole-file
/// digest check fails.
/// The derived values (`total_corrupted_bytes`, `corruption_percentage`,
/// `class`) are computed from the stored fields.
#[derive(Clone, Debug, PartialEq)]
pub struct CorruptionReport {
    pub(crate) path: PathBuf,
    pub(crate) format: Format,
    pub(crate) expected: Digest,
    pub(crate) actual: Digest,
    pub(crate) actual_size: u64,
    pub(crate) expected_size: u64,
    pub(crate) content_seed: ContentSeed,
    pub(crate) regions: Vec<CorruptionRegion>,
}

impl CorruptionReport {
    /// Returns the path of the corrupted file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the CAF format parsed from the file header.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Returns the file ID the path claims.
    #[must_use]
    pub fn expected_digest(&self) -> Digest {
        self.expected
    }

    /// Returns the digest actually computed over the file.
    #[must_use]
    pub fn actual_digest(&self) -> Digest {
        self.actual
    }

    /// Returns the file's size on disk in bytes.
    #[must_use]
    pub fn actual_size(&self) -> u64 {
        self.actual_size
    }

    /// Returns the file length recorded in the header.
    #[must_use]
    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// Returns the content seed from the header.
    #[must_use]
    pub fn content_seed(&self) -> ContentSeed {
        self.content_seed
    }

    /// Returns the corrupted regions in ascending file-offset order.
    #[must_use]
    pub fn regions(&self) -> &[CorruptionRegion] {
        &self.regions
    }

    /// Returns the sum of all region sizes in bytes.
    #[must_use]
    pub fn total_corrupted_bytes(&self) -> u64 {
        self.regions.iter().map(CorruptionRegion::size).sum()
    }

    /// Returns corrupted bytes as a percentage of the analysis size
    /// (the larger of the actual and expected file sizes).
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "matches Python float division; exact above 2^53 is not required"
    )]
    pub fn corruption_percentage(&self) -> f64 {
        let analysis_size = self.actual_size.max(self.expected_size);
        if analysis_size == 0 {
            return 0.0;
        }
        (self.total_corrupted_bytes() as f64 / analysis_size as f64) * 100.0
    }

    /// Classifies the mismatch: [`CorruptionClass::PathMismatch`] when no
    /// byte differs and the sizes agree, otherwise
    /// [`CorruptionClass::Content`].
    #[must_use]
    pub fn class(&self) -> CorruptionClass {
        if self.total_corrupted_bytes() == 0 && self.actual_size == self.expected_size {
            CorruptionClass::PathMismatch
        } else {
            CorruptionClass::Content
        }
    }
}

/// Compares `source` against the regenerated content stream and returns
/// the corrupted regions.
///
/// `source` must be positioned anywhere in the file described by
/// `header`; the comparison starts at the first content byte. Content is
/// compared up to the smaller of `actual_size` and the header's file
/// length; a size delta appends a `truncated` or `extra-bytes` region.
pub(crate) fn analyze(
    mut source: impl Read + Seek,
    header: &Header,
    actual_size: u64,
    chunk_size: NonZeroUsize,
) -> io::Result<Vec<CorruptionRegion>> {
    let expected_size = header.file_length();
    let compare_end = actual_size.min(expected_size);
    let mut remaining = compare_end.saturating_sub(HEADER_SIZE as u64);
    // No chunk can exceed the bytes left to compare, so the buffers stay
    // bounded by the file rather than by the requested chunk size.
    let buffer_size = usize::try_from(remaining)
        .unwrap_or(usize::MAX)
        .min(chunk_size.get());

    source.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
    let mut expected_stream =
        ContentReader::new_with_format(header.content_seed(), header.format());
    let mut actual_chunk = vec![0_u8; buffer_size];
    let mut expected_chunk = vec![0_u8; buffer_size];
    let mut regions: Vec<CorruptionRegion> = Vec::new();
    let mut offset = HEADER_SIZE as u64;

    while remaining > 0 {
        let want = analysis_chunk_len(offset, remaining, chunk_size.get());
        let got = read_full(&mut source, &mut actual_chunk[..want])?;
        if got == 0 {
            break;
        }
        let actual = &actual_chunk[..got];
        let expected = &mut expected_chunk[..got];
        expected_stream
            .read_exact(expected)
            .expect("the content stream is infinite and never fails");

        if actual != expected {
            let pattern = classify_chunk(actual, expected);
            push_region(
                &mut regions,
                CorruptionRegion::new(offset, got as u64, pattern),
            );
        }

        offset += got as u64;
        remaining -= got as u64;
    }

    append_size_region(&mut regions, actual_size, expected_size);

    Ok(regions)
}

/// Positional, parallel corruption analysis for one file group.
///
/// Tasks and analysis chunks are aligned to absolute file offsets. The
/// first task begins after the header, partway through the first physical
/// chunk. Results are merged by task index, so task and I/O completion
/// order cannot affect region classification or ordering.
/// `width` is the whole file-group width; the calling coordinator also
/// executes tasks, keeping total live threads within it.
pub(crate) fn analyze_parallel(
    source: &FileHandle,
    header: &Header,
    actual_size: u64,
    chunk_size: NonZeroUsize,
    width: usize,
    memory: &AnalysisMemory,
) -> io::Result<Vec<CorruptionRegion>> {
    let expected_size = header.file_length();
    let compare_end = actual_size.min(expected_size);
    if compare_end <= HEADER_SIZE as u64 {
        let mut regions = Vec::new();
        append_size_region(&mut regions, actual_size, expected_size);
        return Ok(regions);
    }

    let chunks_per_task = (ANALYSIS_TASK_BYTES / chunk_size.get()).max(1);
    let task_len = chunks_per_task
        .checked_mul(chunk_size.get())
        .expect("analysis chunks are clamped to 64 MiB");
    let total_tasks = compare_end.div_ceil(task_len as u64);
    let lanes = analysis_lane_count(width, task_len, total_tasks);
    debug_assert!(lanes > 0, "parallel analysis has content and spare lanes");

    let plan = AnalysisPlan {
        source,
        format: header.format(),
        seed: header.content_seed(),
        compare_end,
        chunk_size: chunk_size.get(),
        task_len,
        total_tasks,
        lanes,
    };
    let mut collection = run_parallel_analysis(&plan, memory);
    debug_assert!(
        collection.failure.is_some()
            || collection.panic_payload.is_some()
            || collection.next_result == total_tasks,
        "every successful analysis task is collected"
    );
    if let Some(payload) = collection.panic_payload {
        panic::resume_unwind(payload);
    }
    if let Some((_index, source)) = collection.failure {
        return Err(source);
    }

    append_size_region(&mut collection.regions, actual_size, expected_size);
    Ok(collection.regions)
}

fn analysis_lane_count(width: usize, task_len: usize, total_tasks: u64) -> usize {
    debug_assert!(task_len > 0, "an analysis task contains at least one chunk");
    debug_assert!(total_tasks > 0, "analysis lanes require content to compare");
    let memory_lanes = (ANALYSIS_MEMORY_BYTES / task_len.saturating_mul(2)).max(1);
    width
        .min(memory_lanes)
        .min(usize::try_from(total_tasks).unwrap_or(usize::MAX))
}

#[derive(Clone, Copy)]
struct AnalysisPlan<'file> {
    source: &'file FileHandle,
    format: Format,
    seed: ContentSeed,
    compare_end: u64,
    chunk_size: usize,
    task_len: usize,
    total_tasks: u64,
    lanes: usize,
}

fn run_parallel_analysis(plan: &AnalysisPlan<'_>, memory: &AnalysisMemory) -> AnalysisCollection {
    let window = plan.lanes.saturating_mul(4);
    let gate = AnalysisGate::new();
    let (sender, receiver) = mpsc::sync_channel(window);

    thread::scope(|scope| {
        // The coordinator below is one analysis lane. Every additional
        // lane runs the same claim loop on a scoped worker thread.
        for _ in 1..plan.lanes {
            let sender = sender.clone();
            let gate = &gate;
            let handle = thread::Builder::new().spawn_scoped(scope, move || {
                let worked = panic::catch_unwind(AssertUnwindSafe(|| {
                    analyze_tasks(plan, gate, window, memory, &sender);
                }));
                if let Err(payload) = worked {
                    gate.abort(memory);
                    let _ignored = sender.send(AnalysisMessage::Panic(payload));
                }
            });
            // A refused lane only narrows the group: the coordinator
            // runs the same claim loop and finishes the tasks.
            if handle.is_err() {
                break;
            }
        }
        drop(sender);

        let mut collection = AnalysisCollection::new();
        let worked = panic::catch_unwind(AssertUnwindSafe(|| {
            loop {
                while let Ok(message) = receiver.try_recv() {
                    collection.absorb(message);
                    gate.collected_through(collection.next_result);
                }

                let index = match gate.try_claim(plan.total_tasks, window) {
                    AnalysisClaim::Index(index) => index,
                    AnalysisClaim::Blocked => {
                        // Receiving while blocked lets the missing early
                        // result advance the claim window without
                        // deadlocking behind a full result channel.
                        match receiver.recv() {
                            Ok(message) => {
                                collection.absorb(message);
                                gate.collected_through(collection.next_result);
                            }
                            Err(_disconnected) => break,
                        }
                        continue;
                    }
                    AnalysisClaim::Stopped => break,
                };
                let Some(result) = analyze_task(plan, index, memory, &gate) else {
                    break;
                };
                if result.is_err() {
                    gate.stop();
                }
                collection.absorb(AnalysisMessage::Task { index, result });
                gate.collected_through(collection.next_result);
            }
        }));
        if let Err(payload) = worked {
            gate.abort(memory);
            collection.absorb(AnalysisMessage::Panic(payload));
        }

        // Worker senders close after all siblings observe exhaustion or
        // cancellation. Drain every in-flight result before the scope
        // joins and before a panic is resumed.
        for message in receiver {
            collection.absorb(message);
            gate.collected_through(collection.next_result);
        }
        collection
    })
}

fn analyze_tasks(
    plan: &AnalysisPlan<'_>,
    gate: &AnalysisGate,
    window: usize,
    memory: &AnalysisMemory,
    sender: &SyncSender<AnalysisMessage>,
) {
    while let Some(index) = gate.claim(plan.total_tasks, window) {
        let Some(result) = analyze_task(plan, index, memory, gate) else {
            return;
        };
        if result.is_err() {
            gate.stop();
        }
        if sender
            .send(AnalysisMessage::Task { index, result })
            .is_err()
        {
            return;
        }
    }
}

/// Hands out analysis tasks no farther than the bounded reorder window
/// ahead of the lowest result not yet collected.
struct AnalysisGate {
    state: Mutex<AnalysisGateState>,
    changed: Condvar,
}

struct AnalysisGateState {
    next_claim: u64,
    collected: u64,
    stopped: bool,
    aborted: bool,
}

enum AnalysisClaim {
    Index(u64),
    Blocked,
    Stopped,
}

impl AnalysisGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(AnalysisGateState {
                next_claim: 0,
                collected: 0,
                stopped: false,
                aborted: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, AnalysisGateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Nonblocking claim for the coordinator, which must remain able to
    /// drain the result channel when the ordered window is full.
    fn try_claim(&self, total: u64, window: usize) -> AnalysisClaim {
        let mut state = self.lock();
        if state.stopped || state.next_claim >= total {
            return AnalysisClaim::Stopped;
        }
        let limit = state
            .collected
            .saturating_add(u64::try_from(window).unwrap_or(u64::MAX));
        if state.next_claim >= limit {
            return AnalysisClaim::Blocked;
        }
        let index = state.next_claim;
        state.next_claim += 1;
        AnalysisClaim::Index(index)
    }

    /// Blocking worker claim. Cancellation and ordered collection both
    /// wake waiters, so errors and panics cannot strand sibling lanes.
    fn claim(&self, total: u64, window: usize) -> Option<u64> {
        let mut state = self.lock();
        loop {
            if state.stopped || state.next_claim >= total {
                return None;
            }
            let limit = state
                .collected
                .saturating_add(u64::try_from(window).unwrap_or(u64::MAX));
            if state.next_claim < limit {
                let index = state.next_claim;
                state.next_claim += 1;
                return Some(index);
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn collected_through(&self, next_result: u64) {
        let mut state = self.lock();
        if next_result > state.collected {
            state.collected = next_result;
            drop(state);
            self.changed.notify_all();
        }
    }

    fn stop(&self) {
        self.lock().stopped = true;
        self.changed.notify_all();
    }

    fn aborted(&self) -> bool {
        self.lock().aborted
    }

    /// Stops new claims and wakes tasks blocked on the shared memory
    /// budget. Taking the memory lock before the gate lock matches
    /// `AnalysisMemory::acquire`, preventing a cancellation wakeup from
    /// being lost between its abort check and condition-variable wait.
    fn abort(&self, memory: &AnalysisMemory) {
        let _memory = memory.lock();
        let mut state = self.lock();
        state.stopped = true;
        state.aborted = true;
        drop(state);
        self.changed.notify_all();
        memory.available.notify_all();
    }
}

fn analyze_task(
    plan: &AnalysisPlan<'_>,
    index: u64,
    memory: &AnalysisMemory,
    gate: &AnalysisGate,
) -> Option<io::Result<Vec<CorruptionRegion>>> {
    let task_start = index * plan.task_len as u64;
    let file_offset = task_start.max(HEADER_SIZE as u64);
    let task_end = task_start
        .saturating_add(plan.task_len as u64)
        .min(plan.compare_end);
    let len = usize::try_from(task_end - file_offset).expect("a task is bounded by task_len");
    let _memory = memory.acquire(len.saturating_mul(2), gate)?;
    Some((|| {
        let mut actual = vec![0_u8; len];
        let got = plan.source.read_full_at(&mut actual, file_offset)?;
        actual.truncate(got);
        let mut expected = vec![0_u8; got];
        let content_offset = file_offset - HEADER_SIZE as u64;
        ContentReader::new_with_offset_and_format(plan.seed, content_offset, plan.format)
            .read_exact(&mut expected)
            .expect("the content stream is infinite and never fails");

        let mut regions = Vec::new();
        let mut relative = 0;
        while relative < got {
            let chunk_len = analysis_chunk_len(
                file_offset + relative as u64,
                (got - relative) as u64,
                plan.chunk_size,
            );
            let actual = &actual[relative..relative + chunk_len];
            let expected = &expected[relative..relative + chunk_len];
            if actual != expected {
                push_region(
                    &mut regions,
                    CorruptionRegion::new(
                        file_offset + relative as u64,
                        actual.len() as u64,
                        classify_chunk(actual, expected),
                    ),
                );
            }
            relative += chunk_len;
        }
        Ok(regions)
    })())
}

/// Length of the next analysis chunk at an absolute file offset.
///
/// The first content chunk ends at the next physical chunk boundary;
/// subsequent chunks have the configured size unless the comparison ends
/// first.
fn analysis_chunk_len(file_offset: u64, remaining: u64, chunk_size: usize) -> usize {
    let chunk_size = chunk_size as u64;
    let to_boundary = chunk_size - file_offset % chunk_size;
    usize::try_from(remaining.min(to_boundary))
        .expect("the chunk length is bounded by the configured chunk size")
}

enum AnalysisMessage {
    Task {
        index: u64,
        result: io::Result<Vec<CorruptionRegion>>,
    },
    Panic(Box<dyn std::any::Any + Send>),
}

/// Ordered, bounded fold of analysis task messages.
struct AnalysisCollection {
    pending: std::collections::BTreeMap<u64, Vec<CorruptionRegion>>,
    next_result: u64,
    regions: Vec<CorruptionRegion>,
    failure: Option<(u64, io::Error)>,
    panic_payload: Option<Box<dyn std::any::Any + Send>>,
}

impl AnalysisCollection {
    fn new() -> Self {
        Self {
            pending: std::collections::BTreeMap::new(),
            next_result: 0,
            regions: Vec::new(),
            failure: None,
            panic_payload: None,
        }
    }

    fn absorb(&mut self, message: AnalysisMessage) {
        match message {
            AnalysisMessage::Task { index, result } => match result {
                Ok(task_regions) => {
                    self.pending.insert(index, task_regions);
                    while let Some(task_regions) = self.pending.remove(&self.next_result) {
                        for region in task_regions {
                            push_region(&mut self.regions, region);
                        }
                        self.next_result += 1;
                    }
                }
                Err(source) => {
                    if self
                        .failure
                        .as_ref()
                        .is_none_or(|(recorded, _source)| index < *recorded)
                    {
                        self.failure = Some((index, source));
                    }
                }
            },
            AnalysisMessage::Panic(payload) => {
                if self.panic_payload.is_none() {
                    self.panic_payload = Some(payload);
                }
            }
        }
    }
}

fn append_size_region(regions: &mut Vec<CorruptionRegion>, actual_size: u64, expected_size: u64) {
    match actual_size.cmp(&expected_size) {
        std::cmp::Ordering::Less => {
            let missing_bytes = expected_size - actual_size;
            push_region(
                regions,
                CorruptionRegion::new(
                    actual_size,
                    missing_bytes,
                    CorruptionPattern::Truncated { missing_bytes },
                ),
            );
        }
        std::cmp::Ordering::Greater => {
            let extra_count = actual_size - expected_size;
            push_region(
                regions,
                CorruptionRegion::new(
                    expected_size,
                    extra_count,
                    CorruptionPattern::ExtraBytes { extra_count },
                ),
            );
        }
        std::cmp::Ordering::Equal => {}
    }
}

/// Appends `region`, merging it into the previous region when they are
/// contiguous and carry an identical pattern. The earlier pattern is kept.
fn push_region(regions: &mut Vec<CorruptionRegion>, region: CorruptionRegion) {
    if let Some(last) = regions.last_mut() {
        if last.end() == region.offset && last.pattern == region.pattern {
            last.size += region.size;
            return;
        }
    }
    regions.push(region);
}

/// Classifies one differing analysis chunk.
///
/// Positions are chunk-relative: the sparse rate and alignment check
/// both use indices within the chunk.
#[expect(
    clippy::cast_precision_loss,
    reason = "matches Python float division; chunks are far below 2^53 bytes"
)]
fn classify_chunk(actual: &[u8], expected: &[u8]) -> CorruptionPattern {
    debug_assert_eq!(
        actual.len(),
        expected.len(),
        "the regenerated chunk always matches the read length"
    );

    if actual.iter().all(|&byte| byte == 0) {
        return CorruptionPattern::ZeroFilled;
    }
    if let Some((&first, rest)) = actual.split_first() {
        if rest.iter().all(|&byte| byte == first) {
            return CorruptionPattern::RepeatedByte { value: first };
        }
    }

    // Only the count and the first few positions are ever used, so the
    // differing positions are counted in place instead of collected.
    let mut corrupted_count = 0_usize;
    let mut leading = [0_usize; ALIGNMENT_POSITIONS];
    let mut leading_count = 0_usize;
    for (position, (a, e)) in actual.iter().zip(expected).enumerate() {
        if a != e {
            if leading_count < ALIGNMENT_POSITIONS {
                leading[leading_count] = position;
                leading_count += 1;
            }
            corrupted_count += 1;
        }
    }
    let corruption_rate = corrupted_count as f64 / actual.len() as f64;

    if corruption_rate < SPARSE_RATE {
        return CorruptionPattern::Sparse {
            corrupted_count: corrupted_count as u64,
        };
    }
    if let Some(boundary) = check_alignment(&leading[..leading_count]) {
        return CorruptionPattern::Aligned {
            boundary: boundary as u64,
        };
    }
    CorruptionPattern::Random { corruption_rate }
}

/// Returns the first common boundary that `leading` — the first
/// [`ALIGNMENT_POSITIONS`] differing positions of a chunk — all align
/// to, if any.
fn check_alignment(leading: &[usize]) -> Option<usize> {
    ALIGNMENT_BOUNDARIES
        .into_iter()
        .find(|boundary| leading.iter().all(|position| position % boundary == 0))
}

/// Reads until `buf` is full or the source reaches end-of-file, returning
/// the number of bytes read. Chunk comparison depends on filling the
/// buffer across short reads.
pub(crate) fn read_full(mut source: impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _, Write as _};
    use std::num::NonZeroUsize;
    use std::sync::{Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    use caf_format::{ContentReader, ContentSeed, Digest, Format, HEADER_SIZE, Header};

    use super::{
        ANALYSIS_MEMORY_BYTES, AnalysisClaim, AnalysisGate, AnalysisMemory, CorruptionClass,
        CorruptionPattern, CorruptionRegion, CorruptionReport, analysis_lane_count, analyze,
        check_alignment, classify_chunk, push_region,
    };

    fn seed() -> ContentSeed {
        ContentSeed::from_bytes(*b"analysis-fixture")
    }

    /// Builds an in-memory file of `file_length` total bytes with the
    /// correct header and deterministic content.
    fn clean_file(file_length: u64) -> Vec<u8> {
        let header = Header::new(Digest::ZERO, seed(), file_length).unwrap();
        let mut bytes = header.encode().to_vec();
        let content_length =
            usize::try_from(file_length).expect("test sizes are small") - HEADER_SIZE;
        let mut content = vec![0_u8; content_length];
        ContentReader::new(seed()).read_exact(&mut content).unwrap();
        bytes.write_all(&content).unwrap();
        bytes
    }

    fn chunk(size: usize) -> NonZeroUsize {
        NonZeroUsize::new(size).expect("the tests use positive chunk sizes")
    }

    fn regions_of(bytes: &[u8], chunk_size: usize) -> Vec<CorruptionRegion> {
        let header = Header::parse(bytes).unwrap();
        let mut cursor = Cursor::new(bytes);
        analyze(&mut cursor, &header, bytes.len() as u64, chunk(chunk_size)).unwrap()
    }

    #[test]
    fn clean_content_yields_no_regions() {
        let bytes = clean_file(4096);
        assert_eq!(regions_of(&bytes, 256), Vec::new());
    }

    #[test]
    fn analysis_lanes_honor_the_actual_plus_expected_memory_limit() {
        let mib = 1024 * 1024;
        assert_eq!(analysis_lane_count(256, 64 * mib, 100), 2);
        assert_eq!(analysis_lane_count(256, 8 * mib, 100), 16);
        assert_eq!(analysis_lane_count(256, ANALYSIS_MEMORY_BYTES, 100), 1);
        assert_eq!(analysis_lane_count(256, 8 * mib, 3), 3);
    }

    #[test]
    fn analysis_memory_is_shared_and_released_across_groups() {
        let memory = AnalysisMemory::with_limit(10);
        let first_gate = AnalysisGate::new();
        let second_gate = AnalysisGate::new();
        let first = memory.acquire(8, &first_gate).expect("first permit");
        let barrier = Barrier::new(2);
        let (sender, receiver) = mpsc::channel();

        thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                let second = memory.acquire(8, &second_gate).expect("second permit");
                sender.send(()).expect("the test receiver remains");
                drop(second);
            });
            barrier.wait();
            assert_eq!(*memory.lock(), 8);
            assert!(receiver.try_recv().is_err());
            drop(first);
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("releasing the first group wakes the second");
        });
        assert_eq!(*memory.lock(), 0);
    }

    #[test]
    fn analysis_memory_waiters_wake_when_their_group_aborts() {
        let memory = AnalysisMemory::with_limit(10);
        let occupying_gate = AnalysisGate::new();
        let blocked_gate = AnalysisGate::new();
        let occupying = memory
            .acquire(10, &occupying_gate)
            .expect("occupying permit");
        let barrier = Barrier::new(2);
        let (sender, receiver) = mpsc::channel();

        thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                sender
                    .send(memory.acquire(8, &blocked_gate).is_none())
                    .expect("the test receiver remains");
            });
            barrier.wait();
            blocked_gate.abort(&memory);
            assert!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("abort wakes the blocked task")
            );
        });
        drop(occupying);
        assert_eq!(*memory.lock(), 0);
    }

    #[test]
    fn analysis_claims_stay_within_the_ordered_window() {
        let gate = AnalysisGate::new();
        for expected in 0..8 {
            let AnalysisClaim::Index(actual) = gate.try_claim(100, 8) else {
                panic!("index {expected} should be claimable");
            };
            assert_eq!(actual, expected);
        }
        assert!(matches!(gate.try_claim(100, 8), AnalysisClaim::Blocked));
        gate.collected_through(1);
        assert!(matches!(gate.try_claim(100, 8), AnalysisClaim::Index(8)));
    }

    #[test]
    fn zeroed_chunks_merge_into_one_region() {
        // Zero file offsets 1024..1792: exactly three physical 256-byte
        // analysis chunks, which must merge.
        let mut bytes = clean_file(4096);
        bytes[1024..1792].fill(0);
        let regions = regions_of(&bytes, 256);
        assert_eq!(regions.len(), 1, "{regions:?}");
        assert_eq!(regions[0].offset(), 1024);
        assert_eq!(regions[0].size(), 768);
        assert_eq!(regions[0].end(), 1792);
        assert_eq!(regions[0].pattern(), CorruptionPattern::ZeroFilled);
        assert_eq!(regions[0].pattern().name(), "zero-filled");
    }

    #[test]
    fn aligned_zeroed_block_is_one_region() {
        let mut bytes = clean_file(3 * 4096);
        bytes[4096..8192].fill(0);

        let regions = regions_of(&bytes, 4096);

        assert_eq!(
            regions,
            vec![CorruptionRegion::new(
                4096,
                4096,
                CorruptionPattern::ZeroFilled,
            )]
        );
    }

    #[test]
    fn truncation_appends_a_truncated_region() {
        let bytes = clean_file(4096);
        let truncated = &bytes[..4096 - 512];
        let header = Header::parse(truncated).unwrap();
        let mut cursor = Cursor::new(truncated);
        let regions = analyze(&mut cursor, &header, truncated.len() as u64, chunk(256)).unwrap();
        assert_eq!(
            regions,
            vec![CorruptionRegion::new(
                3584,
                512,
                CorruptionPattern::Truncated { missing_bytes: 512 },
            )]
        );
    }

    #[test]
    fn extra_bytes_append_an_extra_bytes_region() {
        let mut bytes = clean_file(1024);
        bytes.extend_from_slice(&[0xAB; 100]);
        let header = Header::parse(&bytes).unwrap();
        let mut cursor = Cursor::new(&bytes);
        let regions = analyze(&mut cursor, &header, bytes.len() as u64, chunk(4096)).unwrap();
        assert_eq!(
            regions,
            vec![CorruptionRegion::new(
                1024,
                100,
                CorruptionPattern::ExtraBytes { extra_count: 100 },
            )]
        );
    }

    #[test]
    fn analysis_is_invariant_under_chunk_size_for_clean_content() {
        let bytes = clean_file(8192);
        for chunk_size in [1, 7, 256, 4096, 65536] {
            assert_eq!(regions_of(&bytes, chunk_size), Vec::new(), "{chunk_size}");
        }
    }

    #[test]
    fn classify_zero_filled_wins_over_repeated_byte() {
        let actual = [0_u8; 64];
        let expected = [0x11_u8; 64];
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::ZeroFilled
        );
    }

    #[test]
    fn classify_repeated_byte_keeps_the_value() {
        let actual = [0xFF_u8; 64];
        let expected = [0x11_u8; 64];
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::RepeatedByte { value: 0xFF }
        );
    }

    #[test]
    fn classify_sparse_counts_differing_bytes() {
        // 3 of 64 bytes differ: rate 4.7% < 10%.
        let expected = [0x11_u8; 64];
        let mut actual = expected;
        actual[3] = 0x22;
        actual[9] = 0x33;
        actual[40] = 0x44;
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::Sparse { corrupted_count: 3 }
        );
    }

    #[test]
    fn classify_aligned_checks_only_the_first_five_positions() {
        // First five differing positions on 512-byte boundaries, then a
        // dense unaligned run to push the rate past 10%.
        let expected = [0x11_u8; 4096];
        let mut actual = expected;
        for position in [0, 512, 1024, 1536, 2048] {
            actual[position] = 0x22;
        }
        for byte in &mut actual[2049..2500] {
            *byte = 0x33;
        }
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::Aligned { boundary: 512 }
        );
    }

    #[test]
    fn classify_random_reports_the_rate() {
        // Alternate every other byte: rate 50%, unaligned.
        let expected = [0x11_u8; 64];
        let mut actual = expected;
        for position in (1..64).step_by(2) {
            actual[position] = 0x22;
        }
        let CorruptionPattern::Random { corruption_rate } = classify_chunk(&actual, &expected)
        else {
            panic!("expected the random pattern");
        };
        assert!((corruption_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn alignment_prefers_the_smallest_boundary() {
        // Multiples of 1024 are also multiples of 512; Python reports
        // the first boundary in [512, 1024, 4096, 8192].
        assert_eq!(check_alignment(&[0, 1024, 2048]), Some(512));
        assert_eq!(check_alignment(&[0, 512, 700]), None);
        assert_eq!(check_alignment(&[4096]), Some(512));
    }

    #[test]
    fn merge_requires_identical_patterns_and_contiguity() {
        let mut regions = vec![CorruptionRegion::new(
            60,
            256,
            CorruptionPattern::Sparse { corrupted_count: 5 },
        )];
        // Contiguous regions with different counts do not merge.
        push_region(
            &mut regions,
            CorruptionRegion::new(316, 256, CorruptionPattern::Sparse { corrupted_count: 6 }),
        );
        assert_eq!(regions.len(), 2);
        // Contiguous with an equal pattern: merge, keeping the pattern.
        push_region(
            &mut regions,
            CorruptionRegion::new(572, 256, CorruptionPattern::Sparse { corrupted_count: 6 }),
        );
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[1].size(), 512);
        // A gap prevents merging even with an equal pattern.
        push_region(
            &mut regions,
            CorruptionRegion::new(2000, 256, CorruptionPattern::Sparse { corrupted_count: 6 }),
        );
        assert_eq!(regions.len(), 3);
    }

    #[test]
    fn report_classifies_path_mismatch_and_content() {
        let path_mismatch = CorruptionReport {
            path: "store/aa".into(),
            format: Format::V2,
            expected: Digest::ZERO,
            actual: Digest::compute(b"x"),
            actual_size: 1024,
            expected_size: 1024,
            content_seed: seed(),
            regions: Vec::new(),
        };
        assert_eq!(path_mismatch.class(), CorruptionClass::PathMismatch);
        assert_eq!(path_mismatch.total_corrupted_bytes(), 0);
        assert!((path_mismatch.corruption_percentage() - 0.0).abs() < f64::EPSILON);

        let content = CorruptionReport {
            path: "store/aa".into(),
            format: Format::V2,
            expected: Digest::ZERO,
            actual: Digest::compute(b"x"),
            actual_size: 1024,
            expected_size: 1024,
            content_seed: seed(),
            regions: vec![CorruptionRegion::new(
                60,
                256,
                CorruptionPattern::ZeroFilled,
            )],
        };
        assert_eq!(content.class(), CorruptionClass::Content);
        assert_eq!(content.total_corrupted_bytes(), 256);
        assert!((content.corruption_percentage() - 25.0).abs() < 1e-9);
    }

    #[test]
    fn size_mismatch_alone_classifies_as_content() {
        // Truncation with intact leading content: the region list holds
        // only the truncated region, and the class must be content.
        let report = CorruptionReport {
            path: "store/aa".into(),
            format: Format::V2,
            expected: Digest::ZERO,
            actual: Digest::compute(b"x"),
            actual_size: 512,
            expected_size: 1024,
            content_seed: seed(),
            regions: vec![CorruptionRegion::new(
                512,
                512,
                CorruptionPattern::Truncated { missing_bytes: 512 },
            )],
        };
        assert_eq!(report.class(), CorruptionClass::Content);
        // Percentage uses the larger of the two sizes.
        assert!((report.corruption_percentage() - 50.0).abs() < 1e-9);
    }
}

#[cfg(all(test, feature = "test-util"))]
mod mocked_parallel_tests {
    use std::io::{self, Cursor, Read as _};
    use std::num::NonZeroUsize;
    use std::panic::{self, AssertUnwindSafe};
    use std::path::Path;
    use std::time::Duration;

    use caf_format::{ContentReader, ContentSeed, Digest, HEADER_SIZE, Header};

    use super::{ANALYSIS_TASK_BYTES, AnalysisMemory, analyze, analyze_parallel};
    use crate::env::Env;

    fn fixture(content_len: usize) -> (Header, Vec<u8>) {
        let seed = ContentSeed::from_bytes(*b"parallel-analyze");
        let file_len = HEADER_SIZE as u64 + content_len as u64;
        let header = Header::new(Digest::ZERO, seed, file_len).expect("the fixture size is valid");
        let mut bytes = header.encode().to_vec();
        let mut content = vec![0_u8; content_len];
        ContentReader::new(seed)
            .read_exact(&mut content)
            .expect("expected content is infinite");
        bytes.extend_from_slice(&content);
        (header, bytes)
    }

    fn chunk_size() -> NonZeroUsize {
        NonZeroUsize::new(4096).expect("the chunk size is positive")
    }

    #[test]
    fn parallel_analysis_retries_and_reorders_positional_reads() {
        let (header, mut bytes) = fixture(2 * ANALYSIS_TASK_BYTES + 1234);
        bytes[HEADER_SIZE + 17] ^= 0xFF;
        bytes[HEADER_SIZE + ANALYSIS_TASK_BYTES + 29] ^= 0xFF;
        let expected = analyze(
            Cursor::new(&bytes),
            &header,
            bytes.len() as u64,
            chunk_size(),
        )
        .expect("serial analysis succeeds");

        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", bytes.clone())
            .expect("the fixture is writable");
        ctrl.delay_read_at(HEADER_SIZE as u64 + 1, Duration::from_millis(30));
        ctrl.interrupt_next_read_at();
        ctrl.limit_next_read_at(17);
        let file = env.open(Path::new("/file")).expect("the file opens");

        let actual = analyze_parallel(
            &file,
            &header,
            bytes.len() as u64,
            chunk_size(),
            4,
            &AnalysisMemory::new(),
        )
        .expect("parallel analysis retries and succeeds");
        assert_eq!(actual, expected);
    }

    #[test]
    fn parallel_analysis_returns_the_lowest_offset_error() {
        let (header, bytes) = fixture(2 * ANALYSIS_TASK_BYTES + 1234);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", bytes.clone())
            .expect("the fixture is writable");
        ctrl.delay_read_at(HEADER_SIZE as u64 + 1, Duration::from_millis(30));
        ctrl.fail_read_at(HEADER_SIZE as u64 + 100, io::ErrorKind::PermissionDenied);
        ctrl.fail_read_at(
            HEADER_SIZE as u64 + ANALYSIS_TASK_BYTES as u64 + 100,
            io::ErrorKind::StorageFull,
        );
        let file = env.open(Path::new("/file")).expect("the file opens");
        let memory = AnalysisMemory::with_limit(2 * ANALYSIS_TASK_BYTES);

        let error = analyze_parallel(&file, &header, bytes.len() as u64, chunk_size(), 3, &memory)
            .expect_err("both initial analysis tasks fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn parallel_analysis_propagates_a_worker_panic() {
        let (header, bytes) = fixture(2 * ANALYSIS_TASK_BYTES + 1234);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", bytes.clone())
            .expect("the fixture is writable");
        ctrl.panic_read_at(HEADER_SIZE as u64 + ANALYSIS_TASK_BYTES as u64 + 100);
        let file = env.open(Path::new("/file")).expect("the file opens");
        let memory = AnalysisMemory::with_limit(2 * ANALYSIS_TASK_BYTES);

        let payload = panic::catch_unwind(AssertUnwindSafe(|| {
            analyze_parallel(&file, &header, bytes.len() as u64, chunk_size(), 3, &memory)
        }))
        .expect_err("the worker panic reaches the coordinator");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"the mocked positional read panicked")
        );
    }
}
