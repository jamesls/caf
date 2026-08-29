//! Global verification lane allocation and within-file identity hashing.
//!
//! Version 2 spends one allocated lane on the calling coordinator and uses
//! the others for positional readers; the coordinator restores file order for
//! its linear `BLAKE2b` stream. Version 3 uses the caller as one block worker
//! and starts `width - 1` peers; all workers store Merkle leaves directly by
//! index. Allocation gives every remaining file one lane, then distributes
//! spare lanes in proportion to file length, subject to the two-segments-per-
//! lane crossover cap.

use std::collections::BTreeMap;
use std::io;
use std::mem;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use caf_format::{
    BLOCK_SIZE, Digest, Format, HEADER_SIZE, Hasher, Header, MerkleHash,
    fill_block_prefix_with_format, v3_file_id_from_leaves, v3_leaf_hash,
};

use crate::env::FileHandle;

/// Buffers in flight per positional reader.
const BUFFERS_PER_READER: usize = 4;

/// Number of sorted files that stay in the width-one contended regime
/// before the final spare-lane allocation.
///
/// Equality is contended, so a nonempty tail is always strictly smaller
/// than the budget. At least one full worker cohort stays on the
/// metadata-free path before a tail is planned.
pub(crate) fn contended_prefix_len(file_count: usize, jobs: usize) -> usize {
    debug_assert!(jobs > 0, "the worker budget is nonzero");
    match file_count.cmp(&jobs) {
        std::cmp::Ordering::Less => 0,
        std::cmp::Ordering::Equal => file_count,
        std::cmp::Ordering::Greater => jobs.max(file_count - (jobs - 1)),
    }
}

/// Maximum useful width for a file of `file_size` bytes.
///
/// Only complete 1 MiB segments count toward the crossover. This makes
/// width two start at 4 MiB and guarantees at least two full segments
/// of work for every assigned lane.
pub(crate) fn width_cap(file_size: u64) -> usize {
    let full_segments = file_size / BLOCK_SIZE as u64;
    let cap = (full_segments / 2).max(1);
    usize::try_from(cap).unwrap_or(usize::MAX)
}

/// Gives `lanes` to `lengths`, which are in report/path order.
///
/// Every file receives one lane. Spare lanes are apportioned by actual
/// length using largest remainders, with equal remainders going to the
/// earlier path. A capped file leaves its refused lanes for another
/// apportionment round.
pub(crate) fn allocate_widths(lengths: &[u64], lanes: usize) -> Vec<usize> {
    if lengths.is_empty() {
        return Vec::new();
    }
    assert!(
        lanes >= lengths.len(),
        "lane allocation requires at least one lane per file"
    );

    let caps: Vec<usize> = lengths.iter().copied().map(width_cap).collect();
    let mut widths = vec![1_usize; lengths.len()];
    let mut spare = lanes - lengths.len();

    while spare > 0 {
        let eligible: Vec<usize> = (0..lengths.len())
            .filter(|&index| widths[index] < caps[index])
            .collect();
        if eligible.is_empty() {
            break;
        }
        let total_weight: u128 = eligible
            .iter()
            .map(|&index| u128::from(lengths[index]))
            .sum();
        debug_assert!(total_weight > 0, "a file with spare capacity is nonempty");

        let round_spare = spare;
        let mut remainders = Vec::with_capacity(eligible.len());
        for &index in &eligible {
            let numerator = round_spare as u128 * u128::from(lengths[index]);
            let quotient = usize::try_from(numerator / total_weight)
                .expect("a proportional share is no larger than the lane budget");
            let grant = quotient.min(caps[index] - widths[index]);
            widths[index] += grant;
            spare -= grant;
            remainders.push((numerator % total_weight, index));
        }

        // Descending remainder, then ascending path index.
        remainders.sort_unstable_by(|(left_rem, left_index), (right_rem, right_index)| {
            right_rem
                .cmp(left_rem)
                .then_with(|| left_index.cmp(right_index))
        });
        for (_remainder, index) in remainders {
            if spare == 0 {
                break;
            }
            if widths[index] < caps[index] {
                widths[index] += 1;
                spare -= 1;
            }
        }
    }
    widths
}

/// Hashes `header_bytes` followed by every actual file byte after the
/// header, overlapping positional reads with the ordered hash stream.
///
/// `width` counts this calling coordinator, so exactly `width - 1`
/// reader threads are started. Read failures are compared by segment
/// index and the lowest-offset one is returned. A reader panic cancels
/// and drains the group before resuming on the coordinator.
pub(crate) fn hash_file(
    file: &FileHandle,
    header_bytes: &[u8],
    actual_size: u64,
    width: usize,
) -> io::Result<Digest> {
    assert!(width >= 2, "parallel hashing needs a reader and a hasher");
    let content_start = header_bytes.len() as u64;
    let content_len = actual_size.saturating_sub(content_start);
    let total = content_len.div_ceil(BLOCK_SIZE as u64);

    let mut hasher = Hasher::new();
    hasher.update(header_bytes);
    if total == 0 {
        return Ok(hasher.finalize());
    }

    let readers = usize::try_from(total).unwrap_or(usize::MAX).min(width - 1);
    let buffer_count = usize::try_from(total)
        .unwrap_or(usize::MAX)
        .min(readers.saturating_mul(BUFFERS_PER_READER));
    let pool = Pool::new(buffer_count);
    let next_index = AtomicU64::new(0);
    let (sender, receiver) = mpsc::sync_channel(buffer_count);

    let (failure, panic_payload, next_hashed) = thread::scope(|scope| {
        for _ in 0..readers {
            let sender = sender.clone();
            let pool = &pool;
            let next_index = &next_index;
            scope.spawn(move || {
                let worked = panic::catch_unwind(AssertUnwindSafe(|| {
                    read_segments(
                        file,
                        content_start,
                        content_len,
                        total,
                        pool,
                        next_index,
                        &sender,
                    );
                }));
                if let Err(payload) = worked {
                    pool.cancel();
                    let _ignored = sender.send(Message::Panic(payload));
                }
            });
        }
        drop(sender);

        let mut pending = BTreeMap::new();
        let mut next_hashed = 0_u64;
        let mut failure: Option<(u64, io::Error)> = None;
        let mut panic_payload = None;
        for message in receiver {
            match message {
                Message::Segment(segment) if failure.is_none() && panic_payload.is_none() => {
                    pending.insert(segment.index, segment);
                    while let Some(segment) = pending.remove(&next_hashed) {
                        hasher.update(segment.bytes());
                        next_hashed += 1;
                    }
                }
                Message::Segment(_segment) => {}
                Message::Error { index, source } => {
                    if failure
                        .as_ref()
                        .is_none_or(|(recorded, _source)| index < *recorded)
                    {
                        failure = Some((index, source));
                    }
                    pending.clear();
                }
                Message::Panic(payload) => {
                    if panic_payload.is_none() {
                        panic_payload = Some(payload);
                    }
                    pending.clear();
                }
            }
        }
        (failure, panic_payload, next_hashed)
    });

    debug_assert_eq!(pool.free(), buffer_count, "every read buffer returns");
    if let Some(payload) = panic_payload {
        panic::resume_unwind(payload);
    }
    if let Some((_index, source)) = failure {
        return Err(source);
    }
    debug_assert_eq!(next_hashed, total, "every successful segment is hashed");
    Ok(hasher.finalize())
}

/// Result of one strict v3 read pass.
pub(crate) struct V3HashResult {
    pub(crate) digest: Digest,
    pub(crate) content_matches: bool,
}

/// Reusable per-worker verification scratch.
///
/// `block` holds bytes read back from the file (the v2 whole-file read
/// buffer and the v3 physical block); `expected` holds regenerated
/// canonical v3 content. A worker keeps one across files, and every use
/// resizes to the length it needs, so a store of many small files costs
/// no per-file scratch allocation and capacity stays at the largest
/// block actually scanned.
pub(crate) struct ScanBuffers {
    pub(crate) block: Vec<u8>,
    pub(crate) expected: Vec<u8>,
}

impl ScanBuffers {
    pub(crate) fn new() -> Self {
        Self {
            block: Vec::new(),
            expected: Vec::new(),
        }
    }
}

/// Hashes actual physical blocks and validates canonical v3 content.
///
/// `width` block workers perform reads, SHAKE generation, and leaf hashing.
/// The calling thread is one of those workers, so the global lane budget does
/// not hide an extra coordinator thread. The calling worker scans through
/// the caller's persistent `scratch`; the spawned peers, which exist only
/// for multi-block files, each allocate their own.
///
/// The Merkle root binds `actual_size`, regardless of the length declared
/// by `header`. Content comparison covers the bytes common to the actual
/// and declared lengths; a size mismatch is reported separately by the
/// caller.
pub(crate) fn hash_v3_file(
    file: &FileHandle,
    header: &Header,
    actual_size: u64,
    width: usize,
    scratch: &mut ScanBuffers,
) -> io::Result<V3HashResult> {
    debug_assert_eq!(header.format(), Format::V3);
    assert!(width >= 1, "a v3 file hash needs at least one lane");
    if actual_size < HEADER_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "a v3 file is shorter than its header",
        ));
    }
    let total = actual_size.div_ceil(BLOCK_SIZE as u64);
    let leaf_count = usize::try_from(total)
        .map_err(|_error| io::Error::new(io::ErrorKind::FileTooLarge, "too many v3 blocks"))?;
    if width == 1 {
        let mut leaves = allocate_leaves(leaf_count)?;
        let mut content_matches = true;
        for index in 0..total {
            let (leaf, block_content_matches) =
                read_v3_block(file, header, actual_size, index, scratch)?;
            let slot =
                usize::try_from(index).expect("a block index fits because the leaf count does");
            leaves[slot] = leaf;
            content_matches &= block_content_matches;
        }
        return Ok(V3HashResult {
            digest: Digest::from_bytes(v3_file_id_from_leaves(actual_size, leaves).into_inner()),
            content_matches,
        });
    }

    let results = V3Results::new(allocate_leaves(leaf_count)?);
    let workers = v3_worker_count(total, width);
    let next_index = AtomicU64::new(0);
    let cancelled = AtomicBool::new(false);

    thread::scope(|scope| {
        for _ in 1..workers {
            let next_index = &next_index;
            let cancelled = &cancelled;
            let results = &results;
            scope.spawn(move || {
                let worked = panic::catch_unwind(AssertUnwindSafe(|| {
                    read_v3_blocks(
                        file,
                        header,
                        actual_size,
                        total,
                        next_index,
                        cancelled,
                        results,
                        &mut ScanBuffers::new(),
                    );
                }));
                if let Err(payload) = worked {
                    cancelled.store(true, Ordering::Relaxed);
                    results.record_panic(payload);
                }
            });
        }

        let worked = panic::catch_unwind(AssertUnwindSafe(|| {
            read_v3_blocks(
                file,
                header,
                actual_size,
                total,
                &next_index,
                &cancelled,
                &results,
                scratch,
            );
        }));
        if let Err(payload) = worked {
            cancelled.store(true, Ordering::Relaxed);
            results.record_panic(payload);
        }
    });

    if let Some(payload) = results.take_panic() {
        panic::resume_unwind(payload);
    }
    if let Some(source) = results.take_error() {
        return Err(source);
    }
    if results.blocks_seen.load(Ordering::Relaxed) != total {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "v3 verification ended before every block was hashed",
        ));
    }
    let content_matches = results.content_matches.load(Ordering::Relaxed);
    let leaves = results
        .leaves
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(V3HashResult {
        digest: Digest::from_bytes(v3_file_id_from_leaves(actual_size, leaves).into_inner()),
        content_matches,
    })
}

/// Number of v3 block workers used for one file.
fn v3_worker_count(total: u64, width: usize) -> usize {
    usize::try_from(total).unwrap_or(usize::MAX).min(width)
}

/// Fallibly allocates the indexed v3 leaf array.
fn allocate_leaves(leaf_count: usize) -> io::Result<Vec<MerkleHash>> {
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(leaf_count)
        .map_err(|_source| io::Error::from(io::ErrorKind::OutOfMemory))?;
    leaves.resize(leaf_count, MerkleHash::from_bytes([0; MerkleHash::SIZE]));
    Ok(leaves)
}

/// Shared indexed results for independent v3 block workers.
struct V3Results {
    leaves: Mutex<Vec<MerkleHash>>,
    blocks_seen: AtomicU64,
    content_matches: AtomicBool,
    failure: Mutex<Option<(u64, io::Error)>>,
    panic_payload: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl V3Results {
    fn new(leaves: Vec<MerkleHash>) -> Self {
        Self {
            leaves: Mutex::new(leaves),
            blocks_seen: AtomicU64::new(0),
            content_matches: AtomicBool::new(true),
            failure: Mutex::new(None),
            panic_payload: Mutex::new(None),
        }
    }

    fn store(&self, index: u64, leaf: MerkleHash, content_matches: bool) {
        let slot = usize::try_from(index).expect("a block index fits because the leaf count does");
        self.leaves.lock().unwrap_or_else(PoisonError::into_inner)[slot] = leaf;
        self.content_matches
            .fetch_and(content_matches, Ordering::Relaxed);
        self.blocks_seen.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self, index: u64, source: io::Error) {
        let mut failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        if failure
            .as_ref()
            .is_none_or(|(recorded, _source)| index < *recorded)
        {
            *failure = Some((index, source));
        }
    }

    fn take_error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(|(_index, source)| source)
    }

    fn record_panic(&self, payload: Box<dyn std::any::Any + Send>) {
        let mut panic_payload = self
            .panic_payload
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if panic_payload.is_none() {
            *panic_payload = Some(payload);
        }
    }

    fn take_panic(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.panic_payload
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "one worker's full read context; grouping would only rename it"
)]
fn read_v3_blocks(
    file: &FileHandle,
    header: &Header,
    actual_size: u64,
    total: u64,
    next_index: &AtomicU64,
    cancelled: &AtomicBool,
    results: &V3Results,
    scratch: &mut ScanBuffers,
) {
    while !cancelled.load(Ordering::Relaxed) {
        let index = next_index.fetch_add(1, Ordering::Relaxed);
        if index >= total {
            return;
        }
        match read_v3_block(file, header, actual_size, index, scratch) {
            Ok((leaf, block_content_matches)) => {
                results.store(index, leaf, block_content_matches);
            }
            Err(source) => {
                cancelled.store(true, Ordering::Relaxed);
                results.record_error(index, source);
                return;
            }
        }
    }
}

fn read_v3_block(
    file: &FileHandle,
    header: &Header,
    actual_size: u64,
    index: u64,
    scratch: &mut ScanBuffers,
) -> io::Result<(MerkleHash, bool)> {
    let offset = index * BLOCK_SIZE as u64;
    let len = usize::try_from((actual_size - offset).min(BLOCK_SIZE as u64))
        .expect("a physical block is at most BLOCK_SIZE bytes");
    let block = &mut scratch.block;
    block.resize(len, 0);
    let got = file.read_full_at(block, offset)?;
    if got != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "v3 file changed while it was being read",
        ));
    }

    let content_start = if index == 0 { HEADER_SIZE } else { 0 };
    let expected_file_end = header.file_length().min(offset + len as u64);
    let compare_len =
        usize::try_from(expected_file_end.saturating_sub(offset + content_start as u64))
            .expect("the comparison is within one physical block");
    let content_matches = if compare_len == 0 {
        true
    } else {
        let expected = &mut scratch.expected;
        expected.resize(compare_len, 0);
        fill_block_prefix_with_format(Format::V3, header.content_seed(), index, expected);
        block[content_start..content_start + compare_len] == expected[..compare_len]
    };
    Ok((v3_leaf_hash(index, block), content_matches))
}

fn read_segments<'pool>(
    file: &FileHandle,
    content_start: u64,
    content_len: u64,
    total: u64,
    pool: &'pool Pool,
    next_index: &AtomicU64,
    sender: &SyncSender<Message<'pool>>,
) {
    // Taking a buffer before claiming an index guarantees that the
    // lowest outstanding segment always has a reader and bounds claims
    // to the pool size ahead of the hasher.
    while let Some(mut buffer) = pool.take() {
        let index = next_index.fetch_add(1, Ordering::Relaxed);
        if index >= total {
            return;
        }
        let relative = index * BLOCK_SIZE as u64;
        let len = usize::try_from((content_len - relative).min(BLOCK_SIZE as u64))
            .expect("a segment is at most BLOCK_SIZE bytes");
        buffer.bytes.resize(len, 0);
        let offset = content_start + relative;
        match file.read_full_at(&mut buffer.bytes, offset) {
            Ok(got) => {
                buffer.bytes.truncate(got);
                if sender
                    .send(Message::Segment(Segment { index, buffer }))
                    .is_err()
                {
                    return;
                }
            }
            Err(source) => {
                pool.cancel();
                let _ignored = sender.send(Message::Error { index, source });
                return;
            }
        }
    }
}

enum Message<'pool> {
    Segment(Segment<'pool>),
    Error { index: u64, source: io::Error },
    Panic(Box<dyn std::any::Any + Send>),
}

struct Segment<'pool> {
    index: u64,
    buffer: Buffer<'pool>,
}

impl Segment<'_> {
    fn bytes(&self) -> &[u8] {
        &self.buffer.bytes
    }
}

/// One pool buffer on loan. Its destructor is the cancellation and panic
/// safety protocol: every exit path returns the allocation.
struct Buffer<'pool> {
    bytes: Vec<u8>,
    pool: &'pool Pool,
}

impl Drop for Buffer<'_> {
    fn drop(&mut self) {
        self.pool.put(mem::take(&mut self.bytes));
    }
}

/// Fixed read buffers and cancellation wakeup for one file group.
struct Pool {
    state: Mutex<PoolState>,
    returned: Condvar,
}

struct PoolState {
    free: Vec<Vec<u8>>,
    cancelled: bool,
}

impl Pool {
    fn new(buffers: usize) -> Self {
        Self {
            state: Mutex::new(PoolState {
                free: (0..buffers)
                    .map(|_| Vec::with_capacity(BLOCK_SIZE))
                    .collect(),
                cancelled: false,
            }),
            returned: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn take(&self) -> Option<Buffer<'_>> {
        let mut state = self.lock();
        loop {
            if state.cancelled {
                return None;
            }
            if let Some(buffer) = state.free.pop() {
                return Some(Buffer {
                    bytes: buffer,
                    pool: self,
                });
            }
            state = self
                .returned
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn put(&self, buffer: Vec<u8>) {
        self.lock().free.push(buffer);
        self.returned.notify_one();
    }

    fn cancel(&self) {
        self.lock().cancelled = true;
        self.returned.notify_all();
    }

    fn free(&self) -> usize {
        self.lock().free.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{allocate_widths, contended_prefix_len, v3_worker_count, width_cap};
    use caf_format::BLOCK_SIZE;

    #[test]
    fn contended_files_stay_width_one_until_fewer_than_jobs_remain() {
        assert_eq!(contended_prefix_len(5, 24), 0);
        assert_eq!(contended_prefix_len(5, 5), 5);
        assert_eq!(contended_prefix_len(25, 24), 24);
        assert_eq!(contended_prefix_len(100, 24), 77);
        assert_eq!(100 - contended_prefix_len(100, 24), 23);
    }

    #[test]
    fn equal_files_split_spares_by_path_order() {
        let one_tib = 1024_u64 * 1024 * 1024 * 1024;
        assert_eq!(allocate_widths(&[one_tib; 5], 24), [5, 5, 5, 5, 4]);
    }

    #[test]
    fn file_width_requires_two_complete_segments_per_lane() {
        let mib = BLOCK_SIZE as u64;
        assert_eq!(width_cap(4 * mib - 1), 1);
        assert_eq!(width_cap(4 * mib), 2);
        assert_eq!(width_cap(5 * mib), 2);
        assert_eq!(width_cap(6 * mib), 3);
    }

    #[test]
    fn v3_assigns_every_width_lane_to_block_workers() {
        assert_eq!(v3_worker_count(5, 1), 1);
        assert_eq!(v3_worker_count(5, 2), 2);
        assert_eq!(v3_worker_count(5, 4), 4);
        assert_eq!(v3_worker_count(5, 8), 5);
    }

    #[test]
    fn capped_lanes_redistribute_to_files_that_can_use_them() {
        let mib = BLOCK_SIZE as u64;
        assert_eq!(allocate_widths(&[4 * mib, 40 * mib], 8), [2, 6]);
        assert_eq!(allocate_widths(&[mib, 40 * mib, mib], 8), [1, 6, 1]);
    }

    #[test]
    fn mixed_sizes_use_largest_remainders() {
        let mib = BLOCK_SIZE as u64;
        assert_eq!(
            allocate_widths(&[8 * mib, 16 * mib, 24 * mib], 10),
            [2, 3, 5]
        );
    }
}

#[cfg(all(test, feature = "test-util"))]
mod mocked_tests {
    use std::io::{self, Read as _};
    use std::panic::{self, AssertUnwindSafe};
    use std::path::Path;
    use std::time::Duration;

    use caf_format::{BLOCK_SIZE, ContentSeed, Digest, FileId, Header};

    use super::{ScanBuffers, hash_file, hash_v3_file};
    use crate::env::Env;

    fn bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from((index * 37 + 11) % 251).unwrap())
            .collect()
    }

    #[test]
    fn v3_hash_rejects_an_actual_size_shorter_than_the_header() {
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", Vec::new())
            .expect("the fixture is writable");
        let file = env.open(Path::new("/file")).expect("the file opens");
        let header = Header::new_v3(
            FileId::ZERO,
            ContentSeed::from_bytes(*b"parallel-verify!"),
            60,
        )
        .expect("the header length is valid");

        let error = hash_v3_file(&file, &header, 59, 1, &mut ScanBuffers::new())
            .err()
            .expect("stale short metadata is rejected");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn ordered_pipeline_matches_one_shot_digest_at_blake2_boundaries() {
        for header_len in [127_usize, 128, 129] {
            let data = bytes(4 * BLOCK_SIZE + 17);
            let expected = Digest::compute(&data);
            let (env, ctrl) = Env::mocked();
            ctrl.write_file("/file", data)
                .expect("the fixture is writable");
            let mut file = env.open(Path::new("/file")).expect("the file opens");
            let mut header = vec![0_u8; header_len];
            file.read_exact(&mut header)
                .expect("the header is readable");

            let actual = hash_file(&file, &header, 4 * BLOCK_SIZE as u64 + 17, 4)
                .expect("parallel reads succeed");
            assert_eq!(actual, expected, "header length {header_len}");
        }
    }

    #[test]
    fn ordered_pipeline_retries_interrupted_and_short_reads() {
        let data = bytes(4 * BLOCK_SIZE);
        let expected = Digest::compute(&data);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", data)
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .expect("the header is readable");
        ctrl.interrupt_next_read_at();
        ctrl.limit_next_read_at(17);

        let actual =
            hash_file(&file, &header, 4 * BLOCK_SIZE as u64, 2).expect("parallel reads retry");
        assert_eq!(actual, expected);
    }

    #[test]
    fn ordered_pipeline_caps_readers_and_buffers_by_segment_count() {
        let data = bytes(BLOCK_SIZE + 17);
        let expected = Digest::compute(&data);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", data)
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .expect("the header is readable");

        let actual = hash_file(&file, &header, BLOCK_SIZE as u64 + 17, 64)
            .expect("more lanes than segments are harmless");
        assert_eq!(actual, expected);
    }

    #[test]
    fn ordered_pipeline_surfaces_injected_positional_read_failures() {
        let data = bytes(4 * BLOCK_SIZE);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", data)
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .expect("the header is readable");
        ctrl.fail_read_at(BLOCK_SIZE as u64 + 100, io::ErrorKind::PermissionDenied);

        let error = hash_file(&file, &header, 4 * BLOCK_SIZE as u64, 4)
            .expect_err("the injected read fails");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn ordered_pipeline_reorders_scrambled_segments() {
        let data = bytes(4 * BLOCK_SIZE);
        let expected = Digest::compute(&data);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", data)
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .expect("the header is readable");
        ctrl.delay_read_at(60, Duration::from_millis(30));

        let actual = hash_file(&file, &header, 4 * BLOCK_SIZE as u64, 3)
            .expect("out-of-order reads succeed");
        assert_eq!(actual, expected);
    }

    #[test]
    fn lowest_offset_read_error_wins_after_a_later_error() {
        let data = bytes(4 * BLOCK_SIZE);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", data)
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .expect("the header is readable");
        ctrl.delay_read_at(60, Duration::from_millis(30));
        ctrl.fail_read_at(100, io::ErrorKind::PermissionDenied);
        ctrl.fail_read_at(BLOCK_SIZE as u64 + 100, io::ErrorKind::StorageFull);

        let error = hash_file(&file, &header, 4 * BLOCK_SIZE as u64, 3)
            .expect_err("both initial segments fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn reader_panic_cancels_siblings_and_resumes_on_the_coordinator() {
        let data = bytes(4 * BLOCK_SIZE);
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", data)
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .expect("the header is readable");
        ctrl.panic_read_at(BLOCK_SIZE as u64 + 100);

        let payload = panic::catch_unwind(AssertUnwindSafe(|| {
            hash_file(&file, &header, 4 * BLOCK_SIZE as u64, 3)
        }))
        .expect_err("the reader panic reaches the coordinator");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"the mocked positional read panicked")
        );
    }
}
