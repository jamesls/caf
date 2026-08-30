//! Parallel generation of one file's bytes and identity.
//!
//! [`write_content`] fills one file from many threads and returns the
//! same digest, over the same bytes, that a sequential write produces.
//! Content blocks are independently derivable and their file offsets are
//! known upfront. Version 2 keeps a single ordered hashing stage because
//! its digest chains over the byte stream. Version 3 generators hash each
//! completed block directly into its indexed Merkle leaf slot.
//!
//! The shared stages run over one set of buffers:
//!
//! - **Generators** (`jobs` threads) take a buffer from the pool, claim
//!   the next block index, squeeze the block's SHAKE output into the
//!   buffer, and compute its v3 leaf when applicable.
//! - **Writers** (a few threads) put each block on disk at its offset
//!   the moment it exists, through positional writes that share one
//!   handle and move no cursor.
//! - **The v2 hasher** (the calling thread) absorbs blocks in index order,
//!   reordering what arrives early in a private map. Version 3 has no hash
//!   channel; after all workers finish, the caller reduces the leaf array.
//!
//! Whichever stage is slowest accumulates the buffers, the pool runs dry,
//! and the generators stall until it drains. The pool bounds file-data
//! memory, one block per buffer. Version 3 also holds one 32-byte leaf per
//! physical file block until reduction completes.
//!
//! Blocks are freed by [`Arc`]. Version 2 sends one reference to each
//! consumer; version 3 sends only to the writer. The final reference
//! returns the buffer to the pool. A write failure records itself, cancels
//! the run, and surfaces as the error of the whole file; the caller's
//! temporary-file guard removes the partial file.

use std::collections::BTreeMap;
use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use caf_format::{
    BLOCK_SIZE, ContentSeed, Digest, Format, HEADER_SIZE, Hasher, Header, MerkleHash,
    fill_block_prefix_with_format, v3_file_id_from_leaves, v3_leaf_hash,
};

use crate::env::FileHandle;
use crate::generate::GenerateError;
use crate::progress::ProgressTracker;
use crate::temp::TempFile;

/// Buffers the pool holds per generator thread.
///
/// One is the block being filled; the other three absorb the spread
/// between the block a generator has just produced and the block a
/// downstream consumer is still processing.
const BUFFERS_PER_GENERATOR: usize = 4;

/// Buffers the pool holds per writer thread: one being written and one
/// queued behind it, so a writer never waits on the queue for work that
/// has already been generated.
const BUFFERS_PER_WRITER: usize = 2;

/// Number of blocks a file of `file_size` bytes is written in.
///
/// Block 0 is the header plus content shortened by the header size, so
/// every later block starts at a [`BLOCK_SIZE`]-aligned file offset and
/// the count is a plain division.
pub(crate) fn total_blocks(file_size: u64) -> u64 {
    file_size.div_ceil(BLOCK_SIZE as u64)
}

/// Writes the whole file `header` describes into `temp` and returns its
/// digest.
///
/// The bytes and the digest are identical to a sequential write at any
/// `jobs` and `write_threads` count; both are speed knobs.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the file cannot be preallocated, if
/// the OS refuses to spawn a worker thread, or if a positional write
/// fails. When two writes fail, the reported error is the one at the
/// lowest block index, so the report does not depend on which writer
/// lost the race.
pub(crate) fn write_content(
    temp: &TempFile,
    header: &Header,
    jobs: NonZeroUsize,
    write_threads: NonZeroUsize,
    progress: Option<&ProgressTracker>,
) -> Result<Digest, GenerateError> {
    let plan = Plan::new(header);
    let generators = thread_count(jobs, plan.blocks);
    let writers = thread_count(write_threads, plan.blocks);

    // Preallocating lets the filesystem lay the whole file out once
    // instead of extending it under every positional write.
    temp.file().set_len(plan.file_size).map_err(|source| {
        GenerateError::io("preallocating the content file", temp.path(), source)
    })?;

    let pool = Pool::new(
        buffer_count(generators, writers, plan.blocks),
        plan.buffer_capacity(),
    );
    run(temp.file(), &plan, &pool, generators, writers, progress)
        .map_err(|source| GenerateError::io("writing content", temp.path(), source))
}

/// Runs the format-specific stages over `pool` and returns the file identity.
///
/// Split out from [`write_content`] so tests can hold the pool and check
/// that every buffer comes back.
fn run(
    file: &FileHandle,
    plan: &Plan,
    pool: &Pool,
    generators: usize,
    writers: usize,
    progress: Option<&ProgressTracker>,
) -> Result<Digest, io::Error> {
    match plan.format {
        Format::V2 => run_v2(file, plan, pool, generators, writers, progress),
        Format::V3 => run_v3(file, plan, pool, generators, writers, progress),
    }
}

/// Runs the ordered v2 hashing pipeline unchanged.
fn run_v2(
    file: &FileHandle,
    plan: &Plan,
    pool: &Pool,
    generators: usize,
    writers: usize,
    progress: Option<&ProgressTracker>,
) -> Result<Digest, io::Error> {
    let failure = ErrorSlot::new();
    let panicked = PanicSlot::new();
    let next_index = AtomicU64::new(0);
    let (hash_tx, hash_rx) = mpsc::channel();
    let (write_tx, write_rx) = mpsc::channel();
    let write_rx = Mutex::new(write_rx);

    // The calling thread hashes inside the scope, so the scope has
    // joined every generator and every writer — the last byte is on
    // disk — before the digest is used to name the file.
    let hashed = thread::scope(|scope| {
        let next_index = &next_index;
        // The OS can refuse a spawn under a process or thread limit. The
        // first refusal stops spawning and cancels the run: the threads
        // that did start drain out and exit, so the scope's implicit
        // join returns instead of waiting forever on generators stalled
        // against a pool that no consumer is refilling.
        let mut spawned = Ok(());
        for _ in 0..generators {
            if spawned.is_err() {
                break;
            }
            let hash_tx = hash_tx.clone();
            let write_tx = write_tx.clone();
            spawned = thread::Builder::new()
                .spawn_scoped(scope, move || {
                    generate_v2(plan, pool, next_index, &hash_tx, &write_tx);
                })
                .map(drop);
        }
        for _ in 0..writers {
            if spawned.is_err() {
                break;
            }
            spawned = thread::Builder::new()
                .spawn_scoped(scope, || {
                    write(file, &write_rx, pool, &failure, &panicked, progress);
                })
                .map(drop);
        }
        // The generators hold the only remaining senders, so both queues
        // close when the last of them exits.
        drop(hash_tx);
        drop(write_tx);

        if let Err(source) = spawned {
            pool.cancel();
            return Err(source);
        }
        Ok(hash_v2(&hash_rx, plan.blocks))
    });

    // The scope has joined the writers, so every write that was going to
    // happen has happened. A recorded panic resumes first — it is the
    // caller's own callback unwinding, not a result to report — then a
    // failure outranks a completed hash: the hasher only reads buffers
    // and can finish while a write is still failing, and a file is
    // correct only once every block reaches the disk.
    if let Some(payload) = panicked.take() {
        panic::resume_unwind(payload);
    }
    if let Some(source) = failure.take() {
        return Err(source);
    }
    // The block stream ends early only when a cancellation cuts it
    // short, and every cause — a failed write, a refused spawn, a
    // panicking writer — has returned or resumed above; a generator
    // panic unwinds through the scope.
    Ok(hashed?.expect("the block stream ends early only after a cancellation"))
}

/// Runs v3 generation with workers storing leaves directly by block index.
fn run_v3(
    file: &FileHandle,
    plan: &Plan,
    pool: &Pool,
    generators: usize,
    writers: usize,
    progress: Option<&ProgressTracker>,
) -> Result<Digest, io::Error> {
    let failure = ErrorSlot::new();
    let panicked = PanicSlot::new();
    let next_index = AtomicU64::new(0);
    let completed = AtomicU64::new(0);
    let leaves = Mutex::new(allocate_leaves(plan.blocks)?);
    let (write_tx, write_rx) = mpsc::channel();
    let write_rx = Mutex::new(write_rx);

    let spawned = thread::scope(|scope| {
        let next_index = &next_index;
        let completed = &completed;
        let leaves = &leaves;
        let mut spawned = Ok(());
        for _ in 0..generators {
            if spawned.is_err() {
                break;
            }
            let write_tx = write_tx.clone();
            spawned = thread::Builder::new()
                .spawn_scoped(scope, move || {
                    generate_v3(plan, pool, next_index, completed, leaves, &write_tx);
                })
                .map(drop);
        }
        for _ in 0..writers {
            if spawned.is_err() {
                break;
            }
            spawned = thread::Builder::new()
                .spawn_scoped(scope, || {
                    write(file, &write_rx, pool, &failure, &panicked, progress);
                })
                .map(drop);
        }
        drop(write_tx);

        if spawned.is_err() {
            pool.cancel();
        }
        spawned
    });

    if let Some(payload) = panicked.take() {
        panic::resume_unwind(payload);
    }
    if let Some(source) = failure.take() {
        return Err(source);
    }
    spawned?;
    if completed.load(Ordering::Relaxed) != plan.blocks {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "v3 generation ended before every block was produced",
        ));
    }
    let leaves = leaves.into_inner().unwrap_or_else(PoisonError::into_inner);
    Ok(Digest::from_bytes(
        v3_file_id_from_leaves(plan.file_size, leaves).into_inner(),
    ))
}

/// Everything a generator needs to produce any block of one file.
struct Plan {
    format: Format,
    seed: ContentSeed,
    header: [u8; HEADER_SIZE],
    file_size: u64,
    blocks: u64,
}

impl Plan {
    fn new(header: &Header) -> Self {
        Self {
            format: header.format(),
            seed: header.content_seed(),
            header: header.encode(),
            file_size: header.file_length(),
            blocks: total_blocks(header.file_length()),
        }
    }

    /// File bytes block `index` covers, short for the last block of a
    /// file whose length is not block aligned.
    fn block_len(&self, index: u64) -> usize {
        usize::try_from((self.file_size - block_offset(index)).min(BLOCK_SIZE as u64))
            .expect("a block covers at most BLOCK_SIZE bytes")
    }

    /// Bytes to allocate per pool buffer: a full block, or the whole
    /// file when it is smaller than one.
    fn buffer_capacity(&self) -> usize {
        self.block_len(0)
    }

    /// Fills `buffer` with block `index` as it appears in the file: the
    /// header followed by content for block 0, content alone after that.
    fn fill<'pool>(&self, index: u64, mut buffer: Vec<u8>, pool: &'pool Pool) -> Block<'pool> {
        let len = self.block_len(index);
        buffer.resize(len, 0);
        if index == 0 {
            // A header's file length is at least the header size, so
            // block 0 always has room for it.
            let (header, content) = buffer.split_at_mut(HEADER_SIZE);
            header.copy_from_slice(&self.header);
            fill_block_prefix_with_format(self.format, self.seed, 0, content);
        } else {
            fill_block_prefix_with_format(self.format, self.seed, index, &mut buffer);
        }
        Block {
            index,
            offset: block_offset(index),
            bytes: buffer,
            pool,
        }
    }
}

/// File offset block `index` starts at.
///
/// Exact, not approximate: block 0 is short by the header size, so every
/// block boundary lands on a [`BLOCK_SIZE`] multiple and no writer needs
/// to know what any other block produced.
fn block_offset(index: u64) -> u64 {
    index * BLOCK_SIZE as u64
}

/// One filled block, on loan from the pool.
///
/// The generator sends references to the format's consumers and keeps none.
/// The final consumer returns the buffer, so `Arc` is the release protocol.
struct Block<'pool> {
    index: u64,
    offset: u64,
    bytes: Vec<u8>,
    pool: &'pool Pool,
}

impl Block<'_> {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Block<'_> {
    fn drop(&mut self) {
        self.pool.put(mem::take(&mut self.bytes));
    }
}

/// Fills blocks until the indices run out or the run is cancelled.
fn generate_v2<'pool>(
    plan: &Plan,
    pool: &'pool Pool,
    next_index: &AtomicU64,
    hash_tx: &Sender<Arc<Block<'pool>>>,
    write_tx: &Sender<Arc<Block<'pool>>>,
) {
    // A buffer is taken before an index is claimed and indices are
    // claimed in increasing order, so the lowest block the hasher is
    // still waiting for always has a buffer behind it and always
    // arrives: the pipeline cannot deadlock on a dry pool.
    while let Some(buffer) = pool.take() {
        let index = next_index.fetch_add(1, Ordering::Relaxed);
        if index >= plan.blocks {
            pool.put(buffer);
            return;
        }
        let block = Arc::new(plan.fill(index, buffer, pool));
        // A closed queue means the consumer is gone, which only a
        // cancelled or unwinding run does; the block drops here.
        if write_tx.send(Arc::clone(&block)).is_err() || hash_tx.send(block).is_err() {
            return;
        }
    }
}

/// Generates v3 blocks and stores each Merkle leaf in its indexed slot.
fn generate_v3<'pool>(
    plan: &Plan,
    pool: &'pool Pool,
    next_index: &AtomicU64,
    completed: &AtomicU64,
    leaves: &Mutex<Vec<MerkleHash>>,
    write_tx: &Sender<Arc<Block<'pool>>>,
) {
    while let Some(buffer) = pool.take() {
        let index = next_index.fetch_add(1, Ordering::Relaxed);
        if index >= plan.blocks {
            pool.put(buffer);
            return;
        }
        let block = Arc::new(plan.fill(index, buffer, pool));
        let leaf = v3_leaf_hash(index, block.bytes());
        let slot = usize::try_from(index).expect("a block index fits because the leaf count does");
        leaves.lock().unwrap_or_else(PoisonError::into_inner)[slot] = leaf;
        completed.fetch_add(1, Ordering::Relaxed);
        if write_tx.send(block).is_err() {
            return;
        }
    }
}

/// Writes blocks at their file offsets until the queue closes.
///
/// A failure cancels the run, and blocks at or above the failing index
/// are then drained without writing: the dropped references are what
/// refill the pool and let a stalled generator observe the cancellation
/// and exit. A block below the failure is still written, so a failure
/// there moves the recorded error down and the report stays the one a
/// sequential write would have stopped at, whatever order the writers
/// ran in. Every such block does arrive: indices are claimed in
/// increasing order, so anything below a failed write was claimed before
/// it, and a claimed block always has its buffer.
fn write(
    file: &FileHandle,
    queue: &Mutex<Receiver<Arc<Block<'_>>>>,
    pool: &Pool,
    failure: &ErrorSlot,
    panicked: &PanicSlot,
    progress: Option<&ProgressTracker>,
) {
    // The progress callback is caller code and may panic. An unwinding
    // writer stops draining the queue, and without a cancellation the
    // generators would wait forever on a pool the retained blocks never
    // refill, deadlocking the scope's implicit join. So the panic is
    // caught, the pool cancelled, and the payload recorded; the caller
    // resumes the unwind once the scope has drained out.
    let worked = panic::catch_unwind(AssertUnwindSafe(|| {
        while let Ok(block) = next_block(queue) {
            if failure.outranks(block.index) {
                continue;
            }
            match file.write_all_at(block.bytes(), block.offset) {
                Ok(()) => {
                    if let Some(progress) = progress {
                        progress.add_bytes(block.bytes().len() as u64);
                    }
                }
                Err(source) => {
                    failure.record(block.index, source);
                    pool.cancel();
                }
            }
        }
    }));
    if let Err(payload) = worked {
        pool.cancel();
        panicked.record(payload);
    }
}

/// Takes the next block off the shared queue.
///
/// The lock is released before the caller writes, so writers only
/// serialize on the dequeue itself.
fn next_block<'pool>(
    queue: &Mutex<Receiver<Arc<Block<'pool>>>>,
) -> Result<Arc<Block<'pool>>, mpsc::RecvError> {
    queue.lock().unwrap_or_else(PoisonError::into_inner).recv()
}

/// Absorbs v2 blocks in index order through the streaming `BLAKE2b` state.
fn hash_v2(blocks: &Receiver<Arc<Block<'_>>>, total: u64) -> Option<Digest> {
    let mut hasher = Hasher::new();
    let mut pending: BTreeMap<u64, Arc<Block<'_>>> = BTreeMap::new();
    let mut next = 0_u64;
    while next < total {
        let Ok(block) = blocks.recv() else {
            return None;
        };
        // BLAKE2b chains over the byte stream in order, so a block that
        // arrives early waits here until every earlier one is absorbed.
        pending.insert(block.index, block);
        while let Some(block) = pending.remove(&next) {
            hasher.update(block.bytes());
            next += 1;
        }
    }
    Some(hasher.finalize())
}

/// Fallibly allocates the indexed v3 leaf array.
fn allocate_leaves(blocks: u64) -> io::Result<Vec<MerkleHash>> {
    let leaf_count = usize::try_from(blocks)
        .map_err(|_error| io::Error::new(io::ErrorKind::FileTooLarge, "too many v3 file blocks"))?;
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(leaf_count)
        .map_err(|_source| io::Error::from(io::ErrorKind::OutOfMemory))?;
    leaves.resize(leaf_count, MerkleHash::from_bytes([0; MerkleHash::SIZE]));
    Ok(leaves)
}

/// Threads to spawn for one stage against a `requested` parallelism:
/// never more than the file has blocks, since a generator with no block
/// to claim or a writer with no block to receive only costs a spawn.
fn thread_count(requested: NonZeroUsize, blocks: u64) -> usize {
    usize::try_from(blocks)
        .unwrap_or(usize::MAX)
        .min(requested.get())
}

/// Buffers to allocate, capped at the block count: a file cannot have
/// more blocks in flight than it has blocks.
fn buffer_count(generators: usize, writers: usize, blocks: u64) -> usize {
    let wanted = generators
        .saturating_mul(BUFFERS_PER_GENERATOR)
        .saturating_add(writers.saturating_mul(BUFFERS_PER_WRITER));
    usize::try_from(blocks).unwrap_or(usize::MAX).min(wanted)
}

/// The fixed set of block buffers the run recycles.
///
/// Handing out a buffer is what admits a generator to the next block, so
/// the pool size is the whole system's backpressure and its memory
/// bound: at most one block per buffer exists at any instant.
struct Pool {
    state: Mutex<PoolState>,
    returned: Condvar,
}

struct PoolState {
    free: Vec<Vec<u8>>,
    cancelled: bool,
}

impl Pool {
    fn new(buffers: usize, capacity: usize) -> Self {
        Self {
            state: Mutex::new(PoolState {
                free: (0..buffers).map(|_| vec![0_u8; capacity]).collect(),
                cancelled: false,
            }),
            returned: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        // The critical sections move a buffer and a flag and cannot
        // panic, so a poisoned lock still guards consistent state; the
        // poison can only have come from an unrelated unwind.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes a free buffer, blocking until one is returned. Returns
    /// `None` once the run is cancelled, which is how a stalled
    /// generator finds out.
    fn take(&self) -> Option<Vec<u8>> {
        let mut state = self.lock();
        loop {
            if state.cancelled {
                return None;
            }
            if let Some(buffer) = state.free.pop() {
                return Some(buffer);
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

    /// Buffers currently back in the pool.
    #[cfg(test)]
    fn free(&self) -> usize {
        self.lock().free.len()
    }
}

/// The first writer panic, held until the caller can resume it.
///
/// A writer's scoped join handle is dropped at spawn, so a panic that
/// unwound out of the thread would surface from the scope as a generic
/// payload. Recording it here lets the caller resume the original one.
struct PanicSlot {
    slot: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl PanicSlot {
    fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    fn record(&self, payload: Box<dyn std::any::Any + Send>) {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(payload);
        }
    }

    fn take(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// The write failure a run reports.
///
/// Keeping the lowest block index makes the reported error the one a
/// sequential write would have stopped at, rather than whichever writer
/// happened to fail first.
struct ErrorSlot {
    slot: Mutex<Option<(u64, io::Error)>>,
}

impl ErrorSlot {
    fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<(u64, io::Error)>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, index: u64, error: io::Error) {
        let mut slot = self.lock();
        if slot.as_ref().is_none_or(|(recorded, _)| index < *recorded) {
            *slot = Some((index, error));
        }
    }

    /// Whether the recorded failure is at or below block `index`,
    /// making a write of that block pointless: it could neither improve
    /// the report nor complete the file.
    fn outranks(&self, index: u64) -> bool {
        self.lock()
            .as_ref()
            .is_some_and(|(recorded, _)| *recorded <= index)
    }

    fn take(&self) -> Option<io::Error> {
        self.lock().take().map(|(_index, error)| error)
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use std::io::{self, Read as _, Write as _};
    use std::num::NonZeroUsize;
    use std::panic::{self, AssertUnwindSafe};
    use std::path::Path;

    use caf_format::{
        BLOCK_SIZE, ContentReader, ContentSeed, Digest, FileId, Format, HEADER_SIZE, Hasher,
        Header, v3_file_id_from_bytes,
    };

    use super::{
        BUFFERS_PER_GENERATOR, BUFFERS_PER_WRITER, ErrorSlot, Plan, Pool, block_offset,
        buffer_count, run, thread_count, total_blocks, write_content,
    };
    use crate::env::{Env, MockCtrl};
    use crate::progress::{ProgressCallback, ProgressTracker};
    use crate::temp::TempFile;

    /// Sizes that exercise every block boundary the writer has to get
    /// right: the smallest legal file, a partial single block, one exact
    /// block, a one-byte tail, an exact multiple, and a one-byte tail
    /// several blocks in.
    const BOUNDARY_SIZES: [u64; 7] = [
        HEADER_SIZE as u64,
        4096,
        BLOCK_SIZE as u64,
        BLOCK_SIZE as u64 + 1,
        2 * BLOCK_SIZE as u64,
        3 * BLOCK_SIZE as u64,
        3 * BLOCK_SIZE as u64 + 1,
    ];

    fn jobs(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("the tests use positive counts")
    }

    fn header_for(file_size: u64) -> Header {
        let seed = ContentSeed::from_bytes(*b"parallel-write!!");
        Header::new(Digest::ZERO, seed, file_size).expect("the sizes are at least a header")
    }

    fn v3_header_for(file_size: u64) -> Header {
        let seed = ContentSeed::from_bytes(*b"parallel-write!!");
        Header::new_v3(FileId::ZERO, seed, file_size).expect("the sizes are at least a header")
    }

    /// A mocked store with one temporary file open in it.
    fn temp_in_store(ctrl: &MockCtrl) -> TempFile {
        let env = Env::from_mock(ctrl.clone());
        env.create_dir_all(Path::new("/store"))
            .expect("the mocked root is creatable");
        TempFile::create(&env, Path::new("/store"), "temp-").expect("the temporary file is created")
    }

    /// Writes one file with the parallel path and returns its digest and
    /// the bytes that landed on disk.
    fn write_parallel(header: &Header, threads: usize) -> (Digest, Vec<u8>) {
        let (_env, ctrl) = Env::mocked();
        let temp = temp_in_store(&ctrl);
        let digest = write_content(&temp, header, jobs(threads), jobs(threads), None)
            .expect("the mocked writes succeed");
        let bytes = ctrl.read_file(temp.path()).expect("the file is readable");
        (digest, bytes)
    }

    /// Writes the same file the way the sequential path does: header,
    /// then the content stream, hashing as it goes.
    fn write_serial(file_size: u64) -> (Digest, Vec<u8>) {
        let (_env, ctrl) = Env::mocked();
        let mut temp = temp_in_store(&ctrl);
        let header = header_for(file_size);

        let mut hasher = Hasher::new();
        let encoded = header.encode();
        temp.file_mut().write_all(&encoded).expect("mocked write");
        hasher.update(encoded);

        let mut reader = ContentReader::new(header.content_seed());
        let mut buffer = vec![0_u8; BLOCK_SIZE];
        let mut remaining = header.content_length();
        while remaining > 0 {
            let take = usize::try_from(remaining.min(BLOCK_SIZE as u64)).expect("one block");
            let chunk = &mut buffer[..take];
            reader.read_exact(chunk).expect("infinite");
            temp.file_mut().write_all(chunk).expect("mocked write");
            hasher.update(chunk);
            remaining -= take as u64;
        }
        let bytes = ctrl.read_file(temp.path()).expect("the file is readable");
        (hasher.finalize(), bytes)
    }

    /// Builds the same v3 bytes without using the positional writer.
    fn write_v3_serial(header: &Header) -> (Digest, Vec<u8>) {
        let len = usize::try_from(header.file_length()).expect("test files fit in memory");
        let mut bytes = vec![0_u8; len];
        bytes[..HEADER_SIZE].copy_from_slice(&header.encode());
        ContentReader::new_with_format(header.content_seed(), Format::V3)
            .read_exact(&mut bytes[HEADER_SIZE..])
            .expect("the content stream is infinite");
        let digest = Digest::from_bytes(v3_file_id_from_bytes(&bytes).into_inner());
        (digest, bytes)
    }

    /// The load-bearing property: parallelism is a speed knob, so the
    /// file and its digest must be what the sequential path produces at
    /// every block boundary and every thread count.
    #[test]
    fn parallel_output_is_byte_identical_to_serial() {
        for file_size in BOUNDARY_SIZES {
            let (expected_digest, expected_bytes) = write_serial(file_size);
            assert_eq!(expected_bytes.len() as u64, file_size, "size {file_size}");
            for threads in [1, 2, 4, 7] {
                let (digest, bytes) = write_parallel(&header_for(file_size), threads);
                assert_eq!(bytes, expected_bytes, "size {file_size}, {threads} threads");
                assert_eq!(
                    digest, expected_digest,
                    "size {file_size}, {threads} threads",
                );
            }
        }
    }

    #[test]
    fn v3_parallel_output_covers_partial_and_odd_leaf_counts() {
        for file_size in [
            BLOCK_SIZE as u64 + 1,
            3 * BLOCK_SIZE as u64,
            5 * BLOCK_SIZE as u64,
        ] {
            let header = v3_header_for(file_size);
            let (expected_digest, expected_bytes) = write_v3_serial(&header);
            for threads in [2, 4, 7] {
                let (digest, bytes) = write_parallel(&header, threads);
                assert_eq!(bytes, expected_bytes, "size {file_size}, {threads} threads");
                assert_eq!(
                    digest, expected_digest,
                    "size {file_size}, {threads} threads",
                );
            }
        }
    }

    /// The golden vectors are files the Python implementation produced,
    /// at exactly the block boundaries this writer has to get right.
    /// Reproducing their digests and bytes pins the parallel path to the
    /// format itself, not just to this crate's sequential path.
    #[test]
    fn golden_vectors_are_reproduced_in_parallel() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/vectors.json");
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("golden vectors exist"))
                .expect("golden vectors parse");
        let vectors = json["file_vectors"]
            .as_array()
            .expect("file vectors are a list");
        assert!(!vectors.is_empty(), "the golden vectors are not empty");

        for vector in vectors {
            let name = vector["name"].as_str().expect("vectors are named");
            let header = Header::new(
                Digest::from_hex(text(vector, "parent_hash")).expect("vector parent"),
                ContentSeed::from_hex(text(vector, "content_seed")).expect("vector seed"),
                vector["file_length"].as_u64().expect("vector file length"),
            )
            .expect("vector lengths are at least a header");

            let (digest, bytes) = write_parallel(&header, 4);
            assert_eq!(
                digest.to_hex(),
                text(vector, "file_blake2b_160"),
                "{name}: whole-file digest",
            );
            assert_eq!(bytes.len() as u64, header.file_length(), "{name}: length");
            assert_eq!(
                hex::encode(&bytes[..HEADER_SIZE]),
                text(vector, "header"),
                "{name}: header bytes",
            );
            for slice in vector["content_slices"]
                .as_array()
                .expect("content slices are a list")
            {
                let offset = usize::try_from(slice["file_offset"].as_u64().expect("slice offset"))
                    .expect("golden offsets fit in memory");
                let expected = hex::decode(text(slice, "hex")).expect("slice hex");
                assert_eq!(
                    &bytes[offset..offset + expected.len()],
                    expected,
                    "{name}: content at {offset}",
                );
            }
        }
    }

    /// Reads a string field of a golden vector.
    fn text<'json>(vector: &'json serde_json::Value, field: &str) -> &'json str {
        vector[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is a string"))
    }

    #[test]
    fn block_counts_follow_the_file_size() {
        assert_eq!(total_blocks(HEADER_SIZE as u64), 1);
        assert_eq!(total_blocks(BLOCK_SIZE as u64), 1);
        assert_eq!(total_blocks(BLOCK_SIZE as u64 + 1), 2);
        assert_eq!(total_blocks(2 * BLOCK_SIZE as u64), 2);
    }

    /// Block 0 carries the header, so its content is short by the header
    /// size and every later block starts on a 1 MiB boundary.
    #[test]
    fn block_offsets_are_aligned_and_cover_the_file() {
        let plan = Plan::new(&header_for(2 * BLOCK_SIZE as u64 + 7));
        assert_eq!(plan.blocks, 3);
        assert_eq!(block_offset(0), 0);
        assert_eq!(plan.block_len(0), BLOCK_SIZE);
        assert_eq!(block_offset(1), BLOCK_SIZE as u64);
        assert_eq!(plan.block_len(1), BLOCK_SIZE);
        assert_eq!(block_offset(2), 2 * BLOCK_SIZE as u64);
        assert_eq!(plan.block_len(2), 7);
    }

    #[test]
    fn the_pool_is_sized_by_threads_and_capped_by_blocks() {
        assert_eq!(
            buffer_count(8, 4, 10_000),
            8 * BUFFERS_PER_GENERATOR + 4 * BUFFERS_PER_WRITER,
        );
        // A three-block file can never have four blocks in flight.
        assert_eq!(buffer_count(8, 4, 3), 3);
        // Generators and writers alike are clamped to the block count: a
        // four-block file gets at most four of each, however large the
        // requested parallelism.
        assert_eq!(thread_count(jobs(8), 3), 3);
        assert_eq!(thread_count(jobs(8), 10_000), 8);
        assert_eq!(thread_count(jobs(256), 4), 4);
    }

    /// Every buffer the pool lends out comes back, on the success path
    /// and after a cancelled run. Since the pool allocates its buffers
    /// once and never makes another, finding exactly the starting count
    /// afterwards is also the peak-memory bound: at most `K` blocks
    /// exist at any instant, whatever the file size.
    #[test]
    fn every_buffer_returns_to_the_pool() {
        let file_size = 4 * BLOCK_SIZE as u64 + 11;
        let plan = Plan::new(&header_for(file_size));
        let buffers = buffer_count(4, 2, plan.blocks);

        let (_env, ctrl) = Env::mocked();
        let temp = temp_in_store(&ctrl);
        let pool = Pool::new(buffers, plan.buffer_capacity());
        run(temp.file(), &plan, &pool, 4, 2, None).expect("the mocked writes succeed");
        assert_eq!(pool.free(), buffers, "after a successful run");

        // Failing every write cancels the run partway through.
        ctrl.fail_write_at(0, io::ErrorKind::StorageFull);
        ctrl.fail_write_at(BLOCK_SIZE as u64, io::ErrorKind::StorageFull);
        ctrl.fail_write_at(2 * BLOCK_SIZE as u64, io::ErrorKind::StorageFull);
        ctrl.fail_write_at(3 * BLOCK_SIZE as u64, io::ErrorKind::StorageFull);
        ctrl.fail_write_at(4 * BLOCK_SIZE as u64, io::ErrorKind::StorageFull);
        let pool = Pool::new(buffers, plan.buffer_capacity());
        let err = run(temp.file(), &plan, &pool, 4, 2, None).expect_err("every write fails");
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(pool.free(), buffers, "after a cancelled run");
    }

    /// Two blocks fail on every run, and whichever writer loses the race
    /// to fail first, the reported error is always the lower block's:
    /// the one a sequential write would have stopped at. This is the
    /// determinism the writers' drain rule exists for — a failure at a
    /// high block must not stop a lower, still-queued block from being
    /// attempted and taking over the report.
    #[test]
    fn a_lower_failure_after_a_cancellation_still_wins() {
        let plan = Plan::new(&header_for(4 * BLOCK_SIZE as u64));
        // Several runs, since the losing schedule is a thread race.
        for _ in 0..8 {
            let (_env, ctrl) = Env::mocked();
            let temp = temp_in_store(&ctrl);
            ctrl.fail_write_at(BLOCK_SIZE as u64, io::ErrorKind::PermissionDenied);
            ctrl.fail_write_at(3 * BLOCK_SIZE as u64, io::ErrorKind::StorageFull);
            let pool = Pool::new(buffer_count(4, 4, plan.blocks), plan.buffer_capacity());
            let err = run(temp.file(), &plan, &pool, 4, 4, None).expect_err("two writes fail");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    /// Two writers can fail at once; the reported error is the one at
    /// the lowest block index, which is the error a sequential write
    /// would have stopped at.
    #[test]
    fn the_lowest_index_error_wins() {
        let slot = ErrorSlot::new();
        slot.record(7, io::Error::from(io::ErrorKind::StorageFull));
        slot.record(3, io::Error::from(io::ErrorKind::PermissionDenied));
        slot.record(9, io::Error::from(io::ErrorKind::NotFound));
        let error = slot.take().expect("a failure was recorded");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(slot.take().is_none(), "the slot is emptied by take");
    }

    /// A panicking progress callback unwinds the only writer. The writer
    /// must cancel the pool on its way out, or the generators would wait
    /// forever on buffers held by the undrained queue and this test
    /// would hang instead of observing the panic.
    #[test]
    fn a_panicking_progress_callback_cancels_the_run() {
        let (_env, ctrl) = Env::mocked();
        let temp = temp_in_store(&ctrl);
        // The tracker reports a zero-byte snapshot at construction; only
        // the first written block trips the panic.
        let tracker = ProgressTracker::new(
            Some(ProgressCallback::new(|progress| {
                assert!(
                    progress.bytes_completed() == 0,
                    "the progress callback panicked"
                );
            })),
            None,
            None,
        );
        let header = header_for(8 * BLOCK_SIZE as u64);
        let payload = panic::catch_unwind(AssertUnwindSafe(|| {
            write_content(&temp, &header, jobs(4), jobs(1), Some(&tracker))
        }))
        .expect_err("the callback panic reaches the caller");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"the progress callback panicked")
        );
    }

    #[test]
    fn a_failed_preallocation_is_reported_with_the_temporary_path() {
        let (_env, ctrl) = Env::mocked();
        let temp = temp_in_store(&ctrl);
        ctrl.fail_set_len(io::ErrorKind::StorageFull);
        let err = write_content(&temp, &header_for(4096), jobs(4), jobs(2), None)
            .expect_err("preallocation fails");
        assert!(err.is_io());
        assert_eq!(err.path(), Some(temp.path()));
        assert_eq!(
            err.to_string(),
            format!(
                "preallocating the content file at {}",
                temp.path().display()
            )
        );
    }

    #[test]
    fn a_failed_write_is_reported_with_the_temporary_path() {
        let (_env, ctrl) = Env::mocked();
        let temp = temp_in_store(&ctrl);
        // Fail a block in the middle of the file, not the first one.
        ctrl.fail_write_at(2 * BLOCK_SIZE as u64, io::ErrorKind::PermissionDenied);
        let err = write_content(
            &temp,
            &header_for(4 * BLOCK_SIZE as u64),
            jobs(4),
            jobs(2),
            None,
        )
        .expect_err("the write fails");
        assert!(err.is_io());
        assert_eq!(err.path(), Some(temp.path()));
    }
}
