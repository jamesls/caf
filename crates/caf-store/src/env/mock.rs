//! In-memory filesystem and deterministic random source (`test-util`).
//!
//! [`MockCtrl`] backs the mocked half of [`Env`](super::Env). It stores
//! a flat map of path to node, so paths are compared exactly as the
//! caller spells them: build them the way the crate does, by joining
//! onto the store root handed to `Generator::builder_mocked` or
//! `Verifier::new_mocked`. Symlinks, permissions, and timestamps are not
//! modeled; nothing in generation or verification depends on them beyond
//! the symlink rules of the walk, which a mocked store never exercises.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::{DirEntry, FileType, Metadata};

/// Drives and inspects a mocked [`Generator`](crate::Generator) or
/// [`Verifier`](crate::Verifier).
///
/// Obtained from `Generator::builder_mocked` or `Verifier::new_mocked`; a
/// clone shares one in-memory filesystem, so the controller can seed a
/// store before a run and read it back afterwards. Every method is
/// thread-safe, which is what lets a mocked verifier use its worker
/// pipeline.
///
/// # Examples
///
/// Generate a store and verify it, entirely in memory:
///
/// ```
/// # #[cfg(feature = "test-util")] {
/// use caf_store::{Generator, SizeChooser};
///
/// let (generator, ctrl) = Generator::builder_mocked("/store");
/// let report = generator
///     .max_files(2)
///     .file_sizes(SizeChooser::fixed(1024))
///     .build()
///     .generate()?;
/// assert_eq!(report.files_created(), 2);
/// assert!(ctrl.exists("/store/.metadata/all"));
///
/// let verification = ctrl.verifier("/store").verify()?;
/// assert!(verification.success());
/// assert_eq!(verification.files_checked(), 2);
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct MockCtrl {
    inner: Arc<Mutex<MockState>>,
}

#[derive(Debug)]
struct MockState {
    nodes: BTreeMap<PathBuf, Node>,
    /// Bytes handed out before the deterministic sequence resumes.
    queued_random: VecDeque<u8>,
    random_counter: u64,
    random_failure: Option<io::ErrorKind>,
    failures: BTreeMap<PathBuf, io::ErrorKind>,
}

#[derive(Debug)]
enum Node {
    Dir,
    /// Shared so an open handle keeps working across a rename, as a real
    /// file descriptor does.
    File(Arc<Mutex<Vec<u8>>>),
}

impl MockCtrl {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState {
                nodes: BTreeMap::new(),
                queued_random: VecDeque::new(),
                random_counter: 0,
                random_failure: None,
                failures: BTreeMap::new(),
            })),
        }
    }

    /// A generator builder writing into this controller's filesystem.
    #[must_use]
    pub fn generator(&self, root: impl Into<PathBuf>) -> crate::GeneratorBuilder {
        crate::GeneratorBuilder::with_env(super::Env::from_mock(self.clone()), root)
    }

    /// A verifier reading this controller's filesystem, so a mocked
    /// store can be generated and verified in one test.
    #[must_use]
    pub fn verifier(&self, root: impl Into<PathBuf>) -> crate::Verifier {
        crate::Verifier::with_env(super::Env::from_mock(self.clone()), root)
    }

    fn lock(&self) -> MutexGuard<'_, MockState> {
        // A poisoned lock leaves the map consistent (no operation can
        // panic partway through a mutation), so keep going rather than
        // turning a test failure into a cascade of panics.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Creates `path` and every missing parent directory.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::NotADirectory`] if `path` or one of its
    /// parents already exists as a file.
    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        let mut state = self.lock();
        state.check_failure(path)?;
        let mut ancestors: Vec<&Path> = path.ancestors().collect();
        ancestors.reverse();
        for ancestor in ancestors {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            match state.nodes.get(ancestor) {
                Some(Node::Dir) => {}
                Some(Node::File(_)) => return Err(error(io::ErrorKind::NotADirectory, ancestor)),
                None => {
                    state.nodes.insert(ancestor.to_owned(), Node::Dir);
                }
            }
        }
        Ok(())
    }

    /// Writes `contents` to `path`, creating parent directories.
    ///
    /// Seeds a store for a mocked verifier; unlike the filesystem, the
    /// parents are created for you.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::NotADirectory`] if a parent of `path`
    /// already exists as a file.
    pub fn write_file(
        &self,
        path: impl AsRef<Path>,
        contents: impl Into<Vec<u8>>,
    ) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        let mut state = self.lock();
        state.check_failure(path)?;
        state.nodes.insert(
            path.to_owned(),
            Node::File(Arc::new(Mutex::new(contents.into()))),
        );
        Ok(())
    }

    /// Returns the content of the file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::NotFound`] if nothing is at `path`, or
    /// [`io::ErrorKind::IsADirectory`] if it is a directory.
    pub fn read_file(&self, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        self.read(path.as_ref())
    }

    /// Returns `true` if anything exists at `path`.
    #[must_use]
    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.lock().nodes.contains_key(path.as_ref())
    }

    /// Returns every path in the mocked filesystem, sorted.
    #[must_use]
    pub fn paths(&self) -> Vec<PathBuf> {
        self.lock().nodes.keys().cloned().collect()
    }

    /// Queues bytes for the next reads of the random source, ahead of
    /// the deterministic sequence.
    pub fn push_random(&self, bytes: impl AsRef<[u8]>) {
        self.lock().queued_random.extend(bytes.as_ref());
    }

    /// Makes every later operation on `path` fail with `kind`.
    ///
    /// This is how a mocked run exercises I/O failure paths that a real
    /// filesystem only reaches through permissions or a full disk.
    pub fn fail(&self, path: impl AsRef<Path>, kind: io::ErrorKind) {
        self.lock().failures.insert(path.as_ref().to_owned(), kind);
    }

    /// Makes every later read of the random source fail with `kind`.
    pub fn fail_random(&self, kind: io::ErrorKind) {
        self.lock().random_failure = Some(kind);
    }

    /// Clears every injected failure, including the random source's.
    pub fn clear_failures(&self) {
        let mut state = self.lock();
        state.failures.clear();
        state.random_failure = None;
    }

    pub(crate) fn fill_random(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut state = self.lock();
        if let Some(kind) = state.random_failure {
            return Err(io::Error::new(kind, "the mocked random source failed"));
        }
        for slot in buf.iter_mut() {
            *slot = state.next_random_byte();
        }
        Ok(())
    }

    pub(crate) fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        let state = self.lock();
        state.check_failure(path)?;
        match state.nodes.get(path) {
            Some(Node::Dir) => Ok(Metadata {
                len: 0,
                file_type: FileType::Dir,
            }),
            Some(Node::File(data)) => Ok(Metadata {
                len: length_of(data),
                file_type: FileType::File,
            }),
            None => Err(error(io::ErrorKind::NotFound, path)),
        }
    }

    pub(crate) fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let state = self.lock();
        state.check_failure(path)?;
        match state.nodes.get(path) {
            Some(Node::Dir) => {}
            Some(Node::File(_)) => return Err(error(io::ErrorKind::NotADirectory, path)),
            None => return Err(error(io::ErrorKind::NotFound, path)),
        }
        Ok(state
            .nodes
            .iter()
            .filter(|(child, _)| child.parent() == Some(path))
            .map(|(child, node)| DirEntry {
                path: child.clone(),
                file_name: child.file_name().unwrap_or(path.as_os_str()).to_os_string(),
                file_type: match node {
                    Node::Dir => FileType::Dir,
                    Node::File(_) => FileType::File,
                },
            })
            .collect())
    }

    pub(crate) fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let state = self.lock();
        state.check_failure(path)?;
        match state.nodes.get(path) {
            Some(Node::File(data)) => Ok(contents_of(data)),
            Some(Node::Dir) => Err(error(io::ErrorKind::IsADirectory, path)),
            None => Err(error(io::ErrorKind::NotFound, path)),
        }
    }

    pub(crate) fn open(&self, path: &Path) -> io::Result<MockFile> {
        let state = self.lock();
        state.check_failure(path)?;
        match state.nodes.get(path) {
            Some(Node::File(data)) => Ok(MockFile::new(Arc::clone(data), false)),
            Some(Node::Dir) => Err(error(io::ErrorKind::IsADirectory, path)),
            None => Err(error(io::ErrorKind::NotFound, path)),
        }
    }

    /// Creates a writable file at `path`, truncating an existing one
    /// unless `exclusive` is set, in which case an existing path is an
    /// [`io::ErrorKind::AlreadyExists`] error.
    pub(crate) fn create(&self, path: &Path, exclusive: bool) -> io::Result<MockFile> {
        let mut state = self.lock();
        state.check_failure(path)?;
        if state.nodes.contains_key(path) {
            if exclusive {
                return Err(error(io::ErrorKind::AlreadyExists, path));
            }
            if matches!(state.nodes.get(path), Some(Node::Dir)) {
                return Err(error(io::ErrorKind::IsADirectory, path));
            }
        }
        state.require_parent_dir(path)?;
        let data = Arc::new(Mutex::new(Vec::new()));
        state
            .nodes
            .insert(path.to_owned(), Node::File(Arc::clone(&data)));
        Ok(MockFile::new(data, true))
    }

    pub(crate) fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut state = self.lock();
        state.check_failure(from)?;
        state.check_failure(to)?;
        if !state.nodes.contains_key(from) {
            return Err(error(io::ErrorKind::NotFound, from));
        }
        state.require_parent_dir(to)?;
        let node = state
            .nodes
            .remove(from)
            .expect("the node was just confirmed present");
        state.nodes.insert(to.to_owned(), node);
        Ok(())
    }

    pub(crate) fn remove_file(&self, path: &Path) -> io::Result<()> {
        let mut state = self.lock();
        state.check_failure(path)?;
        match state.nodes.get(path) {
            Some(Node::File(_)) => {
                state.nodes.remove(path);
                Ok(())
            }
            Some(Node::Dir) => Err(error(io::ErrorKind::IsADirectory, path)),
            None => Err(error(io::ErrorKind::NotFound, path)),
        }
    }
}

impl MockState {
    fn check_failure(&self, path: &Path) -> io::Result<()> {
        match self.failures.get(path) {
            Some(kind) => Err(error(*kind, path)),
            None => Ok(()),
        }
    }

    /// A path's parent must be an existing directory before a file can
    /// be created there, as on a real filesystem. An empty parent is the
    /// implicit working directory.
    fn require_parent_dir(&self, path: &Path) -> io::Result<()> {
        match path.parent() {
            None => Ok(()),
            Some(parent) if parent.as_os_str().is_empty() => Ok(()),
            Some(parent) => match self.nodes.get(parent) {
                Some(Node::Dir) => Ok(()),
                Some(Node::File(_)) => Err(error(io::ErrorKind::NotADirectory, parent)),
                None => Err(error(io::ErrorKind::NotFound, parent)),
            },
        }
    }

    /// `SplitMix64` over a run-local counter: distinct, reproducible bytes
    /// with no operating-system call.
    fn next_random_byte(&mut self) -> u8 {
        if let Some(byte) = self.queued_random.pop_front() {
            return byte;
        }
        self.random_counter = self.random_counter.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.random_counter;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "one byte per step is the intent"
        )]
        {
            (z ^ (z >> 31)) as u8
        }
    }
}

/// An open handle onto one mocked file.
#[derive(Debug)]
pub(crate) struct MockFile {
    data: Arc<Mutex<Vec<u8>>>,
    position: u64,
    writable: bool,
}

impl MockFile {
    fn new(data: Arc<Mutex<Vec<u8>>>, writable: bool) -> Self {
        Self {
            data,
            position: 0,
            writable,
        }
    }

    pub(crate) fn metadata(&self) -> Metadata {
        Metadata {
            len: length_of(&self.data),
            file_type: FileType::File,
        }
    }
}

impl Read for MockFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = lock(&self.data);
        let Ok(start) = usize::try_from(self.position) else {
            return Ok(0);
        };
        if start >= data.len() {
            return Ok(0);
        }
        let take = buf.len().min(data.len() - start);
        buf[..take].copy_from_slice(&data[start..start + take]);
        drop(data);
        self.position += take as u64;
        Ok(take)
    }
}

impl Write for MockFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the mocked file is open for reading",
            ));
        }
        let mut data = lock(&self.data);
        let start = usize::try_from(self.position)
            .map_err(|_err| io::Error::from(io::ErrorKind::InvalidInput))?;
        if data.len() < start {
            data.resize(start, 0);
        }
        let end = start + buf.len();
        if data.len() < end {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(buf);
        drop(data);
        self.position = end as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for MockFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let length = length_of(&self.data);
        let (base, offset) = match pos {
            SeekFrom::Start(absolute) => {
                self.position = absolute;
                return Ok(absolute);
            }
            SeekFrom::End(offset) => (length, offset),
            SeekFrom::Current(offset) => (self.position, offset),
        };
        let target = base
            .checked_add_signed(offset)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.position = target;
        Ok(target)
    }
}

fn lock(data: &Arc<Mutex<Vec<u8>>>) -> MutexGuard<'_, Vec<u8>> {
    data.lock().unwrap_or_else(PoisonError::into_inner)
}

fn length_of(data: &Arc<Mutex<Vec<u8>>>) -> u64 {
    lock(data).len() as u64
}

fn contents_of(data: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    lock(data).clone()
}

/// An `io::Error` that names the path it happened on, like the real
/// filesystem errors the crate wraps.
fn error(kind: io::ErrorKind, path: &Path) -> io::Error {
    io::Error::new(kind, format!("{} (mocked)", path.display()))
}
