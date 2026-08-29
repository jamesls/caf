//! Native/mock dispatch for the filesystem and random-source syscalls.
//!
//! Generation and verification reach the operating system only through
//! [`Env`], an internal enum that dispatches either to `std::fs` and the
//! OS random source or, under the `test-util` feature, to an in-memory
//! [`MockCtrl`]. That keeps [`Generator`](crate::Generator) and
//! [`Verifier`](crate::Verifier) testable without touching a real
//! filesystem: `Generator::builder_mocked` and `Verifier::new_mocked` hand
//! back their own controller.
//!
//! The abstraction is deliberately thin — one method per syscall the
//! crate makes, with `std` types in the signatures — so the native path
//! stays a direct call. [`FileHandle`] carries the positional
//! ([`read_full_at`](FileHandle::read_full_at),
//! [`write_all_at`](FileHandle::write_all_at)) and preallocating
//! ([`set_len`](FileHandle::set_len)) operations parallel generation and
//! verification need alongside the cursor-based [`Read`]/[`Write`] impls
//! the sequential paths use.

#[cfg(feature = "test-util")]
pub(crate) mod mock;

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(feature = "test-util")]
pub use mock::MockCtrl;

/// The filesystem and random source a generator or verifier runs against.
#[derive(Clone, Debug)]
pub(crate) struct Env {
    core: EnvCore,
}

/// Internal dispatch: real syscalls, or a mock controller.
#[derive(Clone, Debug)]
enum EnvCore {
    Native,
    #[cfg(feature = "test-util")]
    Mocked(MockCtrl),
}

impl Env {
    /// The real filesystem and the operating-system random source.
    pub(crate) fn native() -> Self {
        Self {
            core: EnvCore::Native,
        }
    }

    /// An empty in-memory filesystem and a deterministic random source,
    /// plus the controller that inspects and drives them.
    #[cfg(feature = "test-util")]
    pub(crate) fn mocked() -> (Self, MockCtrl) {
        let ctrl = MockCtrl::new();
        (Self::from_mock(ctrl.clone()), ctrl)
    }

    /// The in-memory filesystem an existing controller already owns, so
    /// a generator and a verifier can share one mocked store.
    #[cfg(feature = "test-util")]
    pub(crate) fn from_mock(ctrl: MockCtrl) -> Self {
        Self {
            core: EnvCore::Mocked(ctrl),
        }
    }

    /// Returns `N` bytes from the random source.
    pub(crate) fn random_array<const N: usize>(&self) -> io::Result<[u8; N]> {
        let mut bytes = [0_u8; N];
        match &self.core {
            EnvCore::Native => crate::random::fill(&mut bytes)?,
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.fill_random(&mut bytes)?,
        }
        Ok(bytes)
    }

    /// Creates `path` and every missing parent directory.
    pub(crate) fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        match &self.core {
            EnvCore::Native => fs::create_dir_all(path),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.create_dir_all(path),
        }
    }

    /// Metadata for `path`, following symlinks.
    pub(crate) fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        match &self.core {
            EnvCore::Native => fs::metadata(path).map(|meta| Metadata::from_native(&meta)),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.metadata(path),
        }
    }

    /// Every entry of the directory at `path`, in unspecified order.
    pub(crate) fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        match &self.core {
            EnvCore::Native => fs::read_dir(path)?
                .map(|entry| {
                    let entry = entry?;
                    Ok(DirEntry {
                        file_type: FileType::from_native(entry.file_type()?),
                        path: entry.path(),
                    })
                })
                .collect(),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.read_dir(path),
        }
    }

    /// The whole content of the file at `path`.
    pub(crate) fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        match &self.core {
            EnvCore::Native => fs::read(path),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.read(path),
        }
    }

    /// Opens `path` for reading.
    pub(crate) fn open(&self, path: &Path) -> io::Result<FileHandle> {
        match &self.core {
            EnvCore::Native => File::open(path).map(FileHandle::Native),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.open(path).map(FileHandle::Mocked),
        }
    }

    /// Creates `path` for writing, truncating any existing file.
    pub(crate) fn create(&self, path: &Path) -> io::Result<FileHandle> {
        match &self.core {
            EnvCore::Native => File::create(path).map(FileHandle::Native),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.create(path, false).map(FileHandle::Mocked),
        }
    }

    /// Creates `path` for writing, failing if it already exists.
    pub(crate) fn create_new(&self, path: &Path) -> io::Result<FileHandle> {
        match &self.core {
            EnvCore::Native => OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(FileHandle::Native),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.create(path, true).map(FileHandle::Mocked),
        }
    }

    /// Renames `from` onto `to`, replacing `to` if it exists.
    pub(crate) fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        match &self.core {
            EnvCore::Native => fs::rename(from, to),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.rename(from, to),
        }
    }

    /// Removes the file at `path`.
    pub(crate) fn remove_file(&self, path: &Path) -> io::Result<()> {
        match &self.core {
            EnvCore::Native => fs::remove_file(path),
            #[cfg(feature = "test-util")]
            EnvCore::Mocked(ctrl) => ctrl.remove_file(path),
        }
    }
}

/// What a directory entry or a path points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileType {
    File,
    Dir,
    /// Only the native environment reports symlinks; the mock has none.
    Symlink,
}

impl FileType {
    fn from_native(file_type: fs::FileType) -> Self {
        if file_type.is_dir() {
            Self::Dir
        } else if file_type.is_symlink() {
            Self::Symlink
        } else {
            Self::File
        }
    }

    pub(crate) fn is_dir(self) -> bool {
        self == Self::Dir
    }

    pub(crate) fn is_symlink(self) -> bool {
        self == Self::Symlink
    }
}

/// Size and kind of one path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Metadata {
    len: u64,
    file_type: FileType,
}

impl Metadata {
    fn from_native(metadata: &fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            file_type: FileType::from_native(metadata.file_type()),
        }
    }

    pub(crate) fn len(self) -> u64 {
        self.len
    }

    pub(crate) fn is_dir(self) -> bool {
        self.file_type.is_dir()
    }
}

/// One entry of a directory listing.
#[derive(Clone, Debug)]
pub(crate) struct DirEntry {
    path: PathBuf,
    file_type: FileType,
}

impl DirEntry {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_path(self) -> PathBuf {
        self.path
    }

    pub(crate) fn file_name(&self) -> &OsStr {
        self.path.file_name().unwrap_or(self.path.as_os_str())
    }

    pub(crate) fn into_file_name(self) -> OsString {
        self.path
            .file_name()
            .unwrap_or(self.path.as_os_str())
            .to_os_string()
    }

    /// The entry's own kind: a symlink is reported as one, not followed.
    pub(crate) fn file_type(&self) -> FileType {
        self.file_type
    }
}

/// An open file: a real handle, or a mocked one.
#[derive(Debug)]
pub(crate) enum FileHandle {
    Native(File),
    #[cfg(feature = "test-util")]
    Mocked(mock::MockFile),
}

impl FileHandle {
    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        match self {
            Self::Native(file) => file.metadata().map(|meta| Metadata::from_native(&meta)),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => Ok(file.metadata()),
        }
    }

    /// Flushes the file's content to stable storage.
    pub(crate) fn sync_all(&self) -> io::Result<()> {
        match self {
            Self::Native(file) => file.sync_all(),
            #[cfg(feature = "test-util")]
            Self::Mocked(_) => Ok(()),
        }
    }

    /// Resizes the file to `len` bytes, zero-filling any growth.
    ///
    /// Used to preallocate a file whose size is known before its
    /// content is written, so the filesystem can lay it out in one go
    /// instead of extending it under every write.
    pub(crate) fn set_len(&self, len: u64) -> io::Result<()> {
        match self {
            Self::Native(file) => file.set_len(len),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.set_len(len),
        }
    }

    /// Reads once into `buf` at `offset`, independently of the file
    /// cursor. The read may be short and returns zero at end-of-file.
    /// Windows implements this with `seek_read`, which can move the
    /// handle's cursor as a side effect, so callers must not overlap
    /// positional reads with cursor-based I/O on the same handle.
    pub(crate) fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Native(file) => std::os::unix::fs::FileExt::read_at(file, buf, offset),
            #[cfg(windows)]
            Self::Native(file) => std::os::windows::fs::FileExt::seek_read(file, buf, offset),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.read_at(buf, offset),
        }
    }

    /// Reads into `buf` at `offset` until it is full or EOF is reached.
    ///
    /// Interrupted reads are retried and short reads advance both the
    /// buffer and file offset. A zero-byte read stops immediately, so an
    /// unexpected EOF cannot spin.
    pub(crate) fn read_full_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            let at = offset.checked_add(filled as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "positional read offset overflow",
                )
            })?;
            match self.read_at(&mut buf[filled..], at) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(filled)
    }

    /// Writes all of `buf` at `offset`, independent of the file cursor.
    ///
    /// The offset travels with each call and no shared cursor moves, so
    /// several threads may write disjoint ranges of one file through
    /// one handle at the same time. Short writes are retried, as
    /// [`Write::write_all`] does for the sequential path.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error, or
    /// [`io::ErrorKind::WriteZero`] if a write makes no progress.
    pub(crate) fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            let chunk = &buf[written..];
            let at = offset + written as u64;
            match self.write_at(chunk, at) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "a positional write made no progress",
                    ));
                }
                Ok(count) => written += count,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// One positional write, which may be short.
    ///
    /// Unix has `pwrite`, which never touches the cursor. Windows'
    /// `seek_write` moves the handle's cursor as a side effect, which is
    /// harmless here: nothing reads the cursor of a file being written
    /// positionally.
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Native(file) => std::os::unix::fs::FileExt::write_at(file, buf, offset),
            #[cfg(windows)]
            Self::Native(file) => std::os::windows::fs::FileExt::seek_write(file, buf, offset),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.write_at(buf, offset),
        }
    }
}

impl Read for FileHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Native(file) => file.read(buf),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.read(buf),
        }
    }
}

impl Write for FileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Native(file) => file.write(buf),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Native(file) => file.flush(),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.flush(),
        }
    }
}

impl Seek for FileHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Native(file) => file.seek(pos),
            #[cfg(feature = "test-util")]
            Self::Mocked(file) => file.seek(pos),
        }
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use std::io::{self, Read as _};
    use std::num::NonZeroUsize;
    use std::path::Path;

    use super::Env;
    use crate::{Generator, SizeChooser};

    #[test]
    fn mocked_positional_reads_retry_and_do_not_move_the_cursor() {
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", b"0123456789".to_vec())
            .expect("the fixture is writable");
        let mut file = env.open(Path::new("/file")).expect("the file opens");

        let mut cursor_prefix = [0_u8; 2];
        file.read_exact(&mut cursor_prefix).expect("cursor read");
        assert_eq!(&cursor_prefix, b"01");

        ctrl.interrupt_next_read_at();
        ctrl.limit_next_read_at(2);
        let mut positional = [0_u8; 6];
        let got = file
            .read_full_at(&mut positional, 3)
            .expect("interrupted and short reads are retried");
        assert_eq!(got, positional.len());
        assert_eq!(&positional, b"345678");

        let mut cursor_suffix = [0_u8; 2];
        file.read_exact(&mut cursor_suffix)
            .expect("cursor remains at 2");
        assert_eq!(&cursor_suffix, b"23");
    }

    #[test]
    fn mocked_positional_read_stops_on_eof_and_injects_offset_failures() {
        let (env, ctrl) = Env::mocked();
        ctrl.write_file("/file", b"abcdef".to_vec())
            .expect("the fixture is writable");
        let file = env.open(Path::new("/file")).expect("the file opens");

        let mut tail = [0_u8; 8];
        assert_eq!(file.read_full_at(&mut tail, 4).expect("read to EOF"), 2);
        assert_eq!(&tail[..2], b"ef");

        ctrl.fail_read_at(3, io::ErrorKind::PermissionDenied);
        let error = file
            .read_full_at(&mut tail, 0)
            .expect_err("the requested range covers the failed offset");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// The point of the dispatch: a full generate-then-verify round trip
    /// with no syscall behind it, serially and on the worker pipeline.
    #[test]
    fn a_mocked_store_generates_and_verifies_without_touching_disk() {
        let (generator, ctrl) = Generator::builder_mocked("/store");
        let report = generator
            .max_files(4)
            .file_sizes(SizeChooser::fixed(1024))
            .build()
            .generate()
            .expect("mocked generation succeeds");
        assert_eq!(report.files_created(), 4);
        assert_eq!(report.bytes_written(), 4 * 1024);

        for jobs in [1, 4] {
            let verification = ctrl
                .verifier("/store")
                .jobs(NonZeroUsize::new(jobs).expect("positive"))
                .verify()
                .expect("mocked verification runs");
            assert!(verification.success(), "{:?}", verification.diagnostics());
            assert_eq!(verification.files_checked(), 4, "jobs {jobs}");
        }
        assert!(!std::path::Path::new("/store").exists());
    }

    /// Corruption is detected the same way it is on a real filesystem:
    /// flip a stored byte through the controller and re-verify.
    #[test]
    fn corruption_seeded_through_the_controller_is_detected() {
        let (generator, ctrl) = Generator::builder_mocked("/store");
        generator
            .max_files(1)
            .file_sizes(SizeChooser::fixed(1024))
            .build()
            .generate()
            .expect("mocked generation succeeds");

        let data_file = ctrl
            .paths()
            .into_iter()
            .find(|path| !path.starts_with("/store/.metadata") && ctrl.read_file(path).is_ok())
            .expect("the store has one data file");
        let mut content = ctrl
            .read_file(&data_file)
            .expect("the data file is readable");
        content[100] ^= 0xFF;
        ctrl.write_file(&data_file, content)
            .expect("the data file is writable");

        let verification = ctrl
            .verifier("/store")
            .verify()
            .expect("mocked verification runs");
        assert!(!verification.success());
        assert_eq!(verification.corruption_reports().count(), 1);
    }

    /// Injected failures reach the caller as structured errors, which is
    /// what a real filesystem can only produce through permissions.
    #[test]
    fn injected_failures_surface_as_structured_errors() {
        let (generator, ctrl) = Generator::builder_mocked("/store");
        ctrl.fail_random(io::ErrorKind::Other);
        let err = generator
            .max_files(1)
            .build()
            .generate()
            .expect_err("the random source fails");
        assert!(err.is_randomness());

        let (generator, ctrl) = Generator::builder_mocked("/store");
        ctrl.fail("/store", io::ErrorKind::PermissionDenied);
        let err = generator
            .max_files(1)
            .build()
            .generate()
            .expect_err("the store root is unwritable");
        assert!(err.is_io());
        assert_eq!(err.path(), Some(std::path::Path::new("/store")));
    }
}
