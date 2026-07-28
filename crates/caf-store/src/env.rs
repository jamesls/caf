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
//! stays a direct call.

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
                        file_name: entry.file_name(),
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

    pub(crate) fn is_file(self) -> bool {
        self.file_type == FileType::File
    }
}

/// One entry of a directory listing.
#[derive(Clone, Debug)]
pub(crate) struct DirEntry {
    path: PathBuf,
    file_name: OsString,
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
        &self.file_name
    }

    pub(crate) fn into_file_name(self) -> OsString {
        self.file_name
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
    use std::io;
    use std::num::NonZeroUsize;

    use crate::{Generator, SizeChooser};

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
