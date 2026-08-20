//! Temporary files created on the same filesystem as their target.
//!
//! Content files and the `.metadata/all` aggregate are written to a
//! uniquely named temporary file next to their final location and moved
//! into place with a rename. The guard removes the file
//! on drop unless it was persisted, so no temporary survives a
//! successful run or a reported error; only a killed process can leave
//! one, and a leftover is loudly reported by `verify` because it never
//! matches the store layout.

use std::io;
use std::path::{Path, PathBuf};

use crate::env::{Env, FileHandle};

/// A uniquely named temporary file, removed on drop unless persisted.
#[derive(Debug)]
pub(crate) struct TempFile {
    env: Env,
    path: PathBuf,
    file: Option<FileHandle>,
    keep: bool,
}

impl TempFile {
    /// Creates `<prefix><8 random hex chars>` in `dir`, retrying on the
    /// (vanishingly rare) name collision.
    pub(crate) fn create(env: &Env, dir: &Path, prefix: &str) -> io::Result<Self> {
        const ATTEMPTS: u32 = 16;
        for _ in 0..ATTEMPTS {
            let suffix = u32::from_be_bytes(env.random_array()?);
            let path = dir.join(format!("{prefix}{suffix:08x}"));
            match env.create_new(&path) {
                Ok(file) => {
                    return Ok(Self {
                        env: env.clone(),
                        path,
                        file: Some(file),
                        keep: false,
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a uniquely named temporary file",
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file_mut(&mut self) -> &mut FileHandle {
        self.file
            .as_mut()
            .expect("the file handle is open until persist")
    }

    /// The open handle, shareable across threads.
    ///
    /// Positional writes carry their own offset and move no shared
    /// cursor, so several writers can hold this one handle and write
    /// disjoint ranges at once; [`TempFile::file_mut`] is the sequential
    /// path's cursor-based view of the same file.
    pub(crate) fn file(&self) -> &FileHandle {
        self.file
            .as_ref()
            .expect("the file handle is open until persist")
    }

    /// Closes the file and renames it onto `target`.
    ///
    /// The rename is atomic on the same filesystem: `target` is either
    /// its previous content or the complete new content, never partial.
    /// On failure the temporary file is discarded and the rename error
    /// is returned, since that is the failure the caller acts on.
    pub(crate) fn persist(mut self, target: &Path) -> io::Result<()> {
        self.file = None; // Close before renaming, for platform portability.
        match self.env.rename(&self.path, target) {
            Ok(()) => {
                self.keep = true;
                Ok(())
            }
            Err(err) => {
                let _ = self.discard();
                Err(err)
            }
        }
    }

    /// Closes the file and removes it, reporting a removal failure.
    ///
    /// Dropping a temporary does the same cleanup, but a destructor
    /// cannot report anything; call this where the removal failure is
    /// part of the operation's outcome.
    pub(crate) fn discard(mut self) -> io::Result<()> {
        self.keep = true; // The removal happens here, not in the destructor.
        self.file = None;
        self.env.remove_file(&self.path)
    }
}

impl Drop for TempFile {
    /// Best-effort cleanup for temporaries that were neither persisted
    /// nor discarded, such as one left by an error path or an unwind. A
    /// destructor must not fail, so a removal error is dropped here;
    /// [`TempFile::discard`] is the reporting alternative.
    fn drop(&mut self) {
        if !self.keep {
            self.file = None;
            let _ = self.env.remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::TempFile;
    use crate::env::Env;

    #[test]
    fn persist_moves_the_file_and_keeps_it() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut temp = TempFile::create(&Env::native(), dir.path(), "unit-")?;
        temp.file_mut().write_all(b"payload")?;
        let temp_path = temp.path().to_owned();
        let target = dir.path().join("final");
        temp.persist(&target)?;
        assert!(!temp_path.exists());
        assert_eq!(std::fs::read(&target)?, b"payload");
        Ok(())
    }

    #[test]
    fn dropping_without_persist_removes_the_file() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let temp = TempFile::create(&Env::native(), dir.path(), "unit-")?;
        let temp_path = temp.path().to_owned();
        assert!(temp_path.exists());
        drop(temp);
        assert!(!temp_path.exists());
        Ok(())
    }

    #[test]
    fn discard_removes_the_file_and_reports_failures() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let temp = TempFile::create(&Env::native(), dir.path(), "unit-")?;
        let temp_path = temp.path().to_owned();
        temp.discard()?;
        assert!(!temp_path.exists());

        // Removing the file behind the guard's back makes the teardown
        // fail; dropping would have swallowed that error.
        let temp = TempFile::create(&Env::native(), dir.path(), "unit-")?;
        std::fs::remove_file(temp.path())?;
        let err = temp.discard().expect_err("the file is already gone");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        Ok(())
    }

    #[test]
    fn failed_persist_cleans_up_the_temporary() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let temp = TempFile::create(&Env::native(), dir.path(), "unit-")?;
        let temp_path = temp.path().to_owned();
        // Renaming onto a path inside a missing directory fails.
        let err = temp.persist(&dir.path().join("missing").join("final"));
        assert!(err.is_err());
        assert!(!temp_path.exists());
        Ok(())
    }
}
