//! Operation progress callbacks shared by generation and verification.

use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// A point-in-time snapshot of generation or verification progress.
///
/// Byte and file totals are present when the operation knows them. For
/// generation with sampled file sizes, a byte total may be the configured
/// disk-usage stopping limit rather than the exact final size; the final file
/// is allowed to overshoot that limit. All values are monotonically
/// nondecreasing except that no total is inferred when it is unknowable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationProgress {
    bytes_completed: u64,
    total_bytes: Option<u64>,
    files_completed: u64,
    total_files: Option<u64>,
}

impl OperationProgress {
    /// Bytes written or checked so far.
    #[must_use]
    pub fn bytes_completed(self) -> u64 {
        self.bytes_completed
    }

    /// Total bytes expected, or a generation disk-usage limit when exact
    /// output size is unknowable.
    #[must_use]
    pub fn total_bytes(self) -> Option<u64> {
        self.total_bytes
    }

    /// Files fully written or checked so far.
    #[must_use]
    pub fn files_completed(self) -> u64 {
        self.files_completed
    }

    /// Total files expected, when known.
    #[must_use]
    pub fn total_files(self) -> Option<u64> {
        self.total_files
    }
}

/// A thread-safe callback configured by an operation's builder.
#[derive(Clone)]
pub(crate) struct ProgressCallback(Arc<dyn Fn(OperationProgress) + Send + Sync>);

impl ProgressCallback {
    pub(crate) fn new(report: impl Fn(OperationProgress) + Send + Sync + 'static) -> Self {
        Self(Arc::new(report))
    }

    fn report(&self, progress: OperationProgress) {
        (self.0)(progress);
    }
}

impl Debug for ProgressCallback {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("ProgressCallback")
    }
}

/// Shared counters behind one operation's worker threads.
#[derive(Debug)]
pub(crate) struct ProgressTracker {
    callback: Option<ProgressCallback>,
    bytes_completed: AtomicU64,
    total_bytes: Option<u64>,
    files_completed: AtomicU64,
    total_files: Option<u64>,
    reporting: Mutex<()>,
}

impl ProgressTracker {
    pub(crate) fn new(
        callback: Option<ProgressCallback>,
        total_bytes: Option<u64>,
        total_files: Option<u64>,
    ) -> Self {
        let tracker = Self {
            callback,
            bytes_completed: AtomicU64::new(0),
            total_bytes,
            files_completed: AtomicU64::new(0),
            total_files,
            reporting: Mutex::new(()),
        };
        tracker.report();
        tracker
    }

    pub(crate) fn enabled(&self) -> bool {
        self.callback.is_some()
    }

    pub(crate) fn add_bytes(&self, bytes: u64) {
        if bytes == 0 || !self.enabled() {
            return;
        }
        saturating_add(&self.bytes_completed, bytes);
        self.report();
    }

    pub(crate) fn finish_file(&self) {
        if !self.enabled() {
            return;
        }
        saturating_add(&self.files_completed, 1);
        self.report();
    }

    fn report(&self) {
        if let Some(callback) = &self.callback {
            // Worker updates race, but callback delivery must not: otherwise
            // an older snapshot could arrive after a newer one and make a
            // terminal progress bar jump backwards.
            let _reporting = self
                .reporting
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            callback.report(OperationProgress {
                bytes_completed: self.bytes_completed.load(Ordering::Relaxed),
                total_bytes: self.total_bytes,
                files_completed: self.files_completed.load(Ordering::Relaxed),
                total_files: self.total_files,
            });
        }
    }
}

/// Adds without wrapping at the edge of the counter's range.
fn saturating_add(counter: &AtomicU64, amount: u64) {
    let _previous = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

/// Caps one file's contributions so a second analysis/read pass never makes
/// operation progress exceed the file's on-disk size.
#[derive(Debug)]
pub(crate) struct FileProgress<'tracker> {
    tracker: &'tracker ProgressTracker,
    file_size: u64,
    bytes_completed: AtomicU64,
}

impl<'tracker> FileProgress<'tracker> {
    pub(crate) fn new(tracker: &'tracker ProgressTracker, file_size: u64) -> Self {
        Self {
            tracker,
            file_size,
            bytes_completed: AtomicU64::new(0),
        }
    }

    pub(crate) fn add_bytes(&self, bytes: u64) {
        if bytes == 0 || !self.tracker.enabled() {
            return;
        }
        let mut added = 0;
        let _previous =
            self.bytes_completed
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    let next = current.saturating_add(bytes).min(self.file_size);
                    added = next - current;
                    Some(next)
                });
        self.tracker.add_bytes(added);
    }

    pub(crate) fn finish(&self) {
        if !self.tracker.enabled() {
            return;
        }
        let completed = self.bytes_completed.swap(self.file_size, Ordering::Relaxed);
        self.tracker
            .add_bytes(self.file_size.saturating_sub(completed));
        self.tracker.finish_file();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{FileProgress, ProgressCallback, ProgressTracker};

    #[test]
    fn snapshots_are_monotonic_and_file_reads_are_capped() {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let reported = Arc::clone(&snapshots);
        let tracker = ProgressTracker::new(
            Some(ProgressCallback::new(move |snapshot| {
                reported.lock().expect("callback lock").push(snapshot);
            })),
            Some(100),
            Some(1),
        );
        let file = FileProgress::new(&tracker, 100);
        file.add_bytes(60);
        file.add_bytes(100);
        file.finish();

        let snapshots = snapshots.lock().expect("callback lock");
        assert_eq!(snapshots[0].bytes_completed(), 0);
        assert_eq!(
            snapshots
                .last()
                .expect("a final snapshot")
                .bytes_completed(),
            100
        );
        assert_eq!(
            snapshots
                .last()
                .expect("a final snapshot")
                .files_completed(),
            1
        );
        assert!(snapshots.windows(2).all(|pair| {
            pair[0].bytes_completed() <= pair[1].bytes_completed()
                && pair[0].files_completed() <= pair[1].files_completed()
        }));
    }
}
