//! CAF store operations: generation, verification, reports, and concurrency.
//!
//! This crate performs the filesystem work for CAF stores:
//!
//! - One-chain generation ([`Generator`]): size selection ([`SizeSpec`],
//!   [`SizeChooser`]), temporary-file handling, hash-based placement,
//!   directory caching, root markers, and atomic `.metadata/all`
//!   replacement.
//! - Verification ([`Verifier`]): metadata, file, parent, root, and
//!   orphan checks; corruption regeneration, pattern classification
//!   ([`CorruptionPattern`]), region merging, and structured reports
//!   ([`VerificationReport`], [`Diagnostic`], [`CorruptionReport`]).
//! - Bounded parallel verification ([`Verifier::jobs`]): one global
//!   worker budget shared by concurrent files and positional segment
//!   readers within large files, with results collected back in sorted
//!   file and byte order so serial and parallel reports are identical.
//! - Parallel generation of one file ([`GeneratorBuilder::jobs`]): block
//!   generators and positional writers over a fixed buffer pool, plus the
//!   v2 ordered hasher or v3 indexed Merkle leaves, producing byte-identical
//!   files at any worker count.
//!
//! Operations resolve paths from an explicit store root and never change the
//! process working directory. Configuration uses builders; results,
//! diagnostics, and corruption reports are structured values — nothing in
//! this crate prints, installs a global logger, or renders terminal output.
//! Failures use operation-specific error types ([`GenerateError`],
//! [`ParseSizeError`]) that carry paths and source errors, and are safe to
//! move between worker threads.
//!
//! Format rules (headers, digests, content, hash paths) live in
//! [`caf-format`](../caf_format/index.html); the CLI lives in the `caf`
//! binary crate.
//!
//! # Examples
//!
//! Generate a three-file chain, then verify the store:
//!
//! ```
//! use caf_store::{Generator, SizeChooser, SizeSpec, Verifier};
//!
//! let store = tempfile::tempdir()?;
//! let spec: SizeSpec = "1kb-2kb".parse()?;
//! let report = Generator::builder(store.path())
//!     .max_files(3)
//!     .file_sizes(spec.chooser()?)
//!     .build()
//!     .generate()?;
//! assert_eq!(report.files_created(), 3);
//!
//! let verification = Verifier::new(store.path()).verify()?;
//! assert!(verification.success());
//! assert_eq!(verification.files_checked(), 3);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod analysis;
mod env;
mod generate;
mod metadata;
mod parallel_verify;
mod parallel_write;
mod pipeline;
mod random;
mod size;
mod temp;
mod verify;

#[doc(inline)]
pub use analysis::{CorruptionClass, CorruptionPattern, CorruptionRegion, CorruptionReport};
#[cfg(feature = "test-util")]
#[doc(inline)]
pub use env::MockCtrl;
#[doc(inline)]
pub use generate::{
    DEFAULT_FILE_SIZE, GenerateError, GenerationReport, Generator, GeneratorBuilder,
};
#[doc(inline)]
pub use size::{
    ParseSizeError, SampleError, SizeChooser, SizeSpec, SizeSpecError, parse_byte_size,
};
#[doc(inline)]
pub use verify::{
    DEFAULT_ANALYSIS_CHUNK_SIZE, Diagnostic, MAX_ANALYSIS_CHUNK_SIZE, Severity, VerificationReport,
    Verifier, VerifyError,
};

use std::num::NonZeroUsize;

/// Largest worker count honored by [`Verifier::jobs`] and
/// [`GeneratorBuilder::jobs`].
///
/// A resource bound: each worker costs a thread and verification readers
/// can hold a few block-sized buffers. Both operations saturate on I/O
/// long before this many. Larger requests clamp to this value instead of
/// failing to spawn.
pub const MAX_JOBS: NonZeroUsize = NonZeroUsize::new(256).unwrap();

#[cfg(test)]
mod tests {
    // Keeps the workspace metadata (license and MSRV) pinned in CI.
    #[test]
    fn workspace_metadata_is_pinned() {
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
        assert_eq!(env!("CARGO_PKG_RUST_VERSION"), "1.85");
    }
}
