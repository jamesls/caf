//! CAF version 2 file format: headers, digests, content, and path rules.
//!
//! This crate implements the CAF version 2 file format:
//!
//! - Typed 20-byte BLAKE2b-160 digests ([`Digest`], [`Hasher`]) and 16-byte
//!   content seeds ([`ContentSeed`]).
//! - The 60-byte header ([`Header`]): encoding, parsing, and validation,
//!   including the truncated SHA3-256 header checksum and the reserved
//!   field, plus a raw diagnostic view ([`RawHeader`]) for tools that
//!   display invalid headers.
//! - The deterministic SHAKE-128 content stream ([`ContentReader`],
//!   [`fill_block`], [`fill_block_prefix`]) with the [`CONTENT_DOMAIN`]
//!   domain, the shortened block 0, and 1 MiB later blocks,
//!   independently derivable per block index.
//! - Whole-file digest primitives and hash-to-path / path-to-hash
//!   conversion ([`hash_to_relpath`], [`parse_hash_from_path`]) for the
//!   `aa/bb/cc/<34-character basename>` layout.
//!
//! The crate has no terminal dependency and no knowledge of the CAF store
//! root; filesystem-facing callers live in `caf-store`. One-shot parsers
//! and encoders operate on byte slices and standard readers, and the golden
//! vectors under `tests/golden/` are the primary contract.
//!
//! # Examples
//!
//! Encode a header and regenerate the deterministic content it describes:
//!
//! ```
//! use std::io::Read;
//!
//! use caf_format::{ContentReader, ContentSeed, Digest, Header};
//!
//! let seed = ContentSeed::from_hex("85eac145eafbbe4867e1e46b53a26f88")?;
//! let header = Header::new(Digest::ZERO, seed, 1024)?;
//! let encoded = header.encode();
//! assert_eq!(encoded.len(), caf_format::HEADER_SIZE);
//!
//! let mut content = Vec::new();
//! ContentReader::new(seed)
//!     .take(header.content_length())
//!     .read_to_end(&mut content)?;
//! assert_eq!(content.len() as u64, header.content_length());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod content;
mod digest;
mod header;
mod hex;
mod path;
mod seed;

pub use content::{ContentReader, block_len, fill_block, fill_block_prefix};
pub use digest::{Digest, Hasher};
pub use header::{Header, HeaderError, RawHeader};
pub use hex::ParseHexError;
pub use path::{ParsePathError, hash_to_path, hash_to_relpath, parse_hash_from_path};
pub use seed::ContentSeed;

/// Total size of the version 2 file header in bytes.
///
/// Layout (`docs/file-format.md`):
///
/// | Offset | Size | Field |
/// | --- | --- | --- |
/// | 0 | 20 | Parent hash (BLAKE2b-160, zeros for roots) |
/// | 20 | 16 | Content seed |
/// | 36 | 8 | File length (big-endian `u64`, includes the header) |
/// | 44 | 8 | Header checksum (first 8 bytes of SHA3-256 over bytes 0-43) |
/// | 52 | 8 | Reserved (all zeros in v2) |
pub const HEADER_SIZE: usize = 60;

/// Size of content blocks for deterministic generation.
///
/// Block 0 is [`BLOCK_SIZE`] − [`HEADER_SIZE`] bytes so that later blocks
/// start at 1 MiB-aligned file offsets; see [`block_len`].
pub const BLOCK_SIZE: usize = 1024 * 1024;

/// Domain separation prefix for SHAKE-128 content generation.
///
/// Each content block is the SHAKE-128 output over
/// `CONTENT_DOMAIN || content_seed || block_index` (index as an 8-byte
/// big-endian integer), squeezed to the full block length.
pub const CONTENT_DOMAIN: &[u8] = b"caf:content:shake128:v2:";
