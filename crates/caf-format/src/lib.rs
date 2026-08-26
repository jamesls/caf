//! CAF version 2 and 3 formats: headers, identities, content, and paths.
//!
//! This crate implements both supported CAF file formats:
//!
//! - Typed 20-byte v2 BLAKE2b-160 digests ([`Digest`], [`Hasher`]), typed
//!   metadata aggregates ([`MetadataDigest`], [`MetadataHasher`]), and
//!   16-byte content seeds ([`ContentSeed`]).
//! - Typed CAF v3 Merkle hashes and file IDs ([`MerkleHash`], [`FileId`]),
//!   with independently computable BLAKE3 leaves and deterministic reduction.
//! - The shared 60-byte header ([`Header`]): version dispatch, encoding,
//!   parsing, and validation, plus a raw diagnostic view ([`RawHeader`]).
//! - The deterministic SHAKE-128 content stream ([`ContentReader`],
//!   [`ContentReader::new_with_offset`], [`fill_block`], [`fill_block_prefix`])
//!   with version-specific domains, a shortened block 0, and independently
//!   derivable 1 MiB physical blocks.
//! - Version-specific file identity primitives and typed path conversion for
//!   the shared `aa/bb/cc/<34-character basename>` layout.
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
mod merkle;
mod metadata_digest;
mod path;
mod seed;

pub use content::{
    ContentReader, block_len, fill_block, fill_block_prefix, fill_block_prefix_with_format,
    fill_block_with_format,
};
pub use digest::{Digest, Hasher};
pub use header::{Format, Header, HeaderError, RawHeader};
pub use hex::ParseHexError;
pub use merkle::{
    FileId, MerkleHash, V3_LEAF_DOMAIN, V3_NODE_DOMAIN, V3_ROOT_DOMAIN, v3_file_id,
    v3_file_id_from_bytes, v3_file_id_from_leaves, v3_file_id_from_root, v3_leaf_hash,
    v3_node_hash, v3_root_hash,
};
pub use metadata_digest::{MetadataDigest, MetadataHasher};
pub use path::{
    ParsePathError, file_id_to_path, file_id_to_relpath, hash_to_path, hash_to_relpath,
    parse_file_id_from_path, parse_hash_from_path,
};
pub use seed::ContentSeed;

/// Total size of a CAF v2 or v3 file header in bytes.
///
/// Layout (`docs/file-format.md`):
///
/// | Offset | Size | Field |
/// | --- | --- | --- |
/// | 0 | 20 | Parent file identity (zeros for roots) |
/// | 20 | 16 | Content seed |
/// | 36 | 8 | File length (big-endian `u64`, includes the header) |
/// | 44 | 8 | Version-specific truncated SHA3-256 header checksum |
/// | 52 | 8 | v2 zeros or the strict v3 format descriptor |
pub const HEADER_SIZE: usize = 60;

/// Size of content blocks for deterministic generation.
///
/// Block 0 is [`BLOCK_SIZE`] − [`HEADER_SIZE`] bytes so that later blocks
/// start at 1 MiB-aligned file offsets; see [`block_len`].
pub const BLOCK_SIZE: usize = 1024 * 1024;

/// Version 2 domain separation prefix for SHAKE-128 content generation.
///
/// Each content block is the SHAKE-128 output over
/// `CONTENT_DOMAIN || content_seed || block_index` (index as an 8-byte
/// big-endian integer), squeezed to the full block length.
pub const CONTENT_DOMAIN_V2: &[u8] = b"caf:content:shake128:v2:";

/// Version 3 domain separation prefix for SHAKE-128 content generation.
pub const CONTENT_DOMAIN_V3: &[u8] = b"caf:content:shake128:v3:";

/// Version 2 content domain retained for source compatibility.
pub const CONTENT_DOMAIN: &[u8] = CONTENT_DOMAIN_V2;
