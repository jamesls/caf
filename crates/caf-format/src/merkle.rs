//! CAF v3 Merkle file identities.

use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use crate::hex::{self, ParseHexError};
use crate::{BLOCK_SIZE, HEADER_SIZE};

/// Domain separation prefix for CAF v3 leaf hashes.
pub const V3_LEAF_DOMAIN: &[u8] = b"caf:file:leaf:blake3:v3\0";

/// Domain separation prefix for CAF v3 internal-node hashes.
pub const V3_NODE_DOMAIN: &[u8] = b"caf:file:node:blake3:v3\0";

/// Domain separation prefix for CAF v3 root hashes.
pub const V3_ROOT_DOMAIN: &[u8] = b"caf:file:root:blake3:v3\0";

/// A full 32-byte hash in the CAF v3 Merkle tree.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MerkleHash([u8; Self::SIZE]);

impl MerkleHash {
    /// Merkle hash length in bytes.
    pub const SIZE: usize = 32;

    /// Creates a Merkle hash from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Consumes the hash and returns its raw bytes.
    #[must_use]
    pub const fn into_inner(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// Returns the 64-character lowercase hex form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl From<[u8; MerkleHash::SIZE]> for MerkleHash {
    fn from(bytes: [u8; MerkleHash::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<MerkleHash> for [u8; MerkleHash::SIZE] {
    fn from(hash: MerkleHash) -> Self {
        hash.into_inner()
    }
}

impl AsRef<[u8]> for MerkleHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for MerkleHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Debug for MerkleHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleHash({self})")
    }
}

/// A 20-byte CAF v3 file identity.
///
/// The value is the first 20 bytes of the domain-separated CAF v3 Merkle
/// root. Its byte and hex representations have the same shape as a v2
/// [`Digest`](crate::Digest), but no implicit conversion connects them; callers
/// must choose deliberately when crossing a version-agnostic storage boundary.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId([u8; Self::SIZE]);

impl FileId {
    /// File-ID length in bytes.
    pub const SIZE: usize = 20;

    /// The all-zero parent value used by chain roots.
    pub const ZERO: Self = Self([0; Self::SIZE]);

    /// Creates a file ID from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Parses a file ID from 40 hex characters, accepting either case.
    ///
    /// # Errors
    ///
    /// Returns [`ParseHexError`] if the input is not exactly 40 hex
    /// characters.
    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self, ParseHexError> {
        hex::decode(hex.as_ref()).map(Self)
    }

    /// Returns the raw file-ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Consumes the file ID and returns its raw bytes.
    #[must_use]
    pub const fn into_inner(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// Returns the 40-character lowercase hex form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns `true` for the all-zero root-parent value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

impl From<[u8; FileId::SIZE]> for FileId {
    fn from(bytes: [u8; FileId::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<FileId> for [u8; FileId::SIZE] {
    fn from(file_id: FileId) -> Self {
        file_id.into_inner()
    }
}

impl AsRef<[u8]> for FileId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for FileId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Debug for FileId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "FileId({self})")
    }
}

impl FromStr for FileId {
    type Err = ParseHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Hashes one physical CAF v3 file block as a Merkle leaf.
///
/// `bytes` includes the header when `index` is zero. The block index and
/// actual block length are bound into the hash before the block bytes.
///
/// # Panics
///
/// Panics on a platform where `usize` is wider than 64 bits if the input
/// length does not fit in `u64`.
#[must_use]
pub fn v3_leaf_hash(index: u64, bytes: impl AsRef<[u8]>) -> MerkleHash {
    let bytes = bytes.as_ref();
    let byte_len = u64::try_from(bytes.len()).expect("a CAF block length fits in u64");
    let mut hasher = blake3::Hasher::new();
    hasher.update(V3_LEAF_DOMAIN);
    hasher.update(&index.to_be_bytes());
    hasher.update(&byte_len.to_be_bytes());
    hasher.update(bytes);
    MerkleHash::from_bytes(*hasher.finalize().as_bytes())
}

/// Reduces ordered CAF v3 leaf hashes and returns the file ID.
///
/// `file_length` is the total physical file length, including the header.
/// The number of leaves must equal `ceil(file_length / BLOCK_SIZE)`.
///
/// # Panics
///
/// Panics if the file is shorter than a header or if the leaf count does
/// not match `file_length`.
#[must_use]
pub fn v3_file_id(file_length: u64, leaves: &[MerkleHash]) -> FileId {
    v3_file_id_from_leaves(file_length, leaves.to_vec())
}

/// Reduces an owned CAF v3 leaf array and returns the file ID.
///
/// This is the allocation-free reduction entry point for generation and
/// verification: parent hashes replace consumed children at the front of the
/// supplied vector. Use [`v3_file_id`] when the caller must retain its leaves.
///
/// # Panics
///
/// Panics if the file is shorter than a header or if the leaf count does not
/// match `file_length`.
#[must_use]
pub fn v3_file_id_from_leaves(file_length: u64, mut leaves: Vec<MerkleHash>) -> FileId {
    assert!(
        file_length >= HEADER_SIZE as u64,
        "CAF v3 files are at least {HEADER_SIZE} bytes",
    );
    let block_size = BLOCK_SIZE as u64;
    let expected_leaf_count = file_length.div_ceil(block_size);
    let actual_leaf_count = u64::try_from(leaves.len()).expect("a CAF leaf count fits in u64");
    assert_eq!(
        actual_leaf_count, expected_leaf_count,
        "CAF v3 leaf count does not match file length",
    );

    let mut level = 1_u64;
    while leaves.len() > 1 {
        let parent_count = leaves.len().div_ceil(2);
        for index in 0..parent_count {
            let child_start = 2 * index;
            let child_end = (child_start + 2).min(leaves.len());
            let parent = v3_node_hash(
                level,
                u64::try_from(index).expect("a CAF node index fits in u64"),
                &leaves[child_start..child_end],
            );
            leaves[index] = parent;
        }
        leaves.truncate(parent_count);
        level += 1;
    }

    let tree_root = leaves[0];
    v3_file_id_from_root(v3_root_hash(file_length, expected_leaf_count, tree_root))
}

/// Hashes the shape-bound CAF v3 Merkle root.
///
/// `file_length` is the total physical length including the header, and
/// `leaf_count` is the number of 1 MiB physical file blocks.
///
/// # Panics
///
/// Panics if the file is shorter than a header or `leaf_count` does not
/// equal `ceil(file_length / BLOCK_SIZE)`.
#[must_use]
pub fn v3_root_hash(file_length: u64, leaf_count: u64, tree_root: MerkleHash) -> MerkleHash {
    assert!(
        file_length >= HEADER_SIZE as u64,
        "CAF v3 files are at least {HEADER_SIZE} bytes",
    );
    let block_size = BLOCK_SIZE as u64;
    assert_eq!(
        leaf_count,
        file_length.div_ceil(block_size),
        "CAF v3 leaf count does not match file length",
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(V3_ROOT_DOMAIN);
    hasher.update(&block_size.to_be_bytes());
    hasher.update(&file_length.to_be_bytes());
    hasher.update(&leaf_count.to_be_bytes());
    hasher.update(tree_root.as_bytes());
    MerkleHash::from_bytes(*hasher.finalize().as_bytes())
}

/// Truncates a full CAF v3 root to its externally visible 20-byte file ID.
#[must_use]
pub fn v3_file_id_from_root(root: MerkleHash) -> FileId {
    let mut file_id = [0_u8; FileId::SIZE];
    file_id.copy_from_slice(&root.as_bytes()[..FileId::SIZE]);
    FileId::from_bytes(file_id)
}

/// Computes a CAF v3 file ID serially from complete physical file bytes.
///
/// This convenience function is intended for small inputs and reference
/// checks. Parallel generation and verification should compute leaves in
/// their block workers and call [`v3_file_id`] once all leaves are ready.
///
/// # Panics
///
/// Panics if `bytes` is shorter than a CAF header.
#[must_use]
pub fn v3_file_id_from_bytes(bytes: impl AsRef<[u8]>) -> FileId {
    let bytes = bytes.as_ref();
    let file_length = u64::try_from(bytes.len()).expect("a CAF file length fits in u64");
    let leaves = bytes
        .chunks(BLOCK_SIZE)
        .enumerate()
        .map(|(index, block)| {
            let index = u64::try_from(index).expect("a CAF leaf index fits in u64");
            v3_leaf_hash(index, block)
        })
        .collect::<Vec<_>>();
    v3_file_id_from_leaves(file_length, leaves)
}

/// Hashes an internal CAF v3 Merkle node.
///
/// `level` starts at one for parents of leaves. `index` is the node's
/// zero-based position within that level. A final odd node has one child;
/// every other node has two ordered children.
///
/// # Panics
///
/// Panics unless `children` contains exactly one or two hashes.
#[must_use]
pub fn v3_node_hash(level: u64, index: u64, children: &[MerkleHash]) -> MerkleHash {
    assert!(
        matches!(children.len(), 1 | 2),
        "a CAF v3 node has one or two children",
    );
    let child_count = u8::try_from(children.len()).expect("a node has one or two children");
    let mut hasher = blake3::Hasher::new();
    hasher.update(V3_NODE_DOMAIN);
    hasher.update(&level.to_be_bytes());
    hasher.update(&index.to_be_bytes());
    hasher.update(&[child_count]);
    for child in children {
        hasher.update(child.as_bytes());
    }
    MerkleHash::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        FileId, MerkleHash, v3_file_id, v3_file_id_from_bytes, v3_file_id_from_leaves, v3_leaf_hash,
    };
    use crate::{BLOCK_SIZE, HEADER_SIZE};

    fn reference_pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from((index * 31 + 7) % 256).unwrap())
            .collect()
    }

    #[test]
    fn leaf_matches_independent_reference_vector() {
        assert_eq!(
            v3_leaf_hash(7, b"caf v3 leaf vector").to_hex(),
            "a7440e28e234f3be5c5f12418dc0089b30bb7719b854ea8fcc1ab86245ed87de",
        );
    }

    #[test]
    fn file_ids_match_independent_tree_reference_vectors() {
        let cases = [
            (60, "195e85d76c4e7668aa640bc1b61d7800f72ad2c4"),
            (BLOCK_SIZE, "6a4a541a42f114adb7ed21a34aef38f865a57ea8"),
            (BLOCK_SIZE + 1, "db53fcc6dbabb2167f5b67d940f20d70197b1ac2"),
            (
                BLOCK_SIZE * 2 + 1,
                "30e86fd017874a87fa00b52f3c8ced181b1a430d",
            ),
            (
                BLOCK_SIZE * 4 + 17,
                "efce833c70f7d67875891b84cbfb599d332b8449",
            ),
        ];
        for (file_length, expected) in cases {
            assert_eq!(
                v3_file_id_from_bytes(reference_pattern(file_length)).to_hex(),
                expected,
                "file length {file_length}",
            );
        }
    }

    #[test]
    fn serial_computation_matches_explicit_leaves() {
        let bytes = vec![0x5a; BLOCK_SIZE * 2 + 17];
        let leaves = bytes
            .chunks(BLOCK_SIZE)
            .enumerate()
            .map(|(index, block)| v3_leaf_hash(index as u64, block))
            .collect::<Vec<_>>();

        assert_eq!(
            v3_file_id_from_bytes(&bytes),
            v3_file_id(u64::try_from(bytes.len()).unwrap(), &leaves),
        );
        assert_eq!(
            v3_file_id_from_bytes(&bytes),
            v3_file_id_from_leaves(u64::try_from(bytes.len()).unwrap(), leaves),
        );
    }

    #[test]
    fn leaf_index_and_length_are_bound() {
        assert_ne!(v3_leaf_hash(0, b"same"), v3_leaf_hash(1, b"same"));
        assert_ne!(v3_leaf_hash(0, b"same"), v3_leaf_hash(0, b"same\0"));
    }

    #[test]
    fn odd_leaf_is_not_promoted() {
        let three_blocks = vec![0x33; BLOCK_SIZE * 2 + 1];
        let two_blocks = &three_blocks[..BLOCK_SIZE * 2];
        assert_ne!(
            v3_file_id_from_bytes(&three_blocks),
            v3_file_id_from_bytes(two_blocks),
        );
    }

    #[test]
    fn typed_values_round_trip_through_bytes() {
        let hash = MerkleHash::from_bytes([0xa5; MerkleHash::SIZE]);
        assert_eq!(MerkleHash::from(hash.into_inner()), hash);

        let file_id = FileId::from_bytes([0x5a; FileId::SIZE]);
        assert_eq!(file_id.to_hex().parse::<FileId>().unwrap(), file_id);
        assert_eq!(FileId::from_bytes(file_id.into_inner()), file_id);
    }

    #[test]
    #[should_panic(expected = "CAF v3 files are at least 60 bytes")]
    fn serial_computation_rejects_truncated_files() {
        let _ = v3_file_id_from_bytes([0_u8; HEADER_SIZE - 1]);
    }
}
