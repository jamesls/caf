//! Golden conformance tests against the independent CAF version 3 vectors.
//!
//! `tests/golden/vectors-v3.json` records complete format outputs from the
//! standalone Python reference implementation beside it. These tests require
//! the Rust implementation to reproduce every pinned byte and hash.

use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use caf_format::{
    BLOCK_SIZE, CONTENT_DOMAIN_V3, ContentReader, ContentSeed, FileId, Format, HEADER_SIZE, Header,
    MerkleHash, V3_LEAF_DOMAIN, V3_NODE_DOMAIN, V3_ROOT_DOMAIN, block_len, file_id_to_relpath,
    parse_file_id_from_path, v3_file_id, v3_file_id_from_bytes, v3_file_id_from_root, v3_leaf_hash,
    v3_node_hash, v3_root_hash,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    constants: Constants,
    file_vectors: Vec<FileVector>,
}

#[derive(Deserialize)]
struct Constants {
    header_size: usize,
    block_size: usize,
    block_0_size: usize,
    block_size_log_2: u32,
    format_marker_hex: String,
    file_id_scheme: u8,
    content_scheme: u8,
    flags: u8,
    descriptor_hex: String,
    content_domain: String,
    leaf_domain_hex: String,
    node_domain_hex: String,
    root_domain_hex: String,
    merkle_hash_size: usize,
    file_id_size: usize,
    parent_file_id_size: usize,
    content_seed_size: usize,
    root_parent_file_id: String,
}

#[derive(Deserialize)]
struct FileVector {
    name: String,
    parent_file_id: String,
    content_seed: String,
    file_length: u64,
    block_count: usize,
    header: String,
    content_slices: Vec<ContentSlice>,
    leaf_hashes: Vec<String>,
    reduction_levels: Vec<ReductionLevel>,
    tree_root: String,
    full_root: String,
    file_id: String,
    relative_path: String,
    file_hex: Option<String>,
}

#[derive(Deserialize)]
struct ContentSlice {
    file_offset: usize,
    hex: String,
}

#[derive(Deserialize)]
struct ReductionLevel {
    level: u64,
    hashes: Vec<String>,
}

static VECTORS: LazyLock<Golden> = LazyLock::new(|| {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/vectors-v3.json");
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
    serde_json::from_str(&json).expect("vectors-v3.json matches the schema")
});

impl FileVector {
    fn parent(&self) -> FileId {
        FileId::from_hex(&self.parent_file_id).expect("vector parent file ID")
    }

    fn seed(&self) -> ContentSeed {
        ContentSeed::from_hex(&self.content_seed).expect("vector content seed")
    }

    fn expected_file_id(&self) -> FileId {
        FileId::from_hex(&self.file_id).expect("vector file ID")
    }

    fn rebuild_file_bytes(&self) -> Vec<u8> {
        let header = Header::new_v3(self.parent(), self.seed(), self.file_length)
            .expect("vector lengths are legal");
        let capacity = usize::try_from(self.file_length).expect("vector fits in memory");
        let mut file_bytes = Vec::with_capacity(capacity);
        file_bytes.extend_from_slice(&header.encode());
        ContentReader::new_with_format(self.seed(), Format::V3)
            .take(header.content_length())
            .read_to_end(&mut file_bytes)
            .expect("infinite content stream");
        file_bytes
    }
}

fn reference_node_hash(level: u64, index: u64, children: &[MerkleHash]) -> MerkleHash {
    assert!(matches!(children.len(), 1 | 2), "one or two children");
    let child_count = u8::try_from(children.len()).expect("one or two children");
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

fn reference_reduction_levels(leaves: &[MerkleHash]) -> Vec<Vec<MerkleHash>> {
    let mut current = leaves.to_vec();
    let mut levels = Vec::new();
    let mut level = 1_u64;
    while current.len() > 1 {
        let next = current
            .chunks(2)
            .enumerate()
            .map(|(index, children)| {
                let index = u64::try_from(index).expect("node index fits in u64");
                reference_node_hash(level, index, children)
            })
            .collect::<Vec<_>>();
        levels.push(next.clone());
        current = next;
        level += 1;
    }
    levels
}

fn assert_public_reduction(name: &str, leaves: &[MerkleHash], levels: &[Vec<MerkleHash>]) {
    for (level_index, expected) in levels.iter().enumerate() {
        let level = u64::try_from(level_index + 1).expect("tree level fits in u64");
        let children = if level_index == 0 {
            leaves
        } else {
            &levels[level_index - 1]
        };
        let actual = children
            .chunks(2)
            .enumerate()
            .map(|(index, children)| {
                v3_node_hash(
                    level,
                    u64::try_from(index).expect("node index fits in u64"),
                    children,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, *expected, "vector {name} level {level}");
    }
}

fn reference_full_root(
    file_length: u64,
    block_count: usize,
    tree_root: MerkleHash,
) -> [u8; MerkleHash::SIZE] {
    let block_size = u64::try_from(BLOCK_SIZE).expect("block size fits in u64");
    let block_count = u64::try_from(block_count).expect("block count fits in u64");
    let mut hasher = blake3::Hasher::new();
    hasher.update(V3_ROOT_DOMAIN);
    hasher.update(&block_size.to_be_bytes());
    hasher.update(&file_length.to_be_bytes());
    hasher.update(&block_count.to_be_bytes());
    hasher.update(tree_root.as_bytes());
    *hasher.finalize().as_bytes()
}

#[test]
fn constants_match_frozen_values() {
    let frozen = &VECTORS.constants;
    assert_eq!(frozen.header_size, HEADER_SIZE);
    assert_eq!(frozen.block_size, BLOCK_SIZE);
    assert_eq!(frozen.block_0_size, block_len(0));
    assert_eq!(frozen.block_size_log_2, BLOCK_SIZE.trailing_zeros());
    assert_eq!(frozen.content_domain.as_bytes(), CONTENT_DOMAIN_V3);
    assert_eq!(
        hex::decode(frozen.leaf_domain_hex.as_bytes()).expect("leaf domain hex"),
        V3_LEAF_DOMAIN,
    );
    assert_eq!(
        hex::decode(frozen.node_domain_hex.as_bytes()).expect("node domain hex"),
        V3_NODE_DOMAIN,
    );
    assert_eq!(
        hex::decode(frozen.root_domain_hex.as_bytes()).expect("root domain hex"),
        V3_ROOT_DOMAIN,
    );
    assert_eq!(frozen.merkle_hash_size, MerkleHash::SIZE);
    assert_eq!(frozen.file_id_size, FileId::SIZE);
    assert_eq!(frozen.parent_file_id_size, FileId::SIZE);
    assert_eq!(frozen.content_seed_size, ContentSeed::SIZE);
    assert_eq!(frozen.root_parent_file_id, FileId::ZERO.to_hex());

    let file_length = u64::try_from(HEADER_SIZE).expect("header size fits in u64");
    let seed = ContentSeed::from_bytes([0_u8; ContentSeed::SIZE]);
    let encoded = Header::new_v3(FileId::ZERO, seed, file_length)
        .expect("header length is legal")
        .encode();
    let descriptor = &encoded[52..60];
    assert_eq!(hex::encode(descriptor), frozen.descriptor_hex);
    assert_eq!(hex::encode(&descriptor[..4]), frozen.format_marker_hex);
    assert_eq!(descriptor[4], frozen.file_id_scheme);
    assert_eq!(descriptor[5], frozen.content_scheme);
    assert_eq!(u32::from(descriptor[6]), frozen.block_size_log_2);
    assert_eq!(descriptor[7], frozen.flags);
}

#[test]
fn files_match_frozen_vectors_end_to_end() {
    for vector in &VECTORS.file_vectors {
        let name = &vector.name;
        let file_bytes = vector.rebuild_file_bytes();
        assert_eq!(
            u64::try_from(file_bytes.len()).expect("vector length fits in u64"),
            vector.file_length,
            "vector {name}",
        );

        let expected_header = hex::decode(&vector.header).expect("vector header hex");
        assert_eq!(
            &file_bytes[..HEADER_SIZE],
            expected_header,
            "vector {name} header",
        );
        let parsed =
            Header::parse(&file_bytes).unwrap_or_else(|err| panic!("vector {name}: {err}"));
        assert_eq!(parsed.format(), Format::V3, "vector {name}");
        assert_eq!(
            parsed.parent_file_id(),
            Some(vector.parent()),
            "vector {name}"
        );
        assert_eq!(parsed.content_seed(), vector.seed(), "vector {name}");
        assert_eq!(parsed.file_length(), vector.file_length, "vector {name}");
        assert_eq!(
            parsed.is_root(),
            vector.parent_file_id == VECTORS.constants.root_parent_file_id,
            "vector {name}",
        );

        for slice in &vector.content_slices {
            let expected = hex::decode(&slice.hex).expect("vector slice hex");
            let end = slice.file_offset + expected.len();
            assert_eq!(
                &file_bytes[slice.file_offset..end],
                expected,
                "vector {name} slice at {}",
                slice.file_offset,
            );
        }
        if let Some(expected) = &vector.file_hex {
            assert_eq!(hex::encode(&file_bytes), *expected, "vector {name}");
        }

        let leaves = file_bytes
            .chunks(BLOCK_SIZE)
            .enumerate()
            .map(|(index, block)| {
                let index = u64::try_from(index).expect("leaf index fits in u64");
                v3_leaf_hash(index, block)
            })
            .collect::<Vec<_>>();
        assert_eq!(leaves.len(), vector.block_count, "vector {name}");
        assert_eq!(leaves.len(), vector.leaf_hashes.len(), "vector {name}");
        for (actual, expected) in leaves.iter().zip(&vector.leaf_hashes) {
            assert_eq!(actual.to_hex(), expected.as_str(), "vector {name}");
        }

        let levels = reference_reduction_levels(&leaves);
        assert_eq!(levels.len(), vector.reduction_levels.len(), "vector {name}");
        for (level_index, (actual, expected)) in
            levels.iter().zip(&vector.reduction_levels).enumerate()
        {
            let level = u64::try_from(level_index + 1).expect("tree level fits in u64");
            assert_eq!(expected.level, level, "vector {name}");
            let actual = actual.iter().map(MerkleHash::to_hex).collect::<Vec<_>>();
            assert_eq!(actual, expected.hashes, "vector {name} level {level}");
        }
        assert_public_reduction(name, &leaves, &levels);

        let tree_root = levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or(leaves[0]);
        assert_eq!(tree_root.to_hex(), vector.tree_root, "vector {name}");
        let reference_root = reference_full_root(vector.file_length, leaves.len(), tree_root);
        assert_eq!(
            hex::encode(reference_root),
            vector.full_root,
            "vector {name}"
        );
        let full_root = v3_root_hash(
            vector.file_length,
            u64::try_from(leaves.len()).expect("leaf count fits in u64"),
            tree_root,
        );
        assert_eq!(full_root.as_bytes(), &reference_root, "vector {name}");

        let file_id = v3_file_id(vector.file_length, &leaves);
        assert_eq!(file_id, vector.expected_file_id(), "vector {name}");
        assert_eq!(v3_file_id_from_root(full_root), file_id, "vector {name}");
        assert_eq!(v3_file_id_from_bytes(&file_bytes), file_id, "vector {name}");

        let relative = file_id_to_relpath(file_id);
        assert_eq!(relative.to_string_lossy(), vector.relative_path);
        assert_eq!(
            parse_file_id_from_path(relative).expect("vector path"),
            file_id,
            "vector {name}",
        );
    }
}
