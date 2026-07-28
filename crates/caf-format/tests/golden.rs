//! Golden conformance tests against the version 2 vectors.
//!
//! `tests/golden/vectors.json` (repository root) is the primary contract
//! for this crate: Rust must reproduce every byte, digest, and path the
//! Python implementation used to create the fixture. The same file
//! pins the Python side through `tests/test_golden_vectors.py`.

use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use caf_format::{
    BLOCK_SIZE, CONTENT_DOMAIN, ContentReader, ContentSeed, Digest, HEADER_SIZE, Hasher, Header,
    block_len, hash_to_relpath, parse_hash_from_path,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    constants: Constants,
    file_vectors: Vec<FileVector>,
    metadata_vectors: Vec<MetadataVector>,
}

#[derive(Deserialize)]
struct Constants {
    header_size: usize,
    block_size: usize,
    block_0_size: usize,
    content_domain: String,
    blake2b_digest_size: usize,
    parent_hash_size: usize,
    content_seed_size: usize,
    root_parent_hash: String,
}

#[derive(Deserialize)]
struct FileVector {
    name: String,
    parent_hash: String,
    content_seed: String,
    file_length: u64,
    header: String,
    file_blake2b_160: String,
    relative_path: String,
    content_slices: Vec<ContentSlice>,
    file_hex: Option<String>,
}

#[derive(Deserialize)]
struct ContentSlice {
    file_offset: usize,
    hex: String,
}

#[derive(Deserialize)]
struct MetadataVector {
    root_names: Vec<String>,
    all_file_contents: String,
}

static VECTORS: LazyLock<Golden> = LazyLock::new(|| {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/vectors.json");
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
    serde_json::from_str(&json).expect("vectors.json matches the schema")
});

impl FileVector {
    fn parent(&self) -> Digest {
        Digest::from_hex(&self.parent_hash).expect("vector parent hash")
    }

    fn seed(&self) -> ContentSeed {
        ContentSeed::from_hex(&self.content_seed).expect("vector seed")
    }

    fn digest(&self) -> Digest {
        Digest::from_hex(&self.file_blake2b_160).expect("vector digest")
    }

    /// Rebuilds the complete file, reading content in a prime-sized chunk
    /// (never block aligned) so chunk invariance is exercised on the way.
    fn rebuild_file_bytes(&self) -> Vec<u8> {
        let header = hex::decode(&self.header).expect("vector header hex");
        let mut file_bytes = header;
        let mut reader = ContentReader::new(self.seed());
        let mut remaining =
            usize::try_from(self.file_length).expect("vector fits in memory") - HEADER_SIZE;
        let mut chunk = vec![0_u8; 65_521];
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            reader
                .read_exact(&mut chunk[..take])
                .expect("infinite stream");
            file_bytes.extend_from_slice(&chunk[..take]);
            remaining -= take;
        }
        file_bytes
    }
}

#[test]
fn constants_match_frozen_values() {
    let frozen = &VECTORS.constants;
    assert_eq!(frozen.header_size, HEADER_SIZE);
    assert_eq!(frozen.block_size, BLOCK_SIZE);
    assert_eq!(frozen.block_0_size, block_len(0));
    assert_eq!(frozen.content_domain.as_bytes(), CONTENT_DOMAIN);
    assert_eq!(frozen.blake2b_digest_size, Digest::SIZE);
    assert_eq!(frozen.parent_hash_size, Digest::SIZE);
    assert_eq!(frozen.content_seed_size, ContentSeed::SIZE);
    assert_eq!(frozen.root_parent_hash, Digest::ZERO.to_hex());
}

#[test]
fn header_encoding_matches_vectors() {
    for vector in &VECTORS.file_vectors {
        let header = Header::new(vector.parent(), vector.seed(), vector.file_length)
            .expect("vector lengths are legal");
        assert_eq!(
            hex::encode(header.encode()),
            vector.header,
            "vector {}",
            vector.name,
        );
    }
}

#[test]
fn header_parsing_round_trips_vectors() {
    for vector in &VECTORS.file_vectors {
        let bytes = hex::decode(&vector.header).expect("vector header hex");
        let parsed =
            Header::parse(&bytes).unwrap_or_else(|err| panic!("vector {}: {err}", vector.name));
        assert_eq!(parsed.parent(), vector.parent(), "vector {}", vector.name);
        assert_eq!(parsed.content_seed(), vector.seed());
        assert_eq!(parsed.file_length(), vector.file_length);
        assert_eq!(
            parsed.is_root(),
            vector.parent_hash == VECTORS.constants.root_parent_hash,
        );
    }
}

#[test]
fn content_and_digest_match_vectors() {
    for vector in &VECTORS.file_vectors {
        let name = &vector.name;
        let file_bytes = vector.rebuild_file_bytes();
        assert_eq!(file_bytes.len() as u64, vector.file_length, "vector {name}");

        assert_eq!(
            Digest::compute(&file_bytes),
            vector.digest(),
            "vector {name}",
        );

        for slice in &vector.content_slices {
            let expected = hex::decode(&slice.hex).expect("vector slice hex");
            let actual = &file_bytes[slice.file_offset..slice.file_offset + expected.len()];
            assert_eq!(
                actual, expected,
                "vector {name} slice at {}",
                slice.file_offset,
            );
        }

        if let Some(file_hex) = &vector.file_hex {
            assert_eq!(&hex::encode(&file_bytes), file_hex, "vector {name}");
        }
    }
}

#[test]
fn relative_paths_match_vectors() {
    for vector in &VECTORS.file_vectors {
        let relpath = hash_to_relpath(vector.digest());
        let joined: Vec<String> = relpath
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            joined.join("/"),
            vector.relative_path,
            "vector {}",
            vector.name,
        );
        assert_eq!(
            parse_hash_from_path(&relpath).unwrap(),
            vector.digest(),
            "vector {}",
            vector.name,
        );
    }
}

#[test]
fn metadata_all_digests_match_vectors() {
    // `.metadata/all` is BLAKE2b-160 over the sorted chain-tip filenames
    // concatenated as ASCII; the store crate builds it from this hasher.
    for vector in &VECTORS.metadata_vectors {
        let mut names = vector.root_names.clone();
        names.sort_unstable();
        let mut hasher = Hasher::new();
        for name in &names {
            hasher.update(name.as_bytes());
        }
        assert_eq!(hasher.finalize().to_hex(), vector.all_file_contents);
    }
}
