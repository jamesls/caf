//! Property tests for headers, paths, hex parsing, and content chunking.
//!
//! Generated data is bounded so failures reproduce quickly: content cases
//! stay within a few blocks and use a reduced case count.

use std::io::Read;
use std::path::PathBuf;
use std::sync::LazyLock;

use caf_format::{
    ContentReader, ContentSeed, Digest, HEADER_SIZE, Header, block_len, fill_block,
    fill_block_prefix, hash_to_relpath, parse_hash_from_path,
};
use proptest::prelude::*;

fn arb_digest() -> impl Strategy<Value = Digest> {
    any::<[u8; Digest::SIZE]>().prop_map(Digest::from_bytes)
}

fn arb_seed() -> impl Strategy<Value = ContentSeed> {
    any::<[u8; ContentSeed::SIZE]>().prop_map(ContentSeed::from_bytes)
}

fn arb_header() -> impl Strategy<Value = Header> {
    (arb_digest(), arb_seed(), HEADER_SIZE as u64..=u64::MAX).prop_map(
        |(parent, seed, file_length)| {
            Header::new(parent, seed, file_length).expect("length is at least the header size")
        },
    )
}

proptest! {
    #[test]
    fn header_encode_parse_round_trips(header in arb_header()) {
        let parsed = Header::parse(header.encode()).expect("valid header");
        prop_assert_eq!(parsed, header);
    }

    #[test]
    fn header_parse_rejects_any_single_byte_change(
        header in arb_header(),
        index in 0..HEADER_SIZE,
        flip in 1_u8..=255,
    ) {
        // Changing bytes 0-43 invalidates the stored checksum, and the
        // reserved bytes must be zero.
        let mut bytes = header.encode();
        bytes[index] ^= flip;
        prop_assert!(Header::parse(bytes).is_err());
    }

    #[test]
    fn header_parse_rejects_truncated_input(
        header in arb_header(),
        len in 0..HEADER_SIZE,
    ) {
        let err = Header::parse(&header.encode()[..len]).unwrap_err();
        prop_assert!(err.is_truncated());
    }

    #[test]
    fn header_new_rejects_short_file_lengths(
        parent in arb_digest(),
        seed in arb_seed(),
        file_length in 0..HEADER_SIZE as u64,
    ) {
        let err = Header::new(parent, seed, file_length).unwrap_err();
        prop_assert!(err.is_length_too_small());
    }

    #[test]
    fn digest_hex_round_trips(digest in arb_digest()) {
        let lower = Digest::from_hex(digest.to_hex()).expect("valid hex");
        prop_assert_eq!(lower, digest);
        let upper = Digest::from_hex(digest.to_hex().to_uppercase())
            .expect("valid hex");
        prop_assert_eq!(upper, digest);
    }

    #[test]
    fn seed_hex_round_trips(seed in arb_seed()) {
        let parsed = ContentSeed::from_hex(seed.to_hex()).expect("valid hex");
        prop_assert_eq!(parsed, seed);
    }

    #[test]
    fn digest_path_round_trips(digest in arb_digest()) {
        let relpath = hash_to_relpath(digest);
        prop_assert_eq!(parse_hash_from_path(&relpath).ok(), Some(digest));

        // Paths are case-insensitive when read.
        let upper = PathBuf::from(
            relpath.to_str().expect("hex paths are UTF-8").to_uppercase(),
        );
        prop_assert_eq!(parse_hash_from_path(&upper).ok(), Some(digest));
    }

    #[test]
    fn parse_hash_never_panics_on_arbitrary_paths(path in any::<PathBuf>()) {
        let _unused = parse_hash_from_path(&path);
    }

    #[test]
    fn digest_ordering_matches_hex_ordering(
        a in arb_digest(),
        b in arb_digest(),
    ) {
        prop_assert_eq!(a.cmp(&b), a.to_hex().cmp(&b.to_hex()));
    }
}

/// Fixed seed for the (expensive) chunk-invariance reference stream.
fn reference_seed() -> ContentSeed {
    ContentSeed::from_bytes(*b"chunk-invariance")
}

/// Reference content: blocks 0 and 1 generated block-at-a-time, computed
/// once per process.
static REFERENCE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut bytes = vec![0_u8; block_len(0) + block_len(1)];
    let (block0, block1) = bytes.split_at_mut(block_len(0));
    fill_block(reference_seed(), 0, block0);
    fill_block(reference_seed(), 1, block1);
    bytes
});

proptest! {
    // Each case streams up to ~2 MiB of SHAKE output; keep the case count
    // low so the suite stays fast while still varying the chunk pattern.
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn content_is_invariant_under_read_chunk_sizes(
        chunk_sizes in prop::collection::vec(1_usize..=70_000, 1..64),
    ) {
        let mut reader = ContentReader::new(reference_seed());
        let mut streamed = Vec::new();
        for chunk_size in chunk_sizes {
            if streamed.len() + chunk_size > REFERENCE.len() {
                break;
            }
            let start = streamed.len();
            streamed.resize(start + chunk_size, 0);
            reader.read_exact(&mut streamed[start..]).expect("infinite");
        }
        prop_assert_eq!(&*streamed, &REFERENCE[..streamed.len()]);
    }

    /// A file whose length is not block aligned ends in a partial block,
    /// which the parallel writer squeezes with `fill_block_prefix`. At
    /// every length that has to be the same bytes the sequential reader
    /// puts at those file offsets.
    #[test]
    fn block_prefixes_match_the_streamed_content(
        index in 0_u64..2,
        len in 0_usize..=block_len(1),
    ) {
        let len = len.min(block_len(index));
        let start = if index == 0 { 0 } else { block_len(0) };
        let mut streamed = vec![0_u8; start + len];
        ContentReader::new(reference_seed())
            .read_exact(&mut streamed)
            .expect("infinite");

        let mut prefix = vec![0_u8; len];
        fill_block_prefix(reference_seed(), index, &mut prefix);
        prop_assert_eq!(&*prefix, &streamed[start..]);
    }

    #[test]
    fn two_readers_agree_for_any_seed(seed in arb_seed()) {
        // Cross-seed determinism on a cheap length within block 0.
        let mut a = vec![0_u8; 8192];
        ContentReader::new(seed).read_exact(&mut a).expect("infinite");

        let mut b = Vec::new();
        ContentReader::new(seed)
            .take(8192)
            .read_to_end(&mut b)
            .expect("infinite");
        prop_assert_eq!(a, b);
    }
}
