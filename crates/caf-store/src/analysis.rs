//! Corruption analysis: regeneration, pattern classification, merging.
//!
//! When a file's whole-file digest does not match its path, the verifier
//! regenerates the expected content from the header's seed and compares
//! it in `analysis_chunk_size` chunks. Differing chunks become
//! [`CorruptionRegion`]s, contiguous regions with an identical pattern
//! merge, and size deltas append `truncated` / `extra-bytes` regions.
//! The clean verification path never runs any of this: expected content
//! is regenerated only after a digest or size failure.

use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use caf_format::{ContentReader, ContentSeed, Digest, HEADER_SIZE, Header};

/// A chunk is `sparse` when fewer than this fraction of its bytes differ.
const SPARSE_RATE: f64 = 0.1;
/// Common I/O boundaries checked for the `aligned` pattern, in order.
const ALIGNMENT_BOUNDARIES: [usize; 4] = [512, 1024, 4096, 8192];
/// Only the first this-many differing positions are alignment-checked.
const ALIGNMENT_POSITIONS: usize = 5;

/// The kind of corruption observed in one region of a file.
///
/// Classes and their triggers are evaluated in
/// this order per analysis chunk: [`ZeroFilled`], [`RepeatedByte`],
/// [`Sparse`], [`Aligned`], then [`Random`]. [`Truncated`] and
/// [`ExtraBytes`] come from the difference between the actual file size
/// and the header's file length, not from chunk comparison. Positions
/// used for the sparse rate and alignment check are relative to the
/// analysis chunk, not the file.
///
/// Every payload here has a documented domain (a rate in `0.0..=1.0`, a
/// boundary from a fixed set, a nonzero repeated byte), so the analyzer
/// is the only constructor: the payload-carrying variants are
/// `#[non_exhaustive]` and cannot be built outside this crate. Reading
/// them through a `match` works as usual, with a trailing `..` in the
/// pattern and a wildcard arm for classes added later.
///
/// [`ZeroFilled`]: CorruptionPattern::ZeroFilled
/// [`RepeatedByte`]: CorruptionPattern::RepeatedByte
/// [`Sparse`]: CorruptionPattern::Sparse
/// [`Aligned`]: CorruptionPattern::Aligned
/// [`Random`]: CorruptionPattern::Random
/// [`Truncated`]: CorruptionPattern::Truncated
/// [`ExtraBytes`]: CorruptionPattern::ExtraBytes
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum CorruptionPattern {
    /// All bytes in the region are `0x00`.
    ZeroFilled,
    /// All bytes in the region are the same nonzero value.
    #[non_exhaustive]
    RepeatedByte {
        /// The repeated byte value.
        value: u8,
    },
    /// Less than 10 percent of the region's bytes are corrupted.
    #[non_exhaustive]
    Sparse {
        /// Number of differing bytes in the first analysis chunk of the
        /// region.
        corrupted_count: u64,
    },
    /// Corruption aligns to a common I/O boundary within the chunk.
    #[non_exhaustive]
    Aligned {
        /// The matched boundary in bytes (512, 1024, 4096, or 8192).
        boundary: u64,
    },
    /// Unstructured corruption with a high corruption rate.
    #[non_exhaustive]
    Random {
        /// Fraction of the chunk's bytes that differ, in `0.0..=1.0`.
        corruption_rate: f64,
    },
    /// The file is shorter than the header's file length.
    #[non_exhaustive]
    Truncated {
        /// Bytes missing from the end of the file.
        missing_bytes: u64,
    },
    /// The file has data beyond the header's file length.
    #[non_exhaustive]
    ExtraBytes {
        /// Unexpected bytes past the expected end of the file.
        extra_count: u64,
    },
}

impl CorruptionPattern {
    /// Returns the kebab-case class name for this pattern.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ZeroFilled => "zero-filled",
            Self::RepeatedByte { .. } => "repeated-byte",
            Self::Sparse { .. } => "sparse",
            Self::Aligned { .. } => "aligned",
            Self::Random { .. } => "random",
            Self::Truncated { .. } => "truncated",
            Self::ExtraBytes { .. } => "extra-bytes",
        }
    }
}

/// One corrupted byte range of a file.
///
/// Offsets are absolute file offsets. Region granularity is the
/// verifier's analysis chunk size; contiguous chunks with an identical
/// pattern merge into one region (the pattern of the first chunk is
/// kept).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CorruptionRegion {
    offset: u64,
    size: u64,
    pattern: CorruptionPattern,
}

impl CorruptionRegion {
    fn new(offset: u64, size: u64, pattern: CorruptionPattern) -> Self {
        Self {
            offset,
            size,
            pattern,
        }
    }

    /// Returns the file offset where the region starts.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the region length in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the file offset just past the region.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset + self.size
    }

    /// Returns the corruption pattern of the region.
    #[must_use]
    pub fn pattern(&self) -> CorruptionPattern {
        self.pattern
    }
}

/// How a digest mismatch is classified overall.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CorruptionClass {
    /// The file's bytes differ from the regenerated expected content.
    Content,
    /// The content is valid but stored at a path for a different digest
    /// (zero corrupted bytes and matching sizes).
    PathMismatch,
}

/// Detailed report for one file whose digest does not match its path.
///
/// Produced only for files with a valid header, after the whole-file
/// digest check fails.
/// The derived values (`total_corrupted_bytes`, `corruption_percentage`,
/// `class`) are computed from the stored fields.
#[derive(Clone, Debug, PartialEq)]
pub struct CorruptionReport {
    pub(crate) path: PathBuf,
    pub(crate) expected: Digest,
    pub(crate) actual: Digest,
    pub(crate) actual_size: u64,
    pub(crate) expected_size: u64,
    pub(crate) content_seed: ContentSeed,
    pub(crate) regions: Vec<CorruptionRegion>,
}

impl CorruptionReport {
    /// Returns the path of the corrupted file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the digest the path claims (the expected BLAKE2b-160).
    #[must_use]
    pub fn expected_digest(&self) -> Digest {
        self.expected
    }

    /// Returns the digest actually computed over the file.
    #[must_use]
    pub fn actual_digest(&self) -> Digest {
        self.actual
    }

    /// Returns the file's size on disk in bytes.
    #[must_use]
    pub fn actual_size(&self) -> u64 {
        self.actual_size
    }

    /// Returns the file length recorded in the header.
    #[must_use]
    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// Returns the content seed from the header.
    #[must_use]
    pub fn content_seed(&self) -> ContentSeed {
        self.content_seed
    }

    /// Returns the corrupted regions in ascending file-offset order.
    #[must_use]
    pub fn regions(&self) -> &[CorruptionRegion] {
        &self.regions
    }

    /// Returns the sum of all region sizes in bytes.
    #[must_use]
    pub fn total_corrupted_bytes(&self) -> u64 {
        self.regions.iter().map(CorruptionRegion::size).sum()
    }

    /// Returns corrupted bytes as a percentage of the analysis size
    /// (the larger of the actual and expected file sizes).
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "matches Python float division; exact above 2^53 is not required"
    )]
    pub fn corruption_percentage(&self) -> f64 {
        let analysis_size = self.actual_size.max(self.expected_size);
        if analysis_size == 0 {
            return 0.0;
        }
        (self.total_corrupted_bytes() as f64 / analysis_size as f64) * 100.0
    }

    /// Classifies the mismatch: [`CorruptionClass::PathMismatch`] when no
    /// byte differs and the sizes agree, otherwise
    /// [`CorruptionClass::Content`].
    #[must_use]
    pub fn class(&self) -> CorruptionClass {
        if self.total_corrupted_bytes() == 0 && self.actual_size == self.expected_size {
            CorruptionClass::PathMismatch
        } else {
            CorruptionClass::Content
        }
    }
}

/// Compares `source` against the regenerated content stream and returns
/// the corrupted regions.
///
/// `source` must be positioned anywhere in the file described by
/// `header`; the comparison starts at the first content byte. Content is
/// compared up to the smaller of `actual_size` and the header's file
/// length; a size delta appends a `truncated` or `extra-bytes` region.
pub(crate) fn analyze(
    mut source: impl Read + Seek,
    header: &Header,
    actual_size: u64,
    chunk_size: NonZeroUsize,
) -> io::Result<Vec<CorruptionRegion>> {
    let expected_size = header.file_length();
    let compare_end = actual_size.min(expected_size);
    let mut remaining = compare_end.saturating_sub(HEADER_SIZE as u64);
    // No chunk can exceed the bytes left to compare, so the buffers stay
    // bounded by the file rather than by the requested chunk size.
    let chunk_size = usize::try_from(remaining)
        .unwrap_or(usize::MAX)
        .min(chunk_size.get());

    source.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
    let mut expected_stream = ContentReader::new(header.content_seed());
    let mut actual_chunk = vec![0_u8; chunk_size];
    let mut expected_chunk = vec![0_u8; chunk_size];
    let mut regions: Vec<CorruptionRegion> = Vec::new();
    let mut offset = HEADER_SIZE as u64;

    while remaining > 0 {
        let want = usize::try_from(remaining.min(chunk_size as u64))
            .expect("chunk length is bounded by chunk_size");
        let got = read_full(&mut source, &mut actual_chunk[..want])?;
        if got == 0 {
            break;
        }
        let actual = &actual_chunk[..got];
        let expected = &mut expected_chunk[..got];
        expected_stream
            .read_exact(expected)
            .expect("the content stream is infinite and never fails");

        if actual != expected {
            let pattern = classify_chunk(actual, expected);
            push_region(
                &mut regions,
                CorruptionRegion::new(offset, got as u64, pattern),
            );
        }

        offset += got as u64;
        remaining -= got as u64;
    }

    if actual_size < expected_size {
        let missing_bytes = expected_size - actual_size;
        push_region(
            &mut regions,
            CorruptionRegion::new(
                actual_size,
                missing_bytes,
                CorruptionPattern::Truncated { missing_bytes },
            ),
        );
    } else if actual_size > expected_size {
        let extra_count = actual_size - expected_size;
        push_region(
            &mut regions,
            CorruptionRegion::new(
                expected_size,
                extra_count,
                CorruptionPattern::ExtraBytes { extra_count },
            ),
        );
    }

    Ok(regions)
}

/// Appends `region`, merging it into the previous region when they are
/// contiguous and carry an identical pattern. The earlier pattern is kept.
fn push_region(regions: &mut Vec<CorruptionRegion>, region: CorruptionRegion) {
    if let Some(last) = regions.last_mut() {
        if last.end() == region.offset && last.pattern == region.pattern {
            last.size += region.size;
            return;
        }
    }
    regions.push(region);
}

/// Classifies one differing analysis chunk.
///
/// Positions are chunk-relative: the sparse rate and alignment check
/// both use indices within the chunk.
#[expect(
    clippy::cast_precision_loss,
    reason = "matches Python float division; chunks are far below 2^53 bytes"
)]
fn classify_chunk(actual: &[u8], expected: &[u8]) -> CorruptionPattern {
    debug_assert_eq!(
        actual.len(),
        expected.len(),
        "the regenerated chunk always matches the read length"
    );

    if actual.iter().all(|&byte| byte == 0) {
        return CorruptionPattern::ZeroFilled;
    }
    if let Some((&first, rest)) = actual.split_first() {
        if rest.iter().all(|&byte| byte == first) {
            return CorruptionPattern::RepeatedByte { value: first };
        }
    }

    // Only the count and the first few positions are ever used, so the
    // differing positions are counted in place instead of collected.
    let mut corrupted_count = 0_usize;
    let mut leading = [0_usize; ALIGNMENT_POSITIONS];
    let mut leading_count = 0_usize;
    for (position, (a, e)) in actual.iter().zip(expected).enumerate() {
        if a != e {
            if leading_count < ALIGNMENT_POSITIONS {
                leading[leading_count] = position;
                leading_count += 1;
            }
            corrupted_count += 1;
        }
    }
    let corruption_rate = corrupted_count as f64 / actual.len() as f64;

    if corruption_rate < SPARSE_RATE {
        return CorruptionPattern::Sparse {
            corrupted_count: corrupted_count as u64,
        };
    }
    if let Some(boundary) = check_alignment(&leading[..leading_count]) {
        return CorruptionPattern::Aligned {
            boundary: boundary as u64,
        };
    }
    CorruptionPattern::Random { corruption_rate }
}

/// Returns the first common boundary that `leading` — the first
/// [`ALIGNMENT_POSITIONS`] differing positions of a chunk — all align
/// to, if any.
fn check_alignment(leading: &[usize]) -> Option<usize> {
    ALIGNMENT_BOUNDARIES
        .into_iter()
        .find(|boundary| leading.iter().all(|position| position % boundary == 0))
}

/// Reads until `buf` is full or the source reaches end-of-file, returning
/// the number of bytes read. Chunk comparison depends on filling the
/// buffer across short reads.
pub(crate) fn read_full(mut source: impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _, Write as _};
    use std::num::NonZeroUsize;

    use caf_format::{ContentReader, ContentSeed, Digest, HEADER_SIZE, Header};

    use super::{
        CorruptionClass, CorruptionPattern, CorruptionRegion, CorruptionReport, analyze,
        check_alignment, classify_chunk, push_region,
    };

    fn seed() -> ContentSeed {
        ContentSeed::from_bytes(*b"analysis-fixture")
    }

    /// Builds an in-memory file of `file_length` total bytes with the
    /// correct header and deterministic content.
    fn clean_file(file_length: u64) -> Vec<u8> {
        let header = Header::new(Digest::ZERO, seed(), file_length).unwrap();
        let mut bytes = header.encode().to_vec();
        let content_length =
            usize::try_from(file_length).expect("test sizes are small") - HEADER_SIZE;
        let mut content = vec![0_u8; content_length];
        ContentReader::new(seed()).read_exact(&mut content).unwrap();
        bytes.write_all(&content).unwrap();
        bytes
    }

    fn chunk(size: usize) -> NonZeroUsize {
        NonZeroUsize::new(size).expect("the tests use positive chunk sizes")
    }

    fn regions_of(bytes: &[u8], chunk_size: usize) -> Vec<CorruptionRegion> {
        let header = Header::parse(bytes).unwrap();
        let mut cursor = Cursor::new(bytes);
        analyze(&mut cursor, &header, bytes.len() as u64, chunk(chunk_size)).unwrap()
    }

    #[test]
    fn clean_content_yields_no_regions() {
        let bytes = clean_file(4096);
        assert_eq!(regions_of(&bytes, 256), Vec::new());
    }

    #[test]
    fn zeroed_chunks_merge_into_one_region() {
        // Zero file offsets 1084..1852: exactly three 256-byte analysis
        // chunks (chunks start at 60 + 256k), which must merge.
        let mut bytes = clean_file(4096);
        bytes[1084..1852].fill(0);
        let regions = regions_of(&bytes, 256);
        assert_eq!(regions.len(), 1, "{regions:?}");
        assert_eq!(regions[0].offset(), 1084);
        assert_eq!(regions[0].size(), 768);
        assert_eq!(regions[0].end(), 1852);
        assert_eq!(regions[0].pattern(), CorruptionPattern::ZeroFilled);
        assert_eq!(regions[0].pattern().name(), "zero-filled");
    }

    #[test]
    fn truncation_appends_a_truncated_region() {
        let bytes = clean_file(4096);
        let truncated = &bytes[..4096 - 512];
        let header = Header::parse(truncated).unwrap();
        let mut cursor = Cursor::new(truncated);
        let regions = analyze(&mut cursor, &header, truncated.len() as u64, chunk(256)).unwrap();
        assert_eq!(
            regions,
            vec![CorruptionRegion::new(
                3584,
                512,
                CorruptionPattern::Truncated { missing_bytes: 512 },
            )]
        );
    }

    #[test]
    fn extra_bytes_append_an_extra_bytes_region() {
        let mut bytes = clean_file(1024);
        bytes.extend_from_slice(&[0xAB; 100]);
        let header = Header::parse(&bytes).unwrap();
        let mut cursor = Cursor::new(&bytes);
        let regions = analyze(&mut cursor, &header, bytes.len() as u64, chunk(4096)).unwrap();
        assert_eq!(
            regions,
            vec![CorruptionRegion::new(
                1024,
                100,
                CorruptionPattern::ExtraBytes { extra_count: 100 },
            )]
        );
    }

    #[test]
    fn analysis_is_invariant_under_chunk_size_for_clean_content() {
        let bytes = clean_file(8192);
        for chunk_size in [1, 7, 256, 4096, 65536] {
            assert_eq!(regions_of(&bytes, chunk_size), Vec::new(), "{chunk_size}");
        }
    }

    #[test]
    fn classify_zero_filled_wins_over_repeated_byte() {
        let actual = [0_u8; 64];
        let expected = [0x11_u8; 64];
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::ZeroFilled
        );
    }

    #[test]
    fn classify_repeated_byte_keeps_the_value() {
        let actual = [0xFF_u8; 64];
        let expected = [0x11_u8; 64];
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::RepeatedByte { value: 0xFF }
        );
    }

    #[test]
    fn classify_sparse_counts_differing_bytes() {
        // 3 of 64 bytes differ: rate 4.7% < 10%.
        let expected = [0x11_u8; 64];
        let mut actual = expected;
        actual[3] = 0x22;
        actual[9] = 0x33;
        actual[40] = 0x44;
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::Sparse { corrupted_count: 3 }
        );
    }

    #[test]
    fn classify_aligned_checks_only_the_first_five_positions() {
        // First five differing positions on 512-byte boundaries, then a
        // dense unaligned run to push the rate past 10%.
        let expected = [0x11_u8; 4096];
        let mut actual = expected;
        for position in [0, 512, 1024, 1536, 2048] {
            actual[position] = 0x22;
        }
        for byte in &mut actual[2049..2500] {
            *byte = 0x33;
        }
        assert_eq!(
            classify_chunk(&actual, &expected),
            CorruptionPattern::Aligned { boundary: 512 }
        );
    }

    #[test]
    fn classify_random_reports_the_rate() {
        // Alternate every other byte: rate 50%, unaligned.
        let expected = [0x11_u8; 64];
        let mut actual = expected;
        for position in (1..64).step_by(2) {
            actual[position] = 0x22;
        }
        let CorruptionPattern::Random { corruption_rate } = classify_chunk(&actual, &expected)
        else {
            panic!("expected the random pattern");
        };
        assert!((corruption_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn alignment_prefers_the_smallest_boundary() {
        // Multiples of 1024 are also multiples of 512; Python reports
        // the first boundary in [512, 1024, 4096, 8192].
        assert_eq!(check_alignment(&[0, 1024, 2048]), Some(512));
        assert_eq!(check_alignment(&[0, 512, 700]), None);
        assert_eq!(check_alignment(&[4096]), Some(512));
    }

    #[test]
    fn merge_requires_identical_patterns_and_contiguity() {
        let mut regions = vec![CorruptionRegion::new(
            60,
            256,
            CorruptionPattern::Sparse { corrupted_count: 5 },
        )];
        // Contiguous regions with different counts do not merge.
        push_region(
            &mut regions,
            CorruptionRegion::new(316, 256, CorruptionPattern::Sparse { corrupted_count: 6 }),
        );
        assert_eq!(regions.len(), 2);
        // Contiguous with an equal pattern: merge, keeping the pattern.
        push_region(
            &mut regions,
            CorruptionRegion::new(572, 256, CorruptionPattern::Sparse { corrupted_count: 6 }),
        );
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[1].size(), 512);
        // A gap prevents merging even with an equal pattern.
        push_region(
            &mut regions,
            CorruptionRegion::new(2000, 256, CorruptionPattern::Sparse { corrupted_count: 6 }),
        );
        assert_eq!(regions.len(), 3);
    }

    #[test]
    fn report_classifies_path_mismatch_and_content() {
        let path_mismatch = CorruptionReport {
            path: "store/aa".into(),
            expected: Digest::ZERO,
            actual: Digest::compute(b"x"),
            actual_size: 1024,
            expected_size: 1024,
            content_seed: seed(),
            regions: Vec::new(),
        };
        assert_eq!(path_mismatch.class(), CorruptionClass::PathMismatch);
        assert_eq!(path_mismatch.total_corrupted_bytes(), 0);
        assert!((path_mismatch.corruption_percentage() - 0.0).abs() < f64::EPSILON);

        let content = CorruptionReport {
            path: "store/aa".into(),
            expected: Digest::ZERO,
            actual: Digest::compute(b"x"),
            actual_size: 1024,
            expected_size: 1024,
            content_seed: seed(),
            regions: vec![CorruptionRegion::new(
                60,
                256,
                CorruptionPattern::ZeroFilled,
            )],
        };
        assert_eq!(content.class(), CorruptionClass::Content);
        assert_eq!(content.total_corrupted_bytes(), 256);
        assert!((content.corruption_percentage() - 25.0).abs() < 1e-9);
    }

    #[test]
    fn size_mismatch_alone_classifies_as_content() {
        // Truncation with intact leading content: the region list holds
        // only the truncated region, and the class must be content.
        let report = CorruptionReport {
            path: "store/aa".into(),
            expected: Digest::ZERO,
            actual: Digest::compute(b"x"),
            actual_size: 512,
            expected_size: 1024,
            content_seed: seed(),
            regions: vec![CorruptionRegion::new(
                512,
                512,
                CorruptionPattern::Truncated { missing_bytes: 512 },
            )],
        };
        assert_eq!(report.class(), CorruptionClass::Content);
        // Percentage uses the larger of the two sizes.
        assert!((report.corruption_percentage() - 50.0).abs() < 1e-9);
    }
}
