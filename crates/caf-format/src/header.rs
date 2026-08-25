//! The shared 60-byte CAF v2 and v3 header.

use std::backtrace::Backtrace;
use std::fmt::{self, Display, Formatter};
use std::ops::Range;

use sha3::{Digest as _, Sha3_256};

use crate::HEADER_SIZE;
use crate::digest::Digest;
use crate::hex;
use crate::merkle::FileId;
use crate::seed::ContentSeed;

const PARENT_RANGE: Range<usize> = 0..20;
const SEED_RANGE: Range<usize> = 20..36;
const LENGTH_RANGE: Range<usize> = 36..44;
const CHECKSUM_RANGE: Range<usize> = 44..52;
const RESERVED_RANGE: Range<usize> = 52..60;
const PREFIX_RANGE: Range<usize> = 0..44;
const FORMAT_MARKER_RANGE: Range<usize> = 52..56;
const FILE_ID_SCHEME_OFFSET: usize = 56;
const CONTENT_SCHEME_OFFSET: usize = 57;
const BLOCK_SIZE_LOG_2_OFFSET: usize = 58;
const FLAGS_OFFSET: usize = 59;
const CHECKSUM_SIZE: usize = 8;

const V3_FORMAT_MARKER: [u8; 4] = *b"CAF\x03";
const V3_FILE_ID_SCHEME: u8 = 1;
const V3_CONTENT_SCHEME: u8 = 1;
const V3_BLOCK_SIZE_LOG_2: u8 = 20;
const V3_FLAGS: u8 = 0;
const V3_DESCRIPTOR: [u8; 8] = [
    V3_FORMAT_MARKER[0],
    V3_FORMAT_MARKER[1],
    V3_FORMAT_MARKER[2],
    V3_FORMAT_MARKER[3],
    V3_FILE_ID_SCHEME,
    V3_CONTENT_SCHEME,
    V3_BLOCK_SIZE_LOG_2,
    V3_FLAGS,
];

/// Smallest legal file length: a file is at least its own header.
const MIN_FILE_LENGTH: u64 = HEADER_SIZE as u64;

/// A supported CAF on-disk format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// CAF v2 with linear BLAKE2b-160 file identities.
    V2,
    /// CAF v3 with Merkle BLAKE3 file identities.
    V3,
}

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V2 => "v2",
            Self::V3 => "v3",
        })
    }
}

/// A parsed and validated CAF v2 or v3 header.
///
/// [`Header::parse`] is the single validation implementation shared by
/// verification and the developer commands. It dispatches on the format
/// descriptor, checks the version-specific checksum and descriptor rules,
/// and requires a file length of at least 60.
///
/// # Examples
///
/// ```
/// use caf_format::{ContentSeed, Digest, Header};
///
/// let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86")?;
/// let header = Header::new(Digest::ZERO, seed, 4096)?;
/// let parsed = Header::parse(&header.encode())?;
/// assert_eq!(parsed, header);
/// assert!(parsed.is_root());
/// assert_eq!(parsed.content_length(), 4096 - 60);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    parent: Digest,
    content_seed: ContentSeed,
    file_length: u64,
    format: Format,
}

impl Header {
    /// Creates a CAF v2 header for a file of `file_length` total bytes.
    ///
    /// Roots use [`Digest::ZERO`] as `parent`.
    ///
    /// # Errors
    ///
    /// Returns a [`HeaderError`] if `file_length` is smaller than the
    /// 60-byte header.
    pub fn new(
        parent: Digest,
        content_seed: ContentSeed,
        file_length: u64,
    ) -> Result<Self, HeaderError> {
        Self::new_with_format(parent, content_seed, file_length, Format::V2)
    }

    /// Creates a CAF v3 header for a file of `file_length` total bytes.
    ///
    /// Roots use [`FileId::ZERO`] as `parent`.
    ///
    /// # Errors
    ///
    /// Returns a [`HeaderError`] if `file_length` is smaller than the
    /// 60-byte header.
    pub fn new_v3(
        parent: FileId,
        content_seed: ContentSeed,
        file_length: u64,
    ) -> Result<Self, HeaderError> {
        Self::new_with_format(
            Digest::from_bytes(parent.into_inner()),
            content_seed,
            file_length,
            Format::V3,
        )
    }

    fn new_with_format(
        parent: Digest,
        content_seed: ContentSeed,
        file_length: u64,
        format: Format,
    ) -> Result<Self, HeaderError> {
        if file_length < MIN_FILE_LENGTH {
            return Err(HeaderError::new(HeaderErrorKind::LengthTooSmall {
                file_length,
            }));
        }
        Ok(Self {
            parent,
            content_seed,
            file_length,
            format,
        })
    }

    /// Parses and validates the first 60 bytes of `bytes`.
    ///
    /// Bytes past the header are ignored, so a buffer holding the start of
    /// a file can be passed directly. Validation checks, in order: at
    /// least 60 bytes are present, the descriptor selects v2 or v3, the
    /// stored checksum matches that version's coverage, the v3 algorithm
    /// fields are supported when applicable, and the file length is at
    /// least 60.
    ///
    /// # Errors
    ///
    /// Returns a [`HeaderError`] describing the first failed check.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, HeaderError> {
        let bytes = bytes.as_ref();
        let Some(header) = bytes.get(..HEADER_SIZE) else {
            return Err(HeaderError::new(HeaderErrorKind::Truncated {
                len: bytes.len(),
            }));
        };

        let format = parse_format(header)?;
        let stored: [u8; CHECKSUM_SIZE] = field(header, CHECKSUM_RANGE);
        let computed = checksum(header, format);
        if stored != computed {
            return Err(HeaderError::new(HeaderErrorKind::ChecksumMismatch {
                stored,
                computed,
            }));
        }

        if format == Format::V3 {
            validate_v3_descriptor(header)?;
        }

        let file_length = u64::from_be_bytes(field(header, LENGTH_RANGE));
        Self::new_with_format(
            Digest::from_bytes(field(header, PARENT_RANGE)),
            ContentSeed::from_bytes(field(header, SEED_RANGE)),
            file_length,
            format,
        )
    }

    /// Encodes the header as its 60-byte on-disk form.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0_u8; HEADER_SIZE];
        out[PARENT_RANGE].copy_from_slice(self.parent.as_bytes());
        out[SEED_RANGE].copy_from_slice(self.content_seed.as_bytes());
        out[LENGTH_RANGE].copy_from_slice(&self.file_length.to_be_bytes());
        if self.format == Format::V3 {
            out[RESERVED_RANGE].copy_from_slice(&V3_DESCRIPTOR);
        }
        let digest = checksum(&out, self.format);
        out[CHECKSUM_RANGE].copy_from_slice(&digest);
        out
    }

    /// Returns this header's CAF format.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Returns the raw parent bytes in the legacy digest representation.
    ///
    /// For a typed v3 parent, use [`Header::parent_file_id`].
    #[must_use]
    pub fn parent(&self) -> Digest {
        self.parent
    }

    /// Returns the typed parent file ID for a v3 header.
    ///
    /// Returns `None` for v2, whose parent is a [`Digest`].
    #[must_use]
    pub fn parent_file_id(&self) -> Option<FileId> {
        (self.format == Format::V3).then(|| FileId::from_bytes(self.parent.into_inner()))
    }

    /// Returns the content seed.
    #[must_use]
    pub fn content_seed(&self) -> ContentSeed {
        self.content_seed
    }

    /// Returns the total file length in bytes, including the header.
    #[must_use]
    pub fn file_length(&self) -> u64 {
        self.file_length
    }

    /// Returns the content length in bytes (file length minus the header).
    #[must_use]
    pub fn content_length(&self) -> u64 {
        self.file_length - MIN_FILE_LENGTH
    }

    /// Returns `true` if this file starts a chain (all-zero parent).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parent.is_zero()
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = HeaderError;

    fn try_from(bytes: &[u8]) -> Result<Self, HeaderError> {
        Self::parse(bytes)
    }
}

impl From<Header> for [u8; HEADER_SIZE] {
    fn from(header: Header) -> Self {
        header.encode()
    }
}

/// A raw, unvalidated view of the 60 header bytes, for diagnostics.
///
/// [`Header::parse`] rejects an invalid header outright, which is
/// correct for verification but useless for developer diagnostics
/// (`caf dev show`) that must display the fields of a corrupted header.
/// `RawHeader` exposes every raw field together with the checksum
/// computation [`Header::parse`] uses, and [`RawHeader::validate`]
/// defers to [`Header::parse`], so diagnostic tools share the single
/// validation implementation instead of parsing bytes themselves.
///
/// # Examples
///
/// ```
/// use caf_format::{ContentSeed, Digest, Header, RawHeader};
///
/// let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86")?;
/// let mut bytes = Header::new(Digest::ZERO, seed, 4096)?.encode();
/// bytes[0] ^= 0x01; // corrupt the parent hash
/// let raw = RawHeader::from_bytes(&bytes)?;
/// assert!(!raw.checksum_matches());
/// assert_eq!(raw.file_length(), 4096);
/// assert!(raw.validate().is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawHeader {
    bytes: [u8; HEADER_SIZE],
}

impl RawHeader {
    /// Captures the first 60 bytes of `bytes` without validating them.
    ///
    /// # Errors
    ///
    /// Returns a [`HeaderError`] (truncated) if fewer than 60 bytes are
    /// available — the only condition that leaves nothing to display.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, HeaderError> {
        let bytes = bytes.as_ref();
        let Some(header) = bytes.get(..HEADER_SIZE) else {
            return Err(HeaderError::new(HeaderErrorKind::Truncated {
                len: bytes.len(),
            }));
        };
        Ok(Self {
            bytes: field(header, 0..HEADER_SIZE),
        })
    }

    /// Returns the raw parent digest field.
    #[must_use]
    pub fn parent(&self) -> Digest {
        Digest::from_bytes(field(&self.bytes, PARENT_RANGE))
    }

    /// Returns the raw content seed field.
    #[must_use]
    pub fn content_seed(&self) -> ContentSeed {
        ContentSeed::from_bytes(field(&self.bytes, SEED_RANGE))
    }

    /// Returns the raw file length field (total bytes, header included).
    #[must_use]
    pub fn file_length(&self) -> u64 {
        u64::from_be_bytes(field(&self.bytes, LENGTH_RANGE))
    }

    /// Returns the checksum stored in the header.
    #[must_use]
    pub fn stored_checksum(&self) -> [u8; 8] {
        field(&self.bytes, CHECKSUM_RANGE)
    }

    /// Detects the header format from its raw descriptor.
    ///
    /// Descriptor algorithm bytes are validated separately by [`Self::validate`].
    ///
    /// # Errors
    ///
    /// Returns a [`HeaderError`] if the descriptor is neither a v2 zero
    /// field nor a v3 marker.
    pub fn format(&self) -> Result<Format, HeaderError> {
        parse_format(&self.bytes)
    }

    /// Returns the checksum computed with the detected version's coverage.
    ///
    /// A raw descriptor with the v3 marker uses the v3 checksum coverage;
    /// other descriptors use the v2 prefix coverage for diagnostics. Full
    /// validation still rejects unknown descriptors.
    #[must_use]
    pub fn computed_checksum(&self) -> [u8; 8] {
        let format = if self.bytes[FORMAT_MARKER_RANGE] == V3_FORMAT_MARKER {
            Format::V3
        } else {
            Format::V2
        };
        checksum(&self.bytes, format)
    }

    /// Returns the raw version descriptor field.
    ///
    /// This is all zero in v2 and contains the marker and algorithm
    /// descriptor in v3.
    #[must_use]
    pub fn reserved(&self) -> [u8; 8] {
        field(&self.bytes, RESERVED_RANGE)
    }

    /// Returns the raw four-byte format marker.
    #[must_use]
    pub fn format_marker(&self) -> [u8; 4] {
        field(&self.bytes, FORMAT_MARKER_RANGE)
    }

    /// Returns the raw v3 file-ID scheme byte.
    #[must_use]
    pub fn file_id_scheme(&self) -> u8 {
        self.bytes[FILE_ID_SCHEME_OFFSET]
    }

    /// Returns the raw v3 content scheme byte.
    #[must_use]
    pub fn content_scheme(&self) -> u8 {
        self.bytes[CONTENT_SCHEME_OFFSET]
    }

    /// Returns the raw v3 physical-block log2 byte.
    #[must_use]
    pub fn block_size_log_2(&self) -> u8 {
        self.bytes[BLOCK_SIZE_LOG_2_OFFSET]
    }

    /// Returns the raw v3 flags byte.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.bytes[FLAGS_OFFSET]
    }

    /// Returns `true` if all v3 descriptor algorithm bytes are supported.
    #[must_use]
    pub fn v3_descriptor_is_valid(&self) -> bool {
        self.reserved() == V3_DESCRIPTOR
    }

    /// Returns `true` if the stored checksum matches the computed one.
    #[must_use]
    pub fn checksum_matches(&self) -> bool {
        self.stored_checksum() == self.computed_checksum()
    }

    /// Returns `true` if the reserved field is all zeros.
    #[must_use]
    pub fn reserved_is_zero(&self) -> bool {
        self.bytes[RESERVED_RANGE].iter().all(|&byte| byte == 0)
    }

    /// Returns `true` if the parent field is the all-zero root marker.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parent().is_zero()
    }

    /// Runs the full [`Header::parse`] validation over these bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`HeaderError`] describing the first failed check.
    pub fn validate(&self) -> Result<Header, HeaderError> {
        Header::parse(self.bytes)
    }
}

impl TryFrom<&[u8]> for RawHeader {
    type Error = HeaderError;

    fn try_from(bytes: &[u8]) -> Result<Self, HeaderError> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<RawHeader> for Header {
    type Error = HeaderError;

    fn try_from(raw: RawHeader) -> Result<Self, HeaderError> {
        raw.validate()
    }
}

/// Detects a format before checksum validation selects its coverage.
fn parse_format(header: &[u8]) -> Result<Format, HeaderError> {
    if header[RESERVED_RANGE].iter().all(|&byte| byte == 0) {
        Ok(Format::V2)
    } else if header[FORMAT_MARKER_RANGE] == V3_FORMAT_MARKER {
        Ok(Format::V3)
    } else {
        Err(HeaderError::new(HeaderErrorKind::UnknownFormat {
            descriptor: field(header, RESERVED_RANGE),
        }))
    }
}

/// Validates the algorithm bytes following a recognized v3 marker.
fn validate_v3_descriptor(header: &[u8]) -> Result<(), HeaderError> {
    let file_id_scheme = header[FILE_ID_SCHEME_OFFSET];
    if file_id_scheme != V3_FILE_ID_SCHEME {
        return Err(HeaderError::new(HeaderErrorKind::UnsupportedFileIdScheme {
            found: file_id_scheme,
        }));
    }
    let content_scheme = header[CONTENT_SCHEME_OFFSET];
    if content_scheme != V3_CONTENT_SCHEME {
        return Err(HeaderError::new(
            HeaderErrorKind::UnsupportedContentScheme {
                found: content_scheme,
            },
        ));
    }
    let block_size_log_2 = header[BLOCK_SIZE_LOG_2_OFFSET];
    if block_size_log_2 != V3_BLOCK_SIZE_LOG_2 {
        return Err(HeaderError::new(
            HeaderErrorKind::UnsupportedBlockSizeLog2 {
                found: block_size_log_2,
            },
        ));
    }
    let flags = header[FLAGS_OFFSET];
    if flags != V3_FLAGS {
        return Err(HeaderError::new(HeaderErrorKind::UnsupportedFlags {
            found: flags,
        }));
    }
    Ok(())
}

/// Computes the first 8 bytes of the format-specific SHA3-256 checksum.
fn checksum(header: &[u8], format: Format) -> [u8; CHECKSUM_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(&header[PREFIX_RANGE]);
    if format == Format::V3 {
        hasher.update(&header[RESERVED_RANGE]);
    }
    let digest = hasher.finalize();
    field(digest.as_slice(), 0..CHECKSUM_SIZE)
}

/// Copies a fixed-size field out of a buffer.
fn field<const N: usize>(bytes: &[u8], range: Range<usize>) -> [u8; N] {
    bytes[range]
        .try_into()
        .expect("field range length matches the array size")
}

/// Error constructing or validating a CAF header.
///
/// Produced by [`Header::parse`] and [`Header::new`]. The `is_*` methods
/// identify the failed check; `Display` describes it.
#[derive(Debug)]
pub struct HeaderError {
    kind: HeaderErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum HeaderErrorKind {
    Truncated {
        len: usize,
    },
    ChecksumMismatch {
        stored: [u8; CHECKSUM_SIZE],
        computed: [u8; CHECKSUM_SIZE],
    },
    UnknownFormat {
        descriptor: [u8; 8],
    },
    UnsupportedFileIdScheme {
        found: u8,
    },
    UnsupportedContentScheme {
        found: u8,
    },
    UnsupportedBlockSizeLog2 {
        found: u8,
    },
    UnsupportedFlags {
        found: u8,
    },
    LengthTooSmall {
        file_length: u64,
    },
}

impl HeaderError {
    fn new(kind: HeaderErrorKind) -> Self {
        Self {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns `true` if fewer than 60 bytes were available.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::Truncated { .. })
    }

    /// Returns `true` if the stored checksum does not match the header.
    #[must_use]
    pub fn is_checksum_mismatch(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::ChecksumMismatch { .. })
    }

    /// Returns `true` if the reserved field contains nonzero bytes.
    #[must_use]
    pub fn is_reserved_not_zero(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::UnknownFormat { .. })
    }

    /// Returns `true` if the descriptor identifies no supported format.
    #[must_use]
    pub fn is_unknown_format(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::UnknownFormat { .. })
    }

    /// Returns `true` if a v3 file-ID scheme byte is unsupported.
    #[must_use]
    pub fn is_unsupported_file_id_scheme(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::UnsupportedFileIdScheme { .. })
    }

    /// Returns `true` if a v3 content scheme byte is unsupported.
    #[must_use]
    pub fn is_unsupported_content_scheme(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::UnsupportedContentScheme { .. })
    }

    /// Returns `true` if a v3 block-size descriptor is unsupported.
    #[must_use]
    pub fn is_unsupported_block_size_log_2(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::UnsupportedBlockSizeLog2 { .. })
    }

    /// Returns `true` if a v3 flags byte is unsupported.
    #[must_use]
    pub fn is_unsupported_flags(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::UnsupportedFlags { .. })
    }

    /// Returns `true` if the file length field is smaller than 60.
    #[must_use]
    pub fn is_length_too_small(&self) -> bool {
        matches!(self.kind, HeaderErrorKind::LengthTooSmall { .. })
    }
}

impl Display for HeaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.kind {
            HeaderErrorKind::Truncated { len } => {
                write!(f, "header truncated: need {HEADER_SIZE} bytes, got {len}")
            }
            HeaderErrorKind::ChecksumMismatch { stored, computed } => write!(
                f,
                "header checksum mismatch: stored {}, computed {}",
                hex::encode(stored),
                hex::encode(computed),
            ),
            HeaderErrorKind::UnknownFormat { descriptor } => write!(
                f,
                "unknown header format descriptor {}",
                hex::encode(descriptor),
            ),
            HeaderErrorKind::UnsupportedFileIdScheme { found } => {
                write!(f, "unsupported CAF v3 file-ID scheme {found}")
            }
            HeaderErrorKind::UnsupportedContentScheme { found } => {
                write!(f, "unsupported CAF v3 content scheme {found}")
            }
            HeaderErrorKind::UnsupportedBlockSizeLog2 { found } => {
                write!(f, "unsupported CAF v3 file-block log2 size {found}")
            }
            HeaderErrorKind::UnsupportedFlags { found } => {
                write!(f, "unsupported CAF v3 flags 0x{found:02x}")
            }
            HeaderErrorKind::LengthTooSmall { file_length } => write!(
                f,
                "file length {file_length} is smaller than the \
                 {HEADER_SIZE}-byte header"
            ),
        }
    }
}

impl std::error::Error for HeaderError {}

#[cfg(test)]
mod tests {
    use sha3::{Digest as _, Sha3_256};

    use super::{
        BLOCK_SIZE_LOG_2_OFFSET, CHECKSUM_RANGE, CONTENT_SCHEME_OFFSET, FILE_ID_SCHEME_OFFSET,
        FLAGS_OFFSET, Format, Header, LENGTH_RANGE, RESERVED_RANGE, RawHeader,
    };
    use crate::{ContentSeed, Digest, FileId, HEADER_SIZE, hex};

    fn sample_header() -> Header {
        let parent = Digest::from_hex("605cb937a87b5868c431a749863b38e708e09b76").unwrap();
        let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86").unwrap();
        Header::new(parent, seed, 4096).unwrap()
    }

    fn sample_v3_header() -> Header {
        let header = sample_header();
        Header::new_v3(
            FileId::from_bytes(header.parent().into_inner()),
            header.content_seed(),
            header.file_length(),
        )
        .unwrap()
    }

    fn rewrite_v3_checksum(bytes: &mut [u8; HEADER_SIZE]) {
        let mut hasher = Sha3_256::new();
        hasher.update(&bytes[..44]);
        hasher.update(&bytes[52..]);
        bytes[CHECKSUM_RANGE].copy_from_slice(&hasher.finalize()[..8]);
    }

    #[test]
    fn encode_parse_round_trip() {
        let header = sample_header();
        let parsed = Header::parse(header.encode()).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(parsed.format(), Format::V2);
        assert!(!parsed.is_root());
        assert_eq!(parsed.file_length(), 4096);
        assert_eq!(parsed.content_length(), 4096 - HEADER_SIZE as u64);
    }

    #[test]
    fn v3_header_matches_independent_reference_vector() {
        const EXPECTED: &str = concat!(
            "605cb937a87b5868c431a749863b38e708e09b76",
            "b42d9a6630882f79c7599ae213435f86",
            "0000000000001000",
            "e4298b15e15e2bf2",
            "4341460301011400",
        );
        let header = sample_v3_header();
        assert_eq!(
            header.encode(),
            hex::decode::<HEADER_SIZE>(EXPECTED).unwrap()
        );
        assert_eq!(Header::parse(header.encode()).unwrap(), header);
        assert_eq!(header.format(), Format::V3);
        assert_eq!(
            header.parent_file_id(),
            Some(FileId::from_bytes(header.parent().into_inner()))
        );
    }

    #[test]
    fn v3_descriptor_is_covered_by_checksum() {
        let mut bytes = sample_v3_header().encode();
        bytes[FLAGS_OFFSET] ^= 1;
        assert!(Header::parse(bytes).unwrap_err().is_checksum_mismatch());
    }

    #[test]
    fn unknown_marker_is_reported_before_checksum_mismatch() {
        let mut bytes = sample_v3_header().encode();
        bytes[52] ^= 1;
        bytes[CHECKSUM_RANGE][0] ^= 1;
        let error = Header::parse(bytes).unwrap_err();
        assert!(error.is_unknown_format());
    }

    #[test]
    fn v3_rejects_unsupported_descriptor_values_after_checksum() {
        let cases = [
            (FILE_ID_SCHEME_OFFSET, 2_u8, 0_usize),
            (CONTENT_SCHEME_OFFSET, 2, 1),
            (BLOCK_SIZE_LOG_2_OFFSET, 19, 2),
            (FLAGS_OFFSET, 1, 3),
        ];
        for (offset, value, kind) in cases {
            let mut bytes = sample_v3_header().encode();
            bytes[offset] = value;
            rewrite_v3_checksum(&mut bytes);
            let error = Header::parse(bytes).unwrap_err();
            let expected_kind = [
                error.is_unsupported_file_id_scheme(),
                error.is_unsupported_content_scheme(),
                error.is_unsupported_block_size_log_2(),
                error.is_unsupported_flags(),
            ];
            assert!(expected_kind[kind], "offset {offset}: {error}");
        }
    }

    #[test]
    fn raw_header_diagnostics_follow_v3_checksum_rules() {
        let header = sample_v3_header();
        let raw = RawHeader::from_bytes(header.encode()).unwrap();
        assert_eq!(raw.format().unwrap(), Format::V3);
        assert_eq!(raw.format_marker(), *b"CAF\x03");
        assert_eq!(raw.file_id_scheme(), 1);
        assert_eq!(raw.content_scheme(), 1);
        assert_eq!(raw.block_size_log_2(), 20);
        assert_eq!(raw.flags(), 0);
        assert!(raw.v3_descriptor_is_valid());
        assert!(raw.checksum_matches());
        assert!(!raw.reserved_is_zero());
    }

    #[test]
    fn parse_ignores_trailing_bytes() {
        let header = sample_header();
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"content follows");
        assert_eq!(Header::parse(&bytes).unwrap(), header);
    }

    #[test]
    fn parse_rejects_truncated_input() {
        let encoded = sample_header().encode();
        for len in [0, 1, HEADER_SIZE - 1] {
            let err = Header::parse(&encoded[..len]).unwrap_err();
            assert!(err.is_truncated(), "len {len}: {err}");
        }
    }

    #[test]
    fn parse_rejects_corrupted_checksummed_bytes() {
        let mut bytes = sample_header().encode();
        bytes[0] ^= 0x01;
        let err = Header::parse(bytes).unwrap_err();
        assert!(err.is_checksum_mismatch());
    }

    #[test]
    fn parse_rejects_corrupted_stored_checksum() {
        let mut bytes = sample_header().encode();
        bytes[CHECKSUM_RANGE][0] ^= 0x01;
        let err = Header::parse(bytes).unwrap_err();
        assert!(err.is_checksum_mismatch());
    }

    #[test]
    fn parse_rejects_nonzero_reserved_bytes() {
        // Nonzero reserved bytes fail validation even
        // with a valid checksum (the checksum does not cover them).
        let mut bytes = sample_header().encode();
        bytes[RESERVED_RANGE][7] = 0x01;
        let err = Header::parse(bytes).unwrap_err();
        assert!(err.is_reserved_not_zero());
    }

    #[test]
    fn parse_rejects_file_length_below_minimum() {
        use sha3::Digest as _;

        // Craft a header whose checksum is valid but whose length is 59:
        // encode with a legal length, then rewrite length and checksum.
        let mut bytes = sample_header().encode();
        bytes[LENGTH_RANGE].copy_from_slice(&59_u64.to_be_bytes());
        let digest = sha3::Sha3_256::digest(&bytes[..44]);
        bytes[CHECKSUM_RANGE].copy_from_slice(&digest.as_slice()[..8]);
        let err = Header::parse(bytes).unwrap_err();
        assert!(err.is_length_too_small());
    }

    #[test]
    fn raw_header_exposes_fields_of_an_invalid_header() {
        let header = sample_header();
        let mut bytes = header.encode();
        bytes[RESERVED_RANGE][0] = 0xAA;
        let raw = RawHeader::from_bytes(bytes).unwrap();
        // The reserved bytes are outside the checksummed range, so the
        // checksum still matches while validation fails.
        assert!(raw.checksum_matches());
        assert!(!raw.reserved_is_zero());
        assert_eq!(raw.reserved()[0], 0xAA);
        assert_eq!(raw.parent(), header.parent());
        assert_eq!(raw.content_seed(), header.content_seed());
        assert_eq!(raw.file_length(), 4096);
        assert!(!raw.is_root());
        assert!(raw.validate().unwrap_err().is_reserved_not_zero());
    }

    #[test]
    fn raw_header_matches_parse_on_valid_bytes() {
        let header = sample_header();
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"trailing content is ignored");
        let raw = RawHeader::from_bytes(&bytes).unwrap();
        assert!(raw.checksum_matches());
        assert!(raw.reserved_is_zero());
        assert_eq!(raw.stored_checksum(), raw.computed_checksum());
        assert_eq!(raw.validate().unwrap(), header);
    }

    #[test]
    fn raw_header_rejects_truncated_input() {
        let err = RawHeader::from_bytes([0_u8; HEADER_SIZE - 1]).unwrap_err();
        assert!(err.is_truncated());
    }

    #[test]
    fn conversion_traits_forward_to_the_inherent_methods() {
        let header = sample_header();
        let bytes: [u8; HEADER_SIZE] = header.into();
        assert_eq!(bytes, header.encode());
        assert_eq!(Header::try_from(&bytes[..]).unwrap(), header);

        let raw = RawHeader::try_from(&bytes[..]).unwrap();
        assert_eq!(Header::try_from(raw).unwrap(), header);
        assert!(
            RawHeader::try_from(&bytes[..HEADER_SIZE - 1])
                .unwrap_err()
                .is_truncated()
        );
    }

    #[test]
    fn new_rejects_file_length_below_minimum() {
        let header = sample_header();
        let err = Header::new(header.parent(), header.content_seed(), 59).unwrap_err();
        assert!(err.is_length_too_small());
        assert_eq!(
            err.to_string(),
            "file length 59 is smaller than the 60-byte header"
        );
    }
}
