//! The 60-byte version 2 header: encoding, parsing, and validation.

use std::backtrace::Backtrace;
use std::fmt::{self, Display, Formatter};
use std::ops::Range;

use sha3::{Digest as _, Sha3_256};

use crate::HEADER_SIZE;
use crate::digest::Digest;
use crate::hex;
use crate::seed::ContentSeed;

const PARENT_RANGE: Range<usize> = 0..20;
const SEED_RANGE: Range<usize> = 20..36;
const LENGTH_RANGE: Range<usize> = 36..44;
const CHECKSUM_RANGE: Range<usize> = 44..52;
const RESERVED_RANGE: Range<usize> = 52..60;
/// The checksum covers everything before it: parent, seed, and length.
const CHECKSUMMED_RANGE: Range<usize> = 0..44;
const CHECKSUM_SIZE: usize = 8;

/// Smallest legal file length: a file is at least its own header.
const MIN_FILE_LENGTH: u64 = HEADER_SIZE as u64;

/// A parsed and validated version 2 header.
///
/// [`Header::parse`] is the single validation implementation shared by
/// verification and the developer commands. It
/// checks the stored checksum, requires the reserved bytes to be zero,
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
}

impl Header {
    /// Creates a header for a file of `file_length` total bytes.
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
        if file_length < MIN_FILE_LENGTH {
            return Err(HeaderError::new(HeaderErrorKind::LengthTooSmall {
                file_length,
            }));
        }
        Ok(Self {
            parent,
            content_seed,
            file_length,
        })
    }

    /// Parses and validates the first 60 bytes of `bytes`.
    ///
    /// Bytes past the header are ignored, so a buffer holding the start of
    /// a file can be passed directly. Validation checks, in order: at
    /// least 60 bytes are present, the stored checksum matches the first
    /// 44 bytes, the reserved field is all zeros, and the file length is
    /// at least 60.
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

        let stored: [u8; CHECKSUM_SIZE] = field(header, CHECKSUM_RANGE);
        let computed = checksum(&header[CHECKSUMMED_RANGE]);
        if stored != computed {
            return Err(HeaderError::new(HeaderErrorKind::ChecksumMismatch {
                stored,
                computed,
            }));
        }

        if header[RESERVED_RANGE].iter().any(|&byte| byte != 0) {
            return Err(HeaderError::new(HeaderErrorKind::ReservedNotZero));
        }

        let file_length = u64::from_be_bytes(field(header, LENGTH_RANGE));
        Self::new(
            Digest::from_bytes(field(header, PARENT_RANGE)),
            ContentSeed::from_bytes(field(header, SEED_RANGE)),
            file_length,
        )
    }

    /// Encodes the header as its 60-byte on-disk form.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0_u8; HEADER_SIZE];
        out[PARENT_RANGE].copy_from_slice(self.parent.as_bytes());
        out[SEED_RANGE].copy_from_slice(self.content_seed.as_bytes());
        out[LENGTH_RANGE].copy_from_slice(&self.file_length.to_be_bytes());
        let digest = checksum(&out[CHECKSUMMED_RANGE]);
        out[CHECKSUM_RANGE].copy_from_slice(&digest);
        // The reserved range keeps its zero initialization.
        out
    }

    /// Returns the parent digest ([`Digest::ZERO`] for roots).
    #[must_use]
    pub fn parent(&self) -> Digest {
        self.parent
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

    /// Returns the checksum computed over the header's first 44 bytes.
    #[must_use]
    pub fn computed_checksum(&self) -> [u8; 8] {
        checksum(&self.bytes[CHECKSUMMED_RANGE])
    }

    /// Returns the raw reserved field (all zeros in a valid v2 header).
    #[must_use]
    pub fn reserved(&self) -> [u8; 8] {
        field(&self.bytes, RESERVED_RANGE)
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

/// First 8 bytes of SHA3-256 over the checksummed header prefix.
fn checksum(prefix: &[u8]) -> [u8; CHECKSUM_SIZE] {
    let digest = Sha3_256::digest(prefix);
    field(digest.as_slice(), 0..CHECKSUM_SIZE)
}

/// Copies a fixed-size field out of a buffer.
fn field<const N: usize>(bytes: &[u8], range: Range<usize>) -> [u8; N] {
    bytes[range]
        .try_into()
        .expect("field range length matches the array size")
}

/// Error validating a version 2 header.
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
    ReservedNotZero,
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
        matches!(self.kind, HeaderErrorKind::ReservedNotZero)
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
            HeaderErrorKind::ReservedNotZero => {
                write!(f, "reserved header bytes are not zero")
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
    use super::{CHECKSUM_RANGE, Header, LENGTH_RANGE, RESERVED_RANGE, RawHeader};
    use crate::{ContentSeed, Digest, HEADER_SIZE};

    fn sample_header() -> Header {
        let parent = Digest::from_hex("605cb937a87b5868c431a749863b38e708e09b76").unwrap();
        let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86").unwrap();
        Header::new(parent, seed, 4096).unwrap()
    }

    #[test]
    fn encode_parse_round_trip() {
        let header = sample_header();
        let parsed = Header::parse(header.encode()).unwrap();
        assert_eq!(parsed, header);
        assert!(!parsed.is_root());
        assert_eq!(parsed.file_length(), 4096);
        assert_eq!(parsed.content_length(), 4096 - HEADER_SIZE as u64);
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
