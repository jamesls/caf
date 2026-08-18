//! Lowercase hex encoding and decoding for fixed-size format values.

use std::backtrace::Backtrace;
use std::fmt::{self, Display, Formatter};
use std::str;

/// Error parsing a fixed-length hex string ([`Digest`](crate::Digest) or
/// [`ContentSeed`](crate::ContentSeed)).
#[derive(Debug)]
pub struct ParseHexError {
    /// Expected number of hex characters.
    expected: usize,
    kind: ParseHexErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum ParseHexErrorKind {
    BadLength { actual: usize },
    BadChar { index: usize },
}

impl ParseHexError {
    fn new(expected: usize, kind: ParseHexErrorKind) -> Self {
        Self {
            expected,
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns `true` if the input had the wrong number of characters.
    #[must_use]
    pub fn is_bad_length(&self) -> bool {
        matches!(self.kind, ParseHexErrorKind::BadLength { .. })
    }

    /// Returns `true` if the input contained a non-hex character.
    #[must_use]
    pub fn is_bad_char(&self) -> bool {
        matches!(self.kind, ParseHexErrorKind::BadChar { .. })
    }
}

impl Display for ParseHexError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.kind {
            ParseHexErrorKind::BadLength { actual } => {
                write!(f, "expected {} hex characters, got {actual}", self.expected)
            }
            ParseHexErrorKind::BadChar { index } => {
                write!(f, "invalid hex character at index {index}")
            }
        }
    }
}

impl std::error::Error for ParseHexError {}

/// Lowercase hex digits, indexed by nibble value.
const DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Encodes bytes as lowercase hex.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = vec![0_u8; bytes.len() * 2];
    encode_into(bytes, &mut out);
    String::from_utf8(out).expect("hex digits are ASCII")
}

/// Encodes bytes as lowercase hex into `out`, which must hold exactly
/// two characters per byte, and returns it as a string.
///
/// Callers on hot paths use this with a stack buffer to encode without
/// allocating.
pub(crate) fn encode_into<'a>(bytes: &[u8], out: &'a mut [u8]) -> &'a str {
    assert_eq!(out.len(), bytes.len() * 2, "hex needs two chars per byte");
    for (byte, pair) in bytes.iter().zip(out.chunks_exact_mut(2)) {
        pair[0] = DIGITS[usize::from(byte >> 4)];
        pair[1] = DIGITS[usize::from(byte & 0x0f)];
    }
    str::from_utf8(out).expect("hex digits are ASCII")
}

/// Decodes exactly `N` bytes from a hex string, accepting either case.
pub(crate) fn decode<const N: usize>(hex: &str) -> Result<[u8; N], ParseHexError> {
    let bytes = hex.as_bytes();
    if bytes.len() != N * 2 {
        return Err(ParseHexError::new(
            N * 2,
            ParseHexErrorKind::BadLength {
                actual: bytes.len(),
            },
        ));
    }
    let mut out = [0_u8; N];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = nibble(pair[0]).ok_or_else(|| bad_char::<N>(hex, i * 2))?;
        let lo = nibble(pair[1]).ok_or_else(|| bad_char::<N>(hex, i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn bad_char<const N: usize>(hex: &str, byte_index: usize) -> ParseHexError {
    // Report a character index; for non-ASCII input the byte offset may
    // fall inside a multi-byte character, so count chars up to it.
    let index = hex
        .char_indices()
        .take_while(|(offset, _)| *offset < byte_index)
        .count();
    ParseHexError::new(N * 2, ParseHexErrorKind::BadChar { index })
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn encode_is_lowercase() {
        assert_eq!(encode(&[0x00, 0xab, 0xcd, 0xef, 0x09]), "00abcdef09");
    }

    #[test]
    fn decode_accepts_both_cases() {
        assert_eq!(decode::<2>("beEF").unwrap(), [0xbe, 0xef]);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let err = decode::<2>("beef00").unwrap_err();
        assert!(err.is_bad_length());
        assert_eq!(err.to_string(), "expected 4 hex characters, got 6");
    }

    #[test]
    fn decode_rejects_non_hex_character() {
        let err = decode::<2>("bexf").unwrap_err();
        assert!(err.is_bad_char());
        assert_eq!(err.to_string(), "invalid hex character at index 2");
    }

    #[test]
    fn decode_rejects_non_ascii_character() {
        // 4 bytes but 3 chars; the error must report a character index.
        let err = decode::<2>("b\u{e9}f").unwrap_err();
        assert!(err.is_bad_char());
        assert_eq!(err.to_string(), "invalid hex character at index 1");
    }
}
