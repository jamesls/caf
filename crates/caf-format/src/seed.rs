//! Content seeds: the 16-byte values that determine file content.

use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use crate::hex::{self, ParseHexError};

/// A 16-byte content seed.
///
/// The seed is stored in the header and fully determines a file's content
/// through the SHAKE-128 stream (see
/// [`ContentReader`](crate::ContentReader)). Seeds are random but not
/// secret; both `Display` and `Debug` show the hex form.
///
/// # Examples
///
/// ```
/// use caf_format::ContentSeed;
///
/// let seed = ContentSeed::from_hex("85eac145eafbbe4867e1e46b53a26f88")?;
/// assert_eq!(seed.to_hex(), "85eac145eafbbe4867e1e46b53a26f88");
/// # Ok::<(), caf_format::ParseHexError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentSeed([u8; Self::SIZE]);

impl ContentSeed {
    /// Seed length in bytes.
    pub const SIZE: usize = 16;

    /// Creates a seed from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Parses a seed from 32 hex characters, accepting either case.
    ///
    /// # Errors
    ///
    /// Returns [`ParseHexError`] if the input is not exactly 32 hex
    /// characters.
    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self, ParseHexError> {
        hex::decode(hex.as_ref()).map(Self)
    }

    /// Returns the raw seed bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Consumes the seed and returns the raw bytes it wraps.
    #[must_use]
    pub const fn into_inner(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// Returns the 32-character lowercase hex form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl From<[u8; ContentSeed::SIZE]> for ContentSeed {
    fn from(bytes: [u8; ContentSeed::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<ContentSeed> for [u8; ContentSeed::SIZE] {
    fn from(seed: ContentSeed) -> Self {
        seed.into_inner()
    }
}

impl AsRef<[u8]> for ContentSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for ContentSeed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Debug for ContentSeed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ContentSeed({})", self.to_hex())
    }
}

impl FromStr for ContentSeed {
    type Err = ParseHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::ContentSeed;

    const SEED_HEX: &str = "b42d9a6630882f79c7599ae213435f86";

    #[test]
    fn hex_round_trip_accepts_uppercase() {
        let seed = ContentSeed::from_hex(SEED_HEX.to_uppercase()).unwrap();
        assert_eq!(seed.to_hex(), SEED_HEX);
        assert_eq!(SEED_HEX.parse::<ContentSeed>().unwrap(), seed);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let err = ContentSeed::from_hex("b42d").unwrap_err();
        assert!(err.is_bad_length());
    }

    #[test]
    fn byte_round_trip() {
        let seed = ContentSeed::from_bytes([7; ContentSeed::SIZE]);
        let bytes: [u8; ContentSeed::SIZE] = seed.into();
        assert_eq!(ContentSeed::from(bytes), seed);
        assert_eq!(seed.as_bytes(), &[7; ContentSeed::SIZE]);
        assert_eq!(seed.into_inner(), bytes);
    }
}
