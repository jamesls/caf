//! BLAKE2b-160 digests: file identities, parent links, and metadata hashes.

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Write};
use std::str::FromStr;

use blake2::Digest as _;
use blake2::digest::consts::U20;

use crate::hex::{self, ParseHexError};

/// `BLAKE2b` parameterized to the fixed 20-byte v2 output length.
type Blake2b160 = blake2::Blake2b<U20>;

/// A 20-byte BLAKE2b-160 digest.
///
/// Digests identify files (the hex form is the sharded store path, see
/// [`hash_to_relpath`](crate::hash_to_relpath)), link a file to its parent
/// in the header, and pin the `.metadata/all` aggregate. The all-zero
/// digest ([`Digest::ZERO`]) marks the first file of a chain.
///
/// Ordering is byte-wise, which matches lexicographic ordering of the
/// lowercase hex form.
///
/// # Examples
///
/// ```
/// use caf_format::Digest;
///
/// let digest = Digest::from_hex("f46b7e6f7eee7921da61a4779774a118aac54e98")?;
/// assert_eq!(digest.to_hex(), "f46b7e6f7eee7921da61a4779774a118aac54e98");
/// assert!(!digest.is_zero());
/// # Ok::<(), caf_format::ParseHexError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; Self::SIZE]);

impl Digest {
    /// Digest length in bytes.
    pub const SIZE: usize = 20;

    /// The all-zero digest used as the parent hash of chain roots.
    pub const ZERO: Self = Self([0; Self::SIZE]);

    /// Creates a digest from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Parses a digest from 40 hex characters, accepting either case.
    ///
    /// # Errors
    ///
    /// Returns [`ParseHexError`] if the input is not exactly 40 hex
    /// characters.
    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self, ParseHexError> {
        hex::decode(hex.as_ref()).map(Self)
    }

    /// Computes the BLAKE2b-160 digest of `data` in one shot.
    ///
    /// For streaming input use [`Hasher`].
    #[must_use]
    pub fn compute(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Consumes the digest and returns the raw bytes it wraps.
    #[must_use]
    pub const fn into_inner(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// Returns the 40-character lowercase hex form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns `true` for the all-zero digest ([`Digest::ZERO`]).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

impl From<[u8; Digest::SIZE]> for Digest {
    fn from(bytes: [u8; Digest::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Digest> for [u8; Digest::SIZE] {
    fn from(digest: Digest) -> Self {
        digest.into_inner()
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Debug for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl FromStr for Digest {
    type Err = ParseHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Streaming BLAKE2b-160 hasher producing a [`Digest`].
///
/// Used for whole-file digests and the `.metadata/all` aggregate. Also
/// implements [`std::io::Write`], so it composes with [`std::io::copy`].
///
/// # Examples
///
/// ```
/// use caf_format::{Digest, Hasher};
///
/// let mut hasher = Hasher::new();
/// hasher.update(b"caf");
/// hasher.update(b" data");
/// assert_eq!(hasher.finalize(), Digest::compute(b"caf data"));
/// ```
#[derive(Clone, Default)]
pub struct Hasher(Blake2b160);

impl Hasher {
    /// Creates an empty hasher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs `data` into the hash state.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data);
    }

    /// Consumes the hasher and returns the digest.
    #[must_use]
    pub fn finalize(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

impl Debug for Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher").finish_non_exhaustive()
    }
}

impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, Hasher};

    // BLAKE2b-160 of the empty input.
    const EMPTY_HEX: &str = "3345524abf6bbe1809449224b5972c41790b6cf2";

    #[test]
    fn compute_matches_python_blake2b_160() {
        assert_eq!(Digest::compute(b"").to_hex(), EMPTY_HEX);
    }

    #[test]
    fn hasher_streaming_matches_one_shot() {
        let mut hasher = Hasher::new();
        hasher.update(b"split ");
        hasher.update(b"input");
        assert_eq!(hasher.finalize(), Digest::compute(b"split input"));
    }

    #[test]
    fn hasher_write_matches_update() -> std::io::Result<()> {
        let mut hasher = Hasher::new();
        std::io::copy(&mut &b"copied bytes"[..], &mut hasher)?;
        assert_eq!(hasher.finalize(), Digest::compute(b"copied bytes"));
        Ok(())
    }

    #[test]
    fn hex_round_trip_accepts_uppercase() {
        let digest = Digest::from_hex(EMPTY_HEX.to_uppercase()).unwrap();
        assert_eq!(digest.to_hex(), EMPTY_HEX);
        assert_eq!(EMPTY_HEX.parse::<Digest>().unwrap(), digest);
    }

    #[test]
    fn zero_digest_is_zero() {
        assert!(Digest::ZERO.is_zero());
        assert_eq!(Digest::ZERO.into_inner(), [0; Digest::SIZE]);
        assert_eq!(Digest::ZERO.to_hex(), "0".repeat(40));
        assert!(!Digest::compute(b"").is_zero());
    }

    #[test]
    fn ordering_matches_hex_ordering() {
        let a = Digest::from_bytes([0x00; 20]);
        let b = Digest::from_bytes([0xff; 20]);
        assert!(a < b);
        assert!(a.to_hex() < b.to_hex());
    }

    #[test]
    fn debug_and_display_are_hex() {
        let digest = Digest::ZERO;
        assert_eq!(format!("{digest}"), "0".repeat(40));
        assert_eq!(format!("{digest:?}"), format!("Digest({})", "0".repeat(40)));
    }
}
