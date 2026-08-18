//! Small formatting and path helpers shared by the commands.

use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// The store a command operates on: what `--directory` selected.
///
/// Without `--directory`, both `gen` and `verify` use the current directory.
#[derive(Clone, Copy, Debug)]
pub enum StoreRoot<'a> {
    /// The directory given with `--directory`.
    Given(&'a Path),
    /// No `--directory` was given: the current directory.
    CurrentDirectory,
}

impl StoreRoot<'_> {
    /// Resolves the root to a concrete path.
    ///
    /// Operations never change the process working directory; the
    /// resolved path is passed to the library as an explicit store root.
    ///
    /// # Errors
    ///
    /// Returns the error the operating system reported for the current
    /// directory, when no directory was given.
    pub fn resolve(self) -> Result<PathBuf> {
        match self {
            Self::Given(directory) => Ok(directory.to_path_buf()),
            Self::CurrentDirectory => env::current_dir().context("resolving the current directory"),
        }
    }
}

impl<'a> From<Option<&'a Path>> for StoreRoot<'a> {
    fn from(directory: Option<&'a Path>) -> Self {
        match directory {
            Some(directory) => Self::Given(directory),
            None => Self::CurrentDirectory,
        }
    }
}

/// Formats `value` with thousands separators (`1234567` → `1,234,567`).
pub fn commas(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let lead = digits.len() % 3;
    for (index, ch) in digits.chars().enumerate() {
        if index != 0 && index % 3 == lead % 3 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats bytes as lowercase hex (presentation only; hex *parsing*
/// stays in `caf-format`).
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{commas, hex};

    #[test]
    fn commas_group_digits_like_python() {
        for (value, expected) in [
            (0, "0"),
            (1, "1"),
            (999, "999"),
            (1000, "1,000"),
            (4096, "4,096"),
            (12288, "12,288"),
            (1_234_567, "1,234,567"),
            (1_000_000_000, "1,000,000,000"),
        ] {
            assert_eq!(commas(value), expected, "{value}");
        }
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab]), "000fab");
        assert_eq!(hex(&[]), "");
    }
}
