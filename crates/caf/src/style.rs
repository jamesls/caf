//! Minimal ANSI styling with automatic terminal detection.
//!
//! Colors are presentation only. Exit statuses and semantic fields do
//! not depend on escape sequences. A [`Style`]
//! enables color exactly when its stream is a terminal, `NO_COLOR` is
//! unset or empty, and `TERM` is not `dumb`, so redirected output and
//! subprocess tests always see plain text.

use std::env;
use std::fmt::Display;
use std::io::{IsTerminal, stderr, stdout};

/// Applies ANSI styles to one output stream when appropriate.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    enabled: bool,
}

impl Style {
    /// Styling policy for standard output.
    #[must_use]
    pub fn for_stdout() -> Self {
        Self {
            enabled: color_allowed() && stdout().is_terminal(),
        }
    }

    /// Styling policy for standard error.
    #[must_use]
    pub fn for_stderr() -> Self {
        Self {
            enabled: color_allowed() && stderr().is_terminal(),
        }
    }

    /// Wraps `text` in the SGR sequence `code` when styling is enabled.
    fn paint(self, code: &str, text: impl Display) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// Bold, for labels and headings.
    pub fn bold(self, text: impl Display) -> String {
        self.paint("1", text)
    }

    /// Dim, for secondary detail.
    pub fn dim(self, text: impl Display) -> String {
        self.paint("2", text)
    }

    /// Green, for success markers (`✓`, `yes`, `PASSED`).
    pub fn green(self, text: impl Display) -> String {
        self.paint("32", text)
    }

    /// Red, for failure markers (`✗`, `no`) and corruption bars.
    pub fn red(self, text: impl Display) -> String {
        self.paint("31", text)
    }

    /// Bold red, for `ERROR:`/`CORRUPTION:` prefixes and statuses.
    pub fn red_bold(self, text: impl Display) -> String {
        self.paint("1;31", text)
    }

    /// Bold yellow, for `ORPHAN:` prefixes and warning statuses.
    pub fn yellow_bold(self, text: impl Display) -> String {
        self.paint("1;33", text)
    }
}

/// Returns `true` unless the environment disables color globally.
fn color_allowed() -> bool {
    if env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        return false;
    }
    env::var_os("TERM").is_none_or(|term| term != "dumb")
}

#[cfg(test)]
mod tests {
    use super::Style;

    #[test]
    fn disabled_style_passes_text_through() {
        let style = Style { enabled: false };
        assert_eq!(style.red_bold("CORRUPTION:"), "CORRUPTION:");
        assert_eq!(style.green(42), "42");
    }

    #[test]
    fn enabled_style_wraps_in_sgr_sequences() {
        let style = Style { enabled: true };
        assert_eq!(style.bold("File:"), "\x1b[1mFile:\x1b[0m");
        assert_eq!(style.dim("x"), "\x1b[2mx\x1b[0m");
    }
}
