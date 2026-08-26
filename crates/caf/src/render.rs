//! Rendering of verification results: diagnostic lines and the Error
//! Analysis report.
//!
//! The output includes severity prefixes (`ERROR:`, `CORRUPTION:`,
//! `ORPHAN:`), paths, expected and actual hashes, offsets, sizes,
//! corruption classes, and deterministic ordering. Colors, rule widths,
//! and column padding are presentation details.
//! Diagnostic lines go to standard error, the Error Analysis report to
//! standard output.

use caf_format::Format;
use caf_store::{
    CorruptionClass, CorruptionPattern, CorruptionRegion, CorruptionReport, Diagnostic,
    VerificationReport,
};

use crate::style::Style;
use crate::util::commas;

/// Width of the Error Analysis rule, matching rich's 80-column default
/// for non-terminal output.
const RULE_WIDTH: usize = 80;
/// Number of characters in the corruption visualization bar.
const BAR_LENGTH: usize = 60;

/// Prints one line per diagnostic to standard error, in report order.
pub fn diagnostics(diagnostics: &[Diagnostic], style: Style) {
    for diagnostic in diagnostics {
        let prefix = format!("{}:", diagnostic.severity());
        let prefix = match diagnostic.severity() {
            caf_store::Severity::Orphan => style.yellow_bold(prefix),
            _ => style.red_bold(prefix),
        };
        eprintln!("{prefix} {}", message(diagnostic));
    }
}

/// The message body for one diagnostic.
fn message(diagnostic: &Diagnostic) -> String {
    match diagnostic {
        Diagnostic::InvalidPathLayout { path } => {
            format!("Invalid CAF path layout: {}", path.display())
        }
        Diagnostic::InvalidHeader { path, source } => format!(
            "Header corrupted in {} - cannot proceed with validation ({source})",
            path.display()
        ),
        Diagnostic::SizeMismatch {
            path,
            expected,
            actual,
        } => format!(
            "File size mismatch in {}: expected {expected}, got {actual}",
            path.display()
        ),
        Diagnostic::DigestMismatch { report } => match report.format() {
            Format::V2 => format!(
                "Invalid checksum for file \"{}\": actual blake2b {}",
                report.path().display(),
                report.actual_digest()
            ),
            Format::V3 if report.actual_digest() == report.expected_digest() => format!(
                "Noncanonical CAF v3 content in file \"{}\"",
                report.path().display()
            ),
            Format::V3 => format!(
                "Invalid file ID for file \"{}\": actual CAF-Merkle-BLAKE3-160 {}",
                report.path().display(),
                report.actual_digest()
            ),
        },
        Diagnostic::MissingParent { parent_path, .. } => {
            format!("Parent hash not found: {}", parent_path.display())
        }
        Diagnostic::ChainFormatMismatch {
            path,
            parent_path,
            child_format,
            parent_format,
            ..
        } => format!(
            "Chain format mismatch in {}: {child_format} child references {parent_format} parent {}",
            path.display(),
            parent_path.display()
        ),
        Diagnostic::OrphanedFile { path } => {
            format!("File not referenced by any files: {}", path.display())
        }
        Diagnostic::RootsMismatch { .. } => "Root hash is not valid, roots are missing.".to_owned(),
        // `Diagnostic` is non-exhaustive; render future variants through
        // their severity and path rather than failing to compile.
        other => format!("Verification finding at {}", other.path().display()),
    }
}

/// Prints the Error Analysis section for every corrupted file to
/// standard output; prints nothing when there are no corruption reports.
pub fn error_analysis(report: &VerificationReport, style: Style) {
    let mut reports = report.corruption_reports().peekable();
    if reports.peek().is_none() {
        return;
    }

    println!();
    println!("{}", rule("Error Analysis", style));
    for corruption in reports {
        println!();
        println!("{} {}", style.bold("File:"), corruption.path().display());
        match corruption.class() {
            CorruptionClass::PathMismatch => path_mismatch_block(corruption, style),
            // `CorruptionClass` is non-exhaustive; the content body
            // reports the analysis in full, so it is the right fallback
            // for classes added later.
            _ => content_block(corruption, style),
        }
    }
    println!();
}

/// A centered `── title ──` rule spanning [`RULE_WIDTH`] columns.
fn rule(title: &str, style: Style) -> String {
    let dashes = RULE_WIDTH.saturating_sub(title.chars().count() + 2);
    let left = dashes / 2;
    let right = dashes - left;
    format!(
        "{} {title} {}",
        style.red("─".repeat(left)),
        style.red("─".repeat(right))
    )
}

/// Renders a two-column label/value table: labels are padded to the
/// widest label plus two spaces (rich's `padding=(0, 2, 0, 0)`).
fn table(rows: &[(&str, String)]) {
    let width = rows
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0)
        + 2;
    for (label, value) in rows {
        println!("{label:<width$}{value}");
    }
}

/// The `PATH MISMATCH (content valid)` report body.
fn path_mismatch_block(report: &CorruptionReport, style: Style) {
    println!(
        "{} {} (content valid)",
        style.bold("Status:"),
        style.yellow_bold("PATH MISMATCH")
    );
    table(&[
        (
            "File Size",
            format!("{} bytes", commas(report.actual_size())),
        ),
        ("Path indicates", report.expected_digest().to_hex()),
        ("Actual file ID", report.actual_digest().to_hex()),
    ]);
    println!();
    println!("The file content is valid but stored at an incorrect path.");
}

/// The `CONTENT CORRUPTED` report body: sizes, hashes, region details,
/// and the visualization bar.
fn content_block(report: &CorruptionReport, style: Style) {
    println!(
        "{} {}",
        style.bold("Status:"),
        style.red_bold("CONTENT CORRUPTED")
    );
    table(&[
        (
            "Actual Size",
            format!("{} bytes", commas(report.actual_size())),
        ),
        (
            "Header Size",
            format!("{} bytes", commas(report.expected_size())),
        ),
        (
            expected_id_label(report.format()),
            report.expected_digest().to_hex(),
        ),
        (
            actual_id_label(report.format()),
            report.actual_digest().to_hex(),
        ),
    ]);
    println!();
    // Analysis runs only on files whose header validated, so header
    // validation is always PASSED here.
    println!("Header Validation: {}", style.green("PASSED"));
    println!("Content Seed: {}", report.content_seed().to_hex());

    let analysis_size = report.actual_size().max(report.expected_size());
    println!();
    println!("{}", style.bold("Corruption Analysis"));
    println!("  Analysis size: {}", commas(analysis_size));
    println!(
        "  Bytes corrupted: {} ({:.2}%)",
        style.red(commas(report.total_corrupted_bytes())),
        report.corruption_percentage()
    );
    println!("  Regions: {}", report.regions().len());

    for (index, region) in report.regions().iter().enumerate() {
        println!();
        println!(
            "  {} Offset {}–{} ({} bytes)",
            style.bold(format!("Region {}:", index + 1)),
            commas(region.offset()),
            commas(region.end()),
            commas(region.size())
        );
        let (name, details) = describe_pattern(region.pattern());
        println!("    Pattern: {name}");
        println!("    Details: {details}");
    }

    println!();
    visualization(analysis_size, report.regions(), style);
}

fn expected_id_label(format: Format) -> &'static str {
    match format {
        Format::V2 => "Expected BLAKE2b",
        Format::V3 => "Expected v3 file ID",
    }
}

fn actual_id_label(format: Format) -> &'static str {
    match format {
        Format::V2 => "Actual BLAKE2b",
        Format::V3 => "Actual v3 file ID",
    }
}

/// The `(pattern name, details)` pair for one region.
fn describe_pattern(pattern: CorruptionPattern) -> (&'static str, String) {
    let details = match pattern {
        CorruptionPattern::ZeroFilled => "All bytes are 0x00".to_owned(),
        CorruptionPattern::RepeatedByte { value, .. } => {
            format!("All bytes are 0x{value:02x}")
        }
        CorruptionPattern::Sparse {
            corrupted_count, ..
        } => {
            format!("{corrupted_count} bytes corrupted")
        }
        CorruptionPattern::Aligned { boundary, .. } => {
            format!("Corruption aligned to {boundary}-byte boundaries")
        }
        CorruptionPattern::Random {
            corruption_rate, ..
        } => {
            format!("{:.1}% corruption rate", corruption_rate * 100.0)
        }
        CorruptionPattern::Truncated { missing_bytes, .. } => {
            format!("Missing {} bytes at end of file", commas(missing_bytes))
        }
        CorruptionPattern::ExtraBytes { extra_count, .. } => {
            format!("Unexpected {} extra bytes", commas(extra_count))
        }
        // `CorruptionPattern` is non-exhaustive; describe future
        // patterns by their class name rather than failing to compile.
        _ => format!("{} corruption", pattern.name()),
    };
    (pattern.name(), details)
}

/// Prints the 60-character corruption bar and its percentage footer.
fn visualization(file_size: u64, regions: &[CorruptionRegion], style: Style) {
    if file_size == 0 {
        return;
    }

    let mut corrupted = [false; BAR_LENGTH];
    for region in regions {
        // Floor the scaled offsets, then mark start..=end clamped to the
        // bar. Widened to u128 so huge files
        // cannot overflow the scaling multiplication.
        let scale = |offset: u64| -> usize {
            usize::try_from(u128::from(offset) * BAR_LENGTH as u128 / u128::from(file_size))
                .unwrap_or(BAR_LENGTH)
        };
        let start = scale(region.offset());
        let end = (scale(region.end()) + 1).min(BAR_LENGTH);
        for slot in corrupted.iter_mut().take(end).skip(start) {
            *slot = true;
        }
    }

    let bar: String = corrupted
        .iter()
        .map(|&bad| {
            if bad {
                style.red("█")
            } else {
                style.dim("━")
            }
        })
        .collect();
    println!("{}", style.bold("Visualization:"));
    println!("{bar}");
    println!("0%{}100%", " ".repeat(BAR_LENGTH - 4));
}
