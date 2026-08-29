//! The `caf` command-line interface.
//!
//! This binary owns CLI parsing, terminal rendering, color policy, and
//! process exit status. It renders the structured results returned by
//! `caf-store`. The command names, option grammar, defaults, stopping
//! semantics, diagnostic severities, and exit statuses are stable: 0 for
//! success, 1 for failed verification, and 2 for a usage error. Invalid
//! input produces a usage error without a panic or backtrace.
//!
//! Terminal colors are presentation details. They are applied
//! only when the target stream is a terminal and `NO_COLOR` is unset
//! (see [`style`]).

mod corrupt;
mod generate;
mod progress;
mod render;
mod show;
mod style;
mod util;
mod verify;

use std::process::ExitCode;

use clap::{CommandFactory as _, Parser, Subcommand};

/// Exit status for failed verification.
const EXIT_FAILURE: u8 = 1;
/// Exit status for usage errors.
const EXIT_USAGE: u8 = 2;

/// Top-level argument grammar: `caf [--version] <COMMAND>`.
///
/// The clap-native version flag is disabled so `--version` can print the
/// `caf, version <X.Y.Z>` instead of clap's `caf <X.Y.Z>`.
/// A bare `caf` prints help and exits 2.
#[derive(Debug, Parser)]
#[command(
    name = "caf",
    bin_name = "caf",
    disable_version_flag = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Show the version and exit.
    #[arg(long)]
    version: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

/// The command set: `gen`, `verify`, and the `dev` group.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate content addressable files.
    Gen(generate::Args),
    /// Verify content addressable files and analyze corruption.
    Verify(verify::Args),
    /// Development tools for testing caf.
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
}

/// The `caf dev` subcommands.
#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Print diagnostic information about a CAF content file.
    Show(show::Args),
    /// Intentionally corrupt a file for testing verification.
    CorruptFile(corrupt::Args),
}

fn main() -> ExitCode {
    // Parse errors (unknown commands or options, invalid values) print a
    // usage message and exit 2 inside clap.
    let cli = Cli::parse();
    if cli.version {
        // The version output has the form `caf, version <X.Y.Z>`.
        println!("caf, version {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match cli.command {
        Some(Command::Gen(args)) => generate::run(&args),
        Some(Command::Verify(args)) => verify::run(&args),
        Some(Command::Dev { command }) => match command {
            DevCommand::Show(args) => show::run(&args),
            DevCommand::CorruptFile(args) => corrupt::run(&args),
        },
        None => {
            // Unreachable through normal parsing (`arg_required_else_help`
            // catches the bare invocation), but never panic on input.
            let _ = Cli::command().print_help();
            ExitCode::from(EXIT_USAGE)
        }
    }
}
