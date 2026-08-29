//! Live terminal progress rendering for long-running commands.

use std::env;
use std::io::{self, IsTerminal as _, Write as _};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use caf_store::OperationProgress;

use crate::style::Style;

/// Width of the progress track in terminal columns.
const BAR_WIDTH: usize = 16;
/// Maximum refresh rate; worker callbacks may arrive much more frequently.
const DRAW_INTERVAL: Duration = Duration::from_millis(80);
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Which known limit best describes overall completion.
#[derive(Clone, Copy, Debug)]
pub enum Basis {
    /// Verification knows all file sizes, so bytes prevent one large file
    /// from hiding behind many completed small files.
    Bytes,
    /// Generation stops when any configured limit is reached.
    AnyLimit,
}

/// One in-place terminal progress line, safe to update from worker threads.
#[derive(Debug)]
pub struct ProgressBar {
    label: &'static str,
    basis: Basis,
    enabled: bool,
    style: Style,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    started: Instant,
    last_draw: Option<Instant>,
    latest: Option<OperationProgress>,
    visible: bool,
}

impl ProgressBar {
    /// Creates a progress line for standard error. Rendering is enabled only
    /// for a capable terminal, never for redirected or captured output.
    pub fn new(label: &'static str, basis: Basis) -> Arc<Self> {
        Arc::new(Self {
            label,
            basis,
            enabled: terminal_allowed(),
            style: Style::for_stderr(),
            state: Mutex::new(State {
                started: Instant::now(),
                last_draw: None,
                latest: None,
                visible: false,
            }),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Records a worker snapshot and redraws at a bounded rate.
    pub fn update(&self, progress: OperationProgress) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let mut state = self.lock();
        state.latest = Some(progress);
        let due = state
            .last_draw
            .is_none_or(|last| now.duration_since(last) >= DRAW_INTERVAL);
        if due {
            self.draw(&mut state, now, false, true);
        }
    }

    /// Leaves a final 100% summary line in the terminal history.
    pub fn finish(&self, success: bool) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let mut state = self.lock();
        if state.latest.is_some() {
            self.draw(&mut state, now, true, success);
            let _ignored = writeln!(io::stderr().lock());
            state.visible = false;
        }
    }

    /// Removes the active line before an operation error is printed.
    pub fn clear(&self) {
        if !self.enabled {
            return;
        }
        let mut state = self.lock();
        if state.visible {
            let _ignored = write!(io::stderr().lock(), "\r\x1b[2K");
            state.visible = false;
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the completion ratio is clamped to 0..=1 before conversion"
    )]
    fn draw(&self, state: &mut State, now: Instant, finished: bool, success: bool) {
        let Some(progress) = state.latest else {
            return;
        };
        let elapsed = now.duration_since(state.started);
        let ratio = if finished {
            1.0
        } else {
            completion_ratio(progress, self.basis)
        };
        let percent = (ratio * 100.0).floor() as u8;
        let marker = if finished && success {
            self.style.green("✓")
        } else if finished {
            self.style.red("✗")
        } else {
            let frame = (elapsed.as_millis() / DRAW_INTERVAL.as_millis()) as usize % SPINNER.len();
            self.style.cyan(SPINNER[frame])
        };
        let bar = progress_track(ratio);
        let bar = if finished && success {
            self.style.green(bar)
        } else if finished {
            self.style.red(bar)
        } else {
            self.style.cyan(bar)
        };
        let details = details(progress, ratio, elapsed, finished);
        let mut err = io::stderr().lock();
        // Autowrap is off (DECAWM) while the line is written: on a
        // narrow terminal the details clip at the right edge instead of
        // wrapping, and a wrapped line would leave its first physical
        // row behind, since `\x1b[2K` on the next redraw clears only
        // the row the cursor is on.
        let _ignored = write!(
            err,
            "\x1b[?7l\r\x1b[2K{marker} {:<8} {bar} {percent:>3}%  {details}\x1b[?7h",
            self.label
        );
        let _ignored = err.flush();
        state.last_draw = Some(now);
        state.visible = true;
    }
}

fn terminal_allowed() -> bool {
    io::stderr().is_terminal() && env::var_os("TERM").is_none_or(|term| term != "dumb")
}

/// Highest ratio an unfinished byte-based operation displays.
///
/// Verification bytes can complete before the last files do: corruption
/// analysis rereads a mismatched file after its bytes were counted by
/// the initial hash pass. A full bar would look done while analysis
/// still runs, so an incomplete file count holds the display just short.
const MAX_ACTIVE_RATIO: f64 = 0.99;

fn completion_ratio(progress: OperationProgress, basis: Basis) -> f64 {
    let bytes = fraction(progress.bytes_completed(), progress.total_bytes());
    let files = fraction(progress.files_completed(), progress.total_files());
    let ratio = match basis {
        Basis::Bytes => {
            let ratio = bytes.or(files);
            if files.is_some_and(|files| files < 1.0) {
                ratio.map(|ratio| ratio.min(MAX_ACTIVE_RATIO))
            } else {
                ratio
            }
        }
        Basis::AnyLimit => match (bytes, files) {
            (Some(bytes), Some(files)) => Some(bytes.max(files)),
            (bytes, files) => bytes.or(files),
        },
    };
    ratio.unwrap_or(0.0).clamp(0.0, 1.0)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "terminal percentages and ETAs need only display precision"
)]
fn fraction(completed: u64, total: Option<u64>) -> Option<f64> {
    total.map(|total| {
        if total == 0 {
            1.0
        } else {
            completed as f64 / total as f64
        }
    })
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "the clamped ratio maps into a fixed 16-column integer track"
)]
fn progress_track(ratio: f64) -> String {
    let completed = ((BAR_WIDTH as f64 * ratio).floor() as usize).min(BAR_WIDTH);
    if completed == BAR_WIDTH {
        return "━".repeat(BAR_WIDTH);
    }
    if completed == 0 {
        return "─".repeat(BAR_WIDTH);
    }
    format!(
        "{}╺{}",
        "━".repeat(completed.saturating_sub(1)),
        "─".repeat(BAR_WIDTH - completed)
    )
}

fn details(progress: OperationProgress, ratio: f64, elapsed: Duration, finished: bool) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push(match progress.total_bytes() {
        Some(total) => format!(
            "{} / {}",
            human_bytes(progress.bytes_completed()),
            human_bytes(total)
        ),
        None => format!("{} processed", human_bytes(progress.bytes_completed())),
    });
    parts.push(match progress.total_files() {
        Some(total) => format!("{} / {} files", progress.files_completed(), total),
        None => format!("{} files", progress.files_completed()),
    });

    let seconds = elapsed.as_secs_f64();
    if seconds >= 0.1 && progress.bytes_completed() > 0 {
        let rate = (u128::from(progress.bytes_completed()) * 1_000_000_000 / elapsed.as_nanos())
            .min(u128::from(u64::MAX));
        let rate = u64::try_from(rate).expect("the rate was clamped to the u64 range");
        parts.push(format!("{}/s", human_bytes(rate)));
    }
    if finished {
        parts.push(format_duration(elapsed));
    } else if ratio > 0.0 && ratio < 1.0 && seconds >= 0.1 {
        let remaining = elapsed.mul_f64((1.0 - ratio) / ratio);
        let remaining = if remaining < Duration::from_secs(1) {
            "<1s".to_owned()
        } else {
            format_duration(remaining)
        };
        parts.push(format!("ETA {remaining}"));
    } else {
        parts.push("ETA —".to_owned());
    }
    parts.join("  ")
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 5] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    let (unit, divisor) = UNITS
        .into_iter()
        .find(|(_unit, divisor)| bytes >= *divisor)
        .unwrap_or(("B", 1));
    if divisor == 1 {
        return format!("{bytes} {unit}");
    }
    let whole = bytes / divisor;
    if whole >= 100 {
        format!("{whole} {unit}")
    } else if whole >= 10 {
        let tenths = (u128::from(bytes) * 10 / u128::from(divisor)) % 10;
        format!("{whole}.{tenths} {unit}")
    } else {
        let hundredths = (u128::from(bytes) * 100 / u128::from(divisor)) % 100;
        format!("{whole}.{hundredths:02} {unit}")
    }
}

fn format_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        return "<1s".to_owned();
    }
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, (seconds / 60) % 60)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{format_duration, human_bytes, progress_track};

    #[test]
    fn byte_units_stay_compact() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(64 * 1024 * 1024), "64.0 MiB");
    }

    #[test]
    fn duration_uses_at_most_two_units() {
        assert_eq!(format_duration(Duration::from_millis(900)), "<1s");
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(format_duration(Duration::from_secs(7325)), "2h 02m");
    }

    #[test]
    fn progress_track_has_a_fixed_width() {
        for ratio in [0.0, 0.01, 0.5, 0.99, 1.0] {
            assert_eq!(progress_track(ratio).chars().count(), 16);
        }
    }
}
