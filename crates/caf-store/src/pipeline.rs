//! Bounded worker pipeline with deterministic in-order collection.
//!
//! [`run`] fans indexed tasks out to a fixed pool of worker threads and
//! hands each result to a collector callback in index order, regardless
//! of completion order. In-flight work is bounded: a worker claims an
//! index
//! only while it is within a fixed window of the collector, so buffered
//! results never grow with the total number of tasks. The first task
//! error in index order cancels the run — exactly the error a serial
//! sweep would have stopped at — and a worker panic resumes on the
//! calling thread, as it would have in a serial sweep. If the OS
//! refuses every worker thread, the run completes as exactly that
//! serial sweep on the calling thread; refusing only some narrows the
//! pool.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

/// Indices each worker may run ahead of the collector.
///
/// The claim window is this value times the worker count. A larger
/// window smooths over one slow task at the cost of more buffered
/// results; memory stays `O(jobs)` either way, never `O(tasks)`.
const WINDOW_PER_WORKER: usize = 4;

/// Runs `total` indexed tasks on `jobs` worker threads, delivering
/// results to `collect` in index order.
///
/// Each worker thread calls `make_worker` once and feeds the returned
/// closure claimed indices, so per-worker state (such as a reusable
/// read buffer) lives for the whole run. `collect` runs on the calling
/// thread. If the OS refuses every worker thread, the tasks run
/// serially on the calling thread instead.
///
/// # Errors
///
/// Returns the first task error in index order — the same error a
/// serial sweep of the tasks would have returned.
///
/// # Panics
///
/// Resumes a worker thread's panic on the calling thread once the
/// remaining workers have stopped.
pub(crate) fn run<T, E, W>(
    total: usize,
    jobs: NonZeroUsize,
    make_worker: impl Fn() -> W + Sync,
    mut collect: impl FnMut(T),
) -> Result<(), E>
where
    T: Send,
    E: Send,
    W: FnMut(usize) -> Result<T, E>,
{
    let jobs = jobs.get();
    let window = jobs.saturating_mul(WINDOW_PER_WORKER);
    let gate = Gate::new();
    // Results ride a bounded channel sized to the claim window, so a
    // send can only block while the collector is catching up.
    let (sender, receiver) = mpsc::sync_channel::<(usize, Result<T, E>)>(window);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(jobs);
        for _ in 0..jobs {
            let sender = sender.clone();
            let gate = &gate;
            let make_worker = &make_worker;
            let spawned = thread::Builder::new().spawn_scoped(scope, move || {
                let worked = panic::catch_unwind(AssertUnwindSafe(|| {
                    let mut work = make_worker();
                    while let Some(index) = gate.claim(total, window) {
                        let result = work(index);
                        let failed = result.is_err();
                        if sender.send((index, result)).is_err() {
                            return;
                        }
                        if failed {
                            // Unrecoverable: stop handing out indices now
                            // rather than when the collector reaches this
                            // result.
                            gate.cancel();
                            return;
                        }
                    }
                }));
                if let Err(payload) = worked {
                    // Cancel so siblings blocked in `Gate::claim` are not
                    // left waiting on a result that will never arrive.
                    // Cancelling takes the gate lock, which a destructor
                    // must not do, so the unwind is caught here and
                    // resumed unchanged once the gate is closed.
                    gate.cancel();
                    panic::resume_unwind(payload);
                }
            });
            match spawned {
                Ok(handle) => handles.push(handle),
                // The OS refused a thread; the workers that did start
                // keep the run correct with a narrower pool.
                Err(_refused) => break,
            }
        }
        drop(sender);

        if handles.is_empty() {
            // No worker could start at all: complete the run as a
            // serial sweep on this thread rather than reporting an
            // empty run as success.
            let mut work = make_worker();
            for index in 0..total {
                collect(work(index)?);
            }
            return Ok(());
        }

        // Collect in index order through a reorder buffer. The buffer
        // holds only in-flight results, which the claim window bounds.
        let mut pending: BTreeMap<usize, Result<T, E>> = BTreeMap::new();
        let mut next = 0_usize;
        let mut failure: Option<E> = None;
        for (index, result) in receiver {
            if failure.is_some() {
                // Already failed: drain so workers finish, discard.
                continue;
            }
            pending.insert(index, result);
            while let Some(result) = pending.remove(&next) {
                next += 1;
                match result {
                    Ok(value) => {
                        collect(value);
                        gate.collected_one();
                    }
                    Err(error) => {
                        gate.cancel();
                        failure = Some(error);
                        pending.clear();
                        break;
                    }
                }
            }
        }

        // Every worker has already exited here: the loop above ends only
        // once the last sender is dropped. A worker panic is a
        // programming error, so resume the unwind on this thread rather
        // than reporting it as a run outcome; the scope joins whatever
        // handles are left.
        for handle in handles {
            if let Err(payload) = handle.join() {
                panic::resume_unwind(payload);
            }
        }
        debug_assert!(
            failure.is_some() || next == total,
            "a claimed index produced no result",
        );
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    })
}

/// Hands out task indices while bounding how far claims may run ahead
/// of the collector.
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

struct GateState {
    /// The next index to hand to a worker.
    next_claim: usize,
    /// Results the collector has consumed, in index order.
    collected: usize,
    /// Set on task error, worker panic, or collector shutdown.
    cancelled: bool,
}

impl Gate {
    fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                next_claim: 0,
                collected: 0,
                cancelled: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        // The critical sections only move counters and cannot panic, so
        // poisoning can only come from an unrelated unwind crossing a
        // guard; the counters are still consistent, so keep going
        // instead of double-panicking while cancelling for a panicking
        // worker.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Claims the next index, blocking while the claim would run more
    /// than `window` ahead of the collector. Returns `None` when the
    /// indices are exhausted or the run is cancelled.
    fn claim(&self, total: usize, window: usize) -> Option<usize> {
        let mut state = self.lock();
        loop {
            if state.cancelled || state.next_claim >= total {
                return None;
            }
            if state.next_claim < state.collected.saturating_add(window) {
                let index = state.next_claim;
                state.next_claim += 1;
                return Some(index);
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn collected_one(&self) {
        self.lock().collected += 1;
        self.changed.notify_all();
    }

    fn cancel(&self) {
        self.lock().cancelled = true;
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::{WINDOW_PER_WORKER, run};

    fn jobs(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("the tests use positive worker counts")
    }

    /// Varied per-index sleeps scramble completion order; collection
    /// order must stay 0, 1, 2, …
    #[test]
    fn results_collect_in_index_order() {
        let mut collected = Vec::new();
        let result: Result<(), ()> = run(
            40,
            jobs(8),
            || {
                |index| {
                    thread::sleep(Duration::from_millis((index as u64 * 7) % 5));
                    Ok(index)
                }
            },
            |index| collected.push(index),
        );
        result.expect("the pipeline succeeds");
        assert_eq!(collected, (0..40).collect::<Vec<_>>());
    }

    /// A fast error at a later index must not shadow a slower error at
    /// an earlier index: the failure is the first error in index order,
    /// exactly as a serial sweep would report it.
    #[test]
    fn first_error_in_index_order_wins() {
        let mut collected = Vec::new();
        let result = run(
            40,
            jobs(8),
            || {
                |index| match index {
                    3 => {
                        thread::sleep(Duration::from_millis(30));
                        Err(format!("slow error at {index}"))
                    }
                    10 => Err(format!("fast error at {index}")),
                    _ => Ok(index),
                }
            },
            |index| collected.push(index),
        );
        let message = result.expect_err("expected a task failure");
        assert_eq!(message, "slow error at 3");
        assert_eq!(collected, vec![0, 1, 2]);
    }

    /// An error cancels the run: indices far past the failure are never
    /// claimed once the cancellation lands.
    #[test]
    fn an_error_cancels_remaining_claims() {
        let started = AtomicUsize::new(0);
        let result: Result<(), &str> = run(
            10_000,
            jobs(2),
            || {
                |index| {
                    started.fetch_add(1, Ordering::Relaxed);
                    if index == 0 { Err("boom") } else { Ok(index) }
                }
            },
            |_| {},
        );
        assert!(matches!(result, Err("boom")));
        // The exact count is timing-dependent, but cancellation plus
        // the claim window keep it far below the total.
        assert!(started.load(Ordering::Relaxed) < 1000);
    }

    /// A worker panic is a programming error, so it reaches the caller
    /// as a panic — payload intact — not as a run outcome.
    #[test]
    fn a_worker_panic_resumes_on_the_calling_thread() {
        let payload = panic::catch_unwind(AssertUnwindSafe(|| {
            let result: Result<(), ()> = run(
                20,
                jobs(4),
                || {
                    |index| {
                        assert!(index != 5, "worker bug");
                        Ok(index)
                    }
                },
                |_| {},
            );
            result
        }))
        .expect_err("the worker panic reaches the caller");
        let message = payload
            .downcast_ref::<&str>()
            .expect("the panic payload survives");
        assert_eq!(*message, "worker bug");
    }

    #[test]
    fn zero_tasks_complete_immediately() {
        let mut collected = Vec::new();
        let result: Result<(), ()> = run(
            0,
            jobs(4),
            || |index| Ok(index),
            |index| collected.push(index),
        );
        result.expect("the pipeline succeeds");
        assert!(collected.is_empty());
    }

    #[test]
    fn more_workers_than_tasks() {
        let mut collected = Vec::new();
        let result: Result<(), ()> = run(
            3,
            jobs(16),
            || |index| Ok(index),
            |index| collected.push(index),
        );
        result.expect("the pipeline succeeds");
        assert_eq!(collected, vec![0, 1, 2]);
    }

    /// While the collector is stuck behind one slow task, other workers
    /// may only run ahead by the claim window — never `O(total)`.
    #[test]
    fn the_claim_window_bounds_run_ahead() {
        let workers = jobs(2);
        let window = workers.get() * WINDOW_PER_WORKER;
        let finished_ahead = AtomicUsize::new(0);
        let observed = Mutex::new(None);
        let result: Result<(), ()> = run(
            500,
            workers,
            || {
                |index| {
                    if index == 0 {
                        thread::sleep(Duration::from_millis(50));
                        *observed.lock().expect("no panics hold this lock") =
                            Some(finished_ahead.load(Ordering::Relaxed));
                    } else {
                        finished_ahead.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(index)
                }
            },
            |_| {},
        );
        result.expect("the pipeline succeeds");
        let ahead = observed
            .lock()
            .expect("no panics hold this lock")
            .expect("task 0 records the run-ahead");
        assert!(
            ahead < window,
            "ran {ahead} tasks ahead, window is {window}"
        );
    }
}
