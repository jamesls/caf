//! Worker pool with deterministic in-order collection.
//!
//! [`run`] fans indexed tasks out to a fixed pool of threads, the calling
//! thread among them, and hands each result to a collector callback in
//! index order, regardless of completion order. Claims never wait for the
//! collector: a slow task holds back only collection, so the other workers
//! keep claiming and their results wait in a reorder buffer until it
//! finishes. The first task error in index order cancels the run —
//! exactly the error a serial sweep would have stopped at — and a worker
//! panic resumes on the calling thread, as it would have in a serial
//! sweep. If the OS refuses every worker thread, the calling thread runs
//! every task itself, which is exactly that serial sweep; refusing only
//! some narrows the pool.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

/// Runs `total` indexed tasks on `jobs` threads, delivering results to
/// `collect` in index order.
///
/// The calling thread is one of the `jobs` workers, so the budget hides
/// no extra coordinator thread. Each worker calls `make_worker` once and
/// feeds the returned closure claimed indices, so per-worker state (such
/// as a reusable read buffer) lives for the whole run. `collect` runs on
/// the calling thread, between its own tasks and after them.
///
/// Results that finish ahead of a slower, earlier task are buffered until
/// it completes, so a single long task never idles the other workers. The
/// buffer can hold up to `total` results; callers that keep every result
/// anyway, as verification does, pay no extra memory order for it.
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
    let claims = Claims::new(total);
    let (sender, receiver) = mpsc::channel::<(usize, Result<T, E>)>();
    let mut order = InOrder::new();

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(jobs.get() - 1);
        for _ in 1..jobs.get() {
            let sender = sender.clone();
            let claims = &claims;
            let make_worker = &make_worker;
            let spawned = thread::Builder::new().spawn_scoped(scope, move || {
                let worked = panic::catch_unwind(AssertUnwindSafe(|| {
                    let mut work = make_worker();
                    while let Some(index) = claims.claim() {
                        let result = work(index);
                        if result.is_err() {
                            // Unrecoverable: stop handing out indices now
                            // rather than when the collector reaches this
                            // result.
                            claims.cancel();
                        }
                        if sender.send((index, result)).is_err() {
                            return;
                        }
                    }
                }));
                if let Err(payload) = worked {
                    // Cancel so siblings stop claiming, then resume the
                    // unwind unchanged for the calling thread to join.
                    claims.cancel();
                    panic::resume_unwind(payload);
                }
            });
            match spawned {
                Ok(handle) => handles.push(handle),
                // The OS refused a thread; the workers that did start,
                // and the calling thread, keep the run correct.
                Err(_refused) => break,
            }
        }
        drop(sender);

        // The calling thread works too, folding in whatever the other
        // workers finished between its own tasks. Its receiver never
        // parks while it has work, so senders rarely need to wake it.
        let worked = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut work = make_worker();
            while let Some(index) = claims.claim() {
                let result = work(index);
                if result.is_err() {
                    claims.cancel();
                }
                order.accept(index, result, &mut collect);
                for (index, result) in receiver.try_iter() {
                    order.accept(index, result, &mut collect);
                }
            }
        }));
        if let Err(payload) = worked {
            claims.cancel();
            panic::resume_unwind(payload);
        }
        // The loop ends once every worker has exited and dropped its
        // sender.
        for (index, result) in &receiver {
            order.accept(index, result, &mut collect);
        }

        // A worker panic is a programming error, so resume the unwind on
        // this thread rather than reporting it as a run outcome; the
        // scope joins whatever handles are left.
        for handle in handles {
            if let Err(payload) = handle.join() {
                panic::resume_unwind(payload);
            }
        }
        order.finish(total)
    })
}

/// Hands out task indices in ascending order until they run out or the
/// run is cancelled.
///
/// Claims are ascending, so when a task fails every lower index has
/// already been claimed and will still report: the collector can always
/// find the first error in index order.
struct Claims {
    next: AtomicUsize,
    total: usize,
    cancelled: AtomicBool,
}

impl Claims {
    fn new(total: usize) -> Self {
        Self {
            next: AtomicUsize::new(0),
            total,
            cancelled: AtomicBool::new(false),
        }
    }

    /// Claims the next index, or returns `None` when the indices are
    /// exhausted or the run is cancelled.
    fn claim(&self) -> Option<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return None;
        }
        // Each worker overshoots `total` at most once before it stops,
        // so the counter cannot wrap.
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        (index < self.total).then_some(index)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// Reorders results into index order and records the first failure.
struct InOrder<T, E> {
    /// Results that finished ahead of `next`.
    pending: BTreeMap<usize, Result<T, E>>,
    /// The next index to hand to the collector.
    next: usize,
    failure: Option<E>,
}

impl<T, E> InOrder<T, E> {
    fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            next: 0,
            failure: None,
        }
    }

    /// Accepts one result and collects every result now in order. After
    /// a failure, later results are discarded so workers can finish.
    fn accept(&mut self, index: usize, result: Result<T, E>, collect: &mut impl FnMut(T)) {
        if self.failure.is_some() {
            return;
        }
        self.pending.insert(index, result);
        while let Some(result) = self.pending.remove(&self.next) {
            self.next += 1;
            match result {
                Ok(value) => collect(value),
                Err(error) => {
                    self.failure = Some(error);
                    self.pending.clear();
                    return;
                }
            }
        }
    }

    fn finish(self, total: usize) -> Result<(), E> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        debug_assert_eq!(self.next, total, "a claimed index produced no result");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::run;

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
                    if index == 0 {
                        return Err("boom");
                    }
                    // Slow enough that a stalled cancellation would
                    // have to lose a full second to reach the bound.
                    thread::sleep(Duration::from_millis(1));
                    Ok(index)
                }
            },
            |_| {},
        );
        assert!(matches!(result, Err("boom")));
        // The exact count is timing-dependent, but cancellation keeps it
        // far below the total.
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
        assert_eq!(collected, [] as [usize; 0]);
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

    /// A slow first task holds back only collection: while it runs, the
    /// other worker claims and finishes every later task, and the
    /// results still collect in index order.
    #[test]
    fn a_slow_task_does_not_hold_back_other_workers() {
        const TOTAL: usize = 500;
        let finished_ahead = AtomicUsize::new(0);
        let observed = Mutex::new(None);
        let mut collected = Vec::new();
        let result: Result<(), ()> = run(
            TOTAL,
            jobs(2),
            || {
                |index| {
                    if index == 0 {
                        // The deadline turns a stalled pool into a
                        // failure instead of a hang.
                        let deadline = Instant::now() + Duration::from_secs(10);
                        while finished_ahead.load(Ordering::Relaxed) < TOTAL - 1
                            && Instant::now() < deadline
                        {
                            thread::sleep(Duration::from_millis(1));
                        }
                        *observed.lock().expect("no panics hold this lock") =
                            Some(finished_ahead.load(Ordering::Relaxed));
                    } else {
                        finished_ahead.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(index)
                }
            },
            |index| collected.push(index),
        );
        result.expect("the pipeline succeeds");
        let ahead = observed
            .lock()
            .expect("no panics hold this lock")
            .expect("task 0 records the run-ahead");
        assert_eq!(ahead, TOTAL - 1);
        assert_eq!(collected, (0..TOTAL).collect::<Vec<_>>());
    }
}
