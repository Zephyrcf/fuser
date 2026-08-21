//! Pause/resume control for session worker loops.
//!
//! This module supports zero-interruption hot upgrades of a FUSE daemon. It
//! lets a daemon stop every worker loop at a request boundary - each request
//! that was read from `/dev/fuse` is answered before its worker parks - hand
//! the live fd to a successor process, and still resume serving on the same
//! fds if the takeover fails.

use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::fcntl::fcntl;
use parking_lot::Condvar;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Running,
    Paused,
    Exiting,
}

struct PauseState {
    mode: RunMode,
    /// Live worker loops attached to the session.
    workers: usize,
    /// Workers currently parked on the condvar because the mode is `Paused`.
    parked: usize,
}

struct PauseInner {
    state: Mutex<PauseState>,
    condvar: Condvar,
    /// Read end of the wakeup pipe, polled by workers next to the fuse fd.
    wake_rx: OwnedFd,
    /// Write end of the wakeup pipe, written on pause/exit.
    wake_tx: OwnedFd,
}

/// A cloneable handle that pauses, resumes, or ends the worker loops of one
/// session. Obtained from [`crate::Session::pauser`] or
/// [`crate::BackgroundSession::pauser`].
#[derive(Clone)]
pub struct SessionPauser {
    inner: Arc<PauseInner>,
}

impl std::fmt::Debug for SessionPauser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.state.lock();
        f.debug_struct("SessionPauser")
            .field("mode", &state.mode)
            .field("workers", &state.workers)
            .field("parked", &state.parked)
            .finish()
    }
}

/// Marks the fuse channel fd non-blocking so a worker that lost a poll race
/// gets `EAGAIN` instead of blocking in `read(2)` past a pause request.
pub(crate) fn set_channel_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

impl SessionPauser {
    pub(crate) fn new() -> io::Result<Self> {
        // O_CLOEXEC is set atomically: a hot upgrade forks a successor, and
        // the wakeup pipe must never leak into it.
        let (wake_rx, wake_tx) = nix::unistd::pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
        Ok(Self {
            inner: Arc::new(PauseInner {
                state: Mutex::new(PauseState {
                    mode: RunMode::Running,
                    workers: 0,
                    parked: 0,
                }),
                condvar: Condvar::new(),
                wake_rx,
                wake_tx,
            }),
        })
    }

    /// Stops every worker loop at a request boundary: workers that are
    /// dispatching finish and answer their current request, then park; no
    /// further request is read from the kernel until [`resume`] or the fd is
    /// adopted by a successor. Blocks until all workers are parked.
    ///
    /// On timeout the session is put back into the running state and an
    /// error is returned, so a stalled pause can never wedge the mount.
    ///
    /// [`resume`]: SessionPauser::resume
    pub fn pause(&self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock();
        match state.mode {
            RunMode::Paused => {
                return Err(io::Error::other("the session is already paused"));
            }
            RunMode::Exiting => {
                return Err(io::Error::other("the session is shutting down"));
            }
            RunMode::Running => {}
        }
        if state.workers == 0 {
            return Err(io::Error::other("the session has no live workers"));
        }
        state.mode = RunMode::Paused;
        self.wake();
        while state.parked < state.workers {
            if self
                .inner
                .condvar
                .wait_until(&mut state, deadline)
                .timed_out()
                && state.parked < state.workers
            {
                state.mode = RunMode::Running;
                self.drain_wake();
                self.inner.condvar.notify_all();
                return Err(io::Error::other(
                    "timed out waiting for the session workers to pause",
                ));
            }
        }
        if state.workers == 0 {
            state.mode = RunMode::Running;
            self.drain_wake();
            return Err(io::Error::other("the session workers exited while pausing"));
        }
        Ok(())
    }

    /// Restarts the paused worker loops on the same fds. A no-op unless the
    /// session is paused.
    pub fn resume(&self) {
        let mut state = self.inner.state.lock();
        if state.mode == RunMode::Paused {
            self.drain_wake();
            state.mode = RunMode::Running;
            self.inner.condvar.notify_all();
        }
    }

    /// Makes every worker loop return at the next request boundary, ending
    /// the session run without unmounting anything.
    pub fn exit(&self) {
        let mut state = self.inner.state.lock();
        if state.mode != RunMode::Exiting {
            state.mode = RunMode::Exiting;
            self.wake();
            self.inner.condvar.notify_all();
        }
    }

    /// True while the session is paused.
    pub fn is_paused(&self) -> bool {
        self.inner.state.lock().mode == RunMode::Paused
    }

    /// Puts the session into the paused state before any worker exists, so
    /// workers spawned afterwards park at the top of their first loop
    /// iteration, before ever reading from the fuse fd. The counterpart of
    /// [`pause`](SessionPauser::pause) for a session born paused; see
    /// [`crate::Session::spawn_paused`].
    pub(crate) fn start_paused(&self) {
        self.inner.state.lock().mode = RunMode::Paused;
    }

    /// Waits until exactly `expected` workers are registered and every one
    /// of them is parked. For a session started paused, where
    /// [`pause`](SessionPauser::pause) cannot be used: the workers do not
    /// exist yet when the mode is set, so this is the half of it that waits.
    ///
    /// # Errors
    /// Returns an error if a worker exits instead of parking, if the session
    /// leaves the paused state, or on timeout. The mode is left untouched:
    /// the caller decides between resuming and exiting.
    pub(crate) fn wait_parked(&self, expected: usize, timeout: Duration) -> io::Result<()> {
        if expected == 0 {
            return Err(io::Error::other("the session would have no workers"));
        }
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock();
        loop {
            if state.mode != RunMode::Paused {
                return Err(io::Error::other("the session is no longer paused"));
            }
            // Workers register in one batch, so any other nonzero count means
            // one of them exited rather than parking
            if state.workers != 0 && state.workers != expected {
                return Err(io::Error::other("a session worker exited while parking"));
            }
            if state.workers == expected && state.parked == expected {
                return Ok(());
            }
            if self
                .inner
                .condvar
                .wait_until(&mut state, deadline)
                .timed_out()
            {
                if state.mode == RunMode::Paused
                    && state.workers == expected
                    && state.parked == expected
                {
                    return Ok(());
                }
                return Err(io::Error::other(
                    "timed out waiting for the session workers to park",
                ));
            }
        }
    }

    /// Registers `count` worker loops before they are spawned, so a pause
    /// issued right after spawn already knows how many workers to wait for.
    pub(crate) fn register_workers(&self, count: usize) {
        let mut state = self.inner.state.lock();
        state.workers += count;
    }

    /// Deregistration guard for one worker loop; dropping it (worker exit)
    /// updates the bookkeeping and wakes any pause() waiter.
    pub(crate) fn worker_exit_guard(&self) -> WorkerExitGuard {
        WorkerExitGuard {
            pauser: self.clone(),
        }
    }

    /// Called by workers at the top of every loop iteration. Parks while the
    /// session is paused. Returns `false` when the worker should return.
    pub(crate) fn wait_ready(&self) -> bool {
        let mut state = self.inner.state.lock();
        loop {
            match state.mode {
                RunMode::Running => return true,
                RunMode::Exiting => return false,
                RunMode::Paused => {
                    state.parked += 1;
                    self.inner.condvar.notify_all();
                    self.inner.condvar.wait(&mut state);
                    state.parked -= 1;
                }
            }
        }
    }

    /// The fd workers poll next to the fuse fd for pause/exit wakeups.
    pub(crate) fn wake_fd(&self) -> BorrowedFd<'_> {
        self.inner.wake_rx.as_fd()
    }

    fn wake(&self) {
        // EAGAIN on a full pipe is fine: the wakeup is already pending.
        let _ = nix::unistd::write(self.inner.wake_tx.as_fd(), &[1u8]);
    }

    fn drain_wake(&self) {
        let mut buf = [0u8; 64];
        while let Ok(n) = nix::unistd::read(&self.inner.wake_rx, &mut buf) {
            if n == 0 {
                break;
            }
        }
    }
}

pub(crate) struct WorkerExitGuard {
    pauser: SessionPauser,
}

impl Drop for WorkerExitGuard {
    fn drop(&mut self) {
        let mut state = self.pauser.inner.state.lock();
        state.workers = state.workers.saturating_sub(1);
        self.pauser.inner.condvar.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    /// Spawn `n` fake workers that count loop iterations gated on
    /// `wait_ready`, mirroring the structure of the session event loop.
    fn spawn_workers(
        pauser: &SessionPauser,
        n: usize,
    ) -> (Arc<AtomicUsize>, Vec<thread::JoinHandle<()>>) {
        pauser.register_workers(n);
        let iterations = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..n {
            let pauser = pauser.clone();
            let iterations = Arc::clone(&iterations);
            threads.push(thread::spawn(move || {
                let _guard = pauser.worker_exit_guard();
                while pauser.wait_ready() {
                    iterations.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(1));
                }
            }));
        }
        (iterations, threads)
    }

    #[test]
    fn pause_parks_all_workers_and_resume_restarts_them() {
        let pauser = SessionPauser::new().unwrap();
        let (iterations, threads) = spawn_workers(&pauser, 3);

        pauser.pause(Duration::from_secs(5)).unwrap();
        assert!(pauser.is_paused());
        let frozen = iterations.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(iterations.load(Ordering::SeqCst), frozen);

        pauser.resume();
        assert!(!pauser.is_paused());
        let deadline = Instant::now() + Duration::from_secs(5);
        while iterations.load(Ordering::SeqCst) == frozen {
            assert!(Instant::now() < deadline, "workers never resumed");
            thread::sleep(Duration::from_millis(1));
        }

        pauser.exit();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn exit_while_paused_releases_the_workers() {
        let pauser = SessionPauser::new().unwrap();
        let (_iterations, threads) = spawn_workers(&pauser, 2);
        pauser.pause(Duration::from_secs(5)).unwrap();
        pauser.exit();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn double_pause_is_refused() {
        let pauser = SessionPauser::new().unwrap();
        let (_iterations, threads) = spawn_workers(&pauser, 1);
        pauser.pause(Duration::from_secs(5)).unwrap();
        assert!(pauser.pause(Duration::from_secs(1)).is_err());
        pauser.exit();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn pause_without_workers_is_refused() {
        let pauser = SessionPauser::new().unwrap();
        assert!(pauser.pause(Duration::from_millis(100)).is_err());
        assert!(!pauser.is_paused());
    }

    /// A session started paused parks its workers on their first iteration:
    /// none of them runs the loop body even once until the resume.
    #[test]
    fn start_paused_parks_workers_before_their_first_iteration() {
        let pauser = SessionPauser::new().unwrap();
        pauser.start_paused();
        let (iterations, threads) = spawn_workers(&pauser, 3);
        pauser.wait_parked(3, Duration::from_secs(5)).unwrap();
        assert!(pauser.is_paused());
        assert_eq!(iterations.load(Ordering::SeqCst), 0);

        pauser.resume();
        let deadline = Instant::now() + Duration::from_secs(5);
        while iterations.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "workers never started");
            thread::sleep(Duration::from_millis(1));
        }

        pauser.exit();
        for t in threads {
            t.join().unwrap();
        }
    }

    /// A worker that exits instead of parking fails the wait rather than
    /// letting it time out, and a count that can never be reached does too.
    #[test]
    fn wait_parked_notices_a_missing_worker() {
        let pauser = SessionPauser::new().unwrap();
        pauser.start_paused();
        assert!(pauser.wait_parked(0, Duration::from_millis(100)).is_err());
        // One worker registered but never parking: only the timeout says so
        pauser.register_workers(1);
        assert!(pauser.wait_parked(1, Duration::from_millis(100)).is_err());
        // A worker exiting is noticed immediately, not by timeout
        pauser.register_workers(1);
        drop(pauser.worker_exit_guard());
        assert!(pauser.wait_parked(2, Duration::from_secs(60)).is_err());
    }

    #[test]
    fn timed_out_pause_reverts_to_running() {
        let pauser = SessionPauser::new().unwrap();
        // A registered worker that never calls wait_ready models a wedged
        // dispatch: the pause must give up and put the session back into the
        // running state.
        pauser.register_workers(1);
        assert!(pauser.pause(Duration::from_millis(100)).is_err());
        assert!(!pauser.is_paused());
    }
}
