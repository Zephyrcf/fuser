//! Pause/resume control for session worker loops.
//!
//! This module supports zero-interruption hot upgrades of a FUSE daemon. It
//! lets a daemon stop every worker loop at a request boundary - each request
//! that was read from `/dev/fuse` is answered before its worker parks - hand
//! the live fd to a successor process, and still resume serving on the same
//! fds if the takeover fails.
//!
//! Linux only: elsewhere the worker loops block in `read(2)` and cannot be paused.

use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use log::warn;
use nix::errno::Errno;
use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::fcntl::fcntl;
use parking_lot::Condvar;
use parking_lot::Mutex;
use parking_lot::MutexGuard;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Running,
    Paused,
    Exiting,
}

#[derive(Debug)]
struct PauseState {
    mode: RunMode,
    /// Live worker loops attached to the session.
    workers: usize,
    /// Workers currently parked on the condvar because the mode is `Paused`.
    parked: usize,
}

#[derive(Debug)]
struct PauseInner {
    state: Mutex<PauseState>,
    condvar: Condvar,
    /// Mirrors `state.mode == Running`, so a running worker passes each
    /// request boundary without taking the lock.
    running: AtomicBool,
    /// Read end of the wakeup pipe, polled by workers next to the fuse fd.
    wake_rx: OwnedFd,
    /// Write end of the wakeup pipe, written on pause/exit.
    wake_tx: OwnedFd,
}

/// A cloneable handle that pauses, resumes, or ends the worker loops of one
/// session. Obtained from [`crate::Session::pauser`] or
/// [`crate::BackgroundSession::pauser`].
#[derive(Clone, Debug)]
pub struct SessionPauser {
    inner: Arc<PauseInner>,
}

/// Marks the fuse channel fd non-blocking so a worker that lost a race for a
/// request gets `EAGAIN` instead of blocking in `read(2)` past a pause request.
///
/// The flag lives on the open file description, so it also applies to every
/// duplicate of the descriptor, including those held for failover.
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
                running: AtomicBool::new(true),
                wake_rx,
                wake_tx,
            }),
        })
    }

    /// Stops every worker loop at a request boundary: each worker answers the
    /// request it is dispatching, then parks without reading another. Blocks
    /// until all workers are parked.
    ///
    /// On failure, including a timeout, the session is put back into the
    /// running state, so a stalled pause can never wedge the mount.
    pub fn pause(&self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock();
        match state.mode {
            RunMode::Paused => return Err(io::Error::other("the session is already paused")),
            RunMode::Exiting => return Err(io::Error::other("the session is shutting down")),
            RunMode::Running => {}
        }
        let workers = state.workers;
        if workers == 0 {
            return Err(io::Error::other("the session has no live workers"));
        }
        self.set_mode(&mut state, RunMode::Paused);
        self.wake();
        let result = self.wait_all_parked(&mut state, workers, deadline);
        if result.is_err() {
            self.resume_locked(&mut state);
        }
        result
    }

    /// Restarts the paused worker loops on the same fds. A no-op unless the
    /// session is paused.
    pub fn resume(&self) {
        self.resume_locked(&mut self.inner.state.lock());
    }

    /// Makes every worker loop return at the next request boundary, ending
    /// the session run without unmounting anything.
    pub fn exit(&self) {
        let mut state = self.inner.state.lock();
        if state.mode != RunMode::Exiting {
            self.set_mode(&mut state, RunMode::Exiting);
            self.wake();
            self.inner.condvar.notify_all();
        }
    }

    /// Pauses a session whose workers are not spawned yet, so they park
    /// before their first read. See [`crate::Session::spawn_paused`].
    pub(crate) fn start_paused(&self) {
        self.set_mode(&mut self.inner.state.lock(), RunMode::Paused);
    }

    /// Waits until the `expected` workers of a session started paused are
    /// all parked. Unlike [`pause`](SessionPauser::pause), a failure leaves
    /// the mode alone: the caller decides between resuming and exiting.
    pub(crate) fn wait_parked(&self, expected: usize, timeout: Duration) -> io::Result<()> {
        let mut state = self.inner.state.lock();
        self.wait_all_parked(&mut state, expected, Instant::now() + timeout)
    }

    /// Waits until all `expected` workers are parked. Fails if the session
    /// leaves the paused state, a worker exits instead, or `deadline` passes.
    fn wait_all_parked(
        &self,
        state: &mut MutexGuard<'_, PauseState>,
        expected: usize,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut timed_out = false;
        loop {
            if state.mode != RunMode::Paused {
                return Err(io::Error::other("the session is no longer paused"));
            }
            if state.workers != expected {
                return Err(io::Error::other("a session worker exited while parking"));
            }
            if state.parked == expected {
                return Ok(());
            }
            if timed_out {
                return Err(io::Error::other(
                    "timed out waiting for the session workers to park",
                ));
            }
            timed_out = self.inner.condvar.wait_until(state, deadline).timed_out();
        }
    }

    fn set_mode(&self, state: &mut PauseState, mode: RunMode) {
        state.mode = mode;
        self.inner
            .running
            .store(mode == RunMode::Running, Ordering::Release);
    }

    fn resume_locked(&self, state: &mut PauseState) {
        if state.mode == RunMode::Paused {
            self.drain_wake();
            self.set_mode(state, RunMode::Running);
            self.inner.condvar.notify_all();
        }
    }

    /// Registers `count` worker loops before they are spawned, so a pause
    /// issued right after spawn already knows how many workers to wait for.
    pub(crate) fn register_workers(&self, count: usize) {
        let mut state = self.inner.state.lock();
        state.workers += count;
    }

    /// Undoes [`register_workers`](SessionPauser::register_workers) for
    /// workers that were never spawned.
    pub(crate) fn unregister_workers(&self, count: usize) {
        let mut state = self.inner.state.lock();
        state.workers = state.workers.saturating_sub(count);
        self.inner.condvar.notify_all();
    }

    /// Returns whether no worker of this session can be reading or answering
    /// a request: either none is running, or all of them are parked.
    pub(crate) fn workers_quiescent(&self) -> bool {
        let state = self.inner.state.lock();
        state.workers == 0 || (state.mode == RunMode::Paused && state.parked == state.workers)
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
        if self.inner.running.load(Ordering::Acquire) {
            return true;
        }
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

    /// Creates a waiter for one worker that blocks until `channel` has a
    /// request or a pause/exit wakeup arrives.
    pub(crate) fn request_waiter<'a>(
        &'a self,
        channel: BorrowedFd<'a>,
    ) -> io::Result<RequestWaiter<'a>> {
        RequestWaiter::new(channel, self.inner.wake_rx.as_fd())
    }

    fn wake(&self) {
        match nix::unistd::write(self.inner.wake_tx.as_fd(), &[1u8]) {
            // A full pipe already holds a pending wakeup
            Ok(_) | Err(Errno::EAGAIN) => {}
            Err(err) => warn!("failed to wake the session workers: {err}"),
        }
    }

    fn drain_wake(&self) {
        let mut buf = [0u8; 64];
        loop {
            match nix::unistd::read(&self.inner.wake_rx, &mut buf) {
                Ok(0) | Err(Errno::EAGAIN) => return,
                Ok(_) | Err(Errno::EINTR) => {}
                Err(err) => {
                    warn!("failed to drain the session wakeup pipe: {err}");
                    return;
                }
            }
        }
    }
}

/// Blocks one worker until its channel is readable or the session is woken.
///
/// The channel is registered with `EPOLLEXCLUSIVE`, so a new request wakes
/// one idle worker rather than every worker sharing the connection. The
/// wakeup pipe is registered normally so that pause and exit reach all.
pub(crate) struct RequestWaiter<'a> {
    epoll: nix::sys::epoll::Epoll,
    _fds: std::marker::PhantomData<BorrowedFd<'a>>,
}

impl<'a> RequestWaiter<'a> {
    fn new(channel: BorrowedFd<'a>, wake: BorrowedFd<'a>) -> io::Result<Self> {
        use nix::sys::epoll::Epoll;
        use nix::sys::epoll::EpollCreateFlags;
        use nix::sys::epoll::EpollEvent;
        use nix::sys::epoll::EpollFlags;

        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        epoll.add(
            channel,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLEXCLUSIVE, 0),
        )?;
        epoll.add(wake, EpollEvent::new(EpollFlags::EPOLLIN, 0))?;
        Ok(Self {
            epoll,
            _fds: std::marker::PhantomData,
        })
    }

    /// Blocks until the channel is readable or a wakeup is pending.
    pub(crate) fn wait(&self) -> io::Result<()> {
        use nix::sys::epoll::EpollEvent;
        use nix::sys::epoll::EpollTimeout;

        let mut events = [EpollEvent::empty(); 2];
        match self.epoll.wait(&mut events, EpollTimeout::NONE) {
            Ok(_) | Err(Errno::EINTR) => Ok(()),
            Err(err) => Err(err.into()),
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

    fn mode(pauser: &SessionPauser) -> RunMode {
        pauser.inner.state.lock().mode
    }

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
            let iterations = iterations.clone();
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
        assert_eq!(mode(&pauser), RunMode::Paused);
        let frozen = iterations.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(iterations.load(Ordering::SeqCst), frozen);

        pauser.resume();
        assert_eq!(mode(&pauser), RunMode::Running);
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
        assert_eq!(
            pauser
                .pause(Duration::from_secs(1))
                .unwrap_err()
                .to_string(),
            "the session is already paused"
        );
        pauser.exit();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn pause_without_workers_is_refused() {
        let pauser = SessionPauser::new().unwrap();
        assert_eq!(
            pauser
                .pause(Duration::from_millis(100))
                .unwrap_err()
                .to_string(),
            "the session has no live workers"
        );
        assert_eq!(mode(&pauser), RunMode::Running);
    }

    /// A session started paused parks its workers on their first iteration:
    /// none of them runs the loop body even once until the resume.
    #[test]
    fn start_paused_parks_workers_before_their_first_iteration() {
        let pauser = SessionPauser::new().unwrap();
        pauser.start_paused();
        let (iterations, threads) = spawn_workers(&pauser, 3);
        pauser.wait_parked(3, Duration::from_secs(5)).unwrap();
        assert_eq!(mode(&pauser), RunMode::Paused);
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
    /// letting it time out.
    #[test]
    fn wait_parked_notices_a_missing_worker() {
        let pauser = SessionPauser::new().unwrap();
        pauser.start_paused();
        let message = |result: io::Result<()>| result.unwrap_err().to_string();
        // One worker registered but never parking: only the timeout says so
        pauser.register_workers(1);
        assert_eq!(
            message(pauser.wait_parked(1, Duration::from_millis(100))),
            "timed out waiting for the session workers to park"
        );
        // A worker exiting is noticed immediately, not by timeout
        pauser.register_workers(1);
        drop(pauser.worker_exit_guard());
        assert_eq!(
            message(pauser.wait_parked(2, Duration::from_secs(60))),
            "a session worker exited while parking"
        );
    }

    #[test]
    fn timed_out_pause_reverts_to_running() {
        let pauser = SessionPauser::new().unwrap();
        // A registered worker that never calls wait_ready models a wedged
        // dispatch: the pause must give up and put the session back into the
        // running state.
        pauser.register_workers(1);
        assert_eq!(
            pauser
                .pause(Duration::from_millis(100))
                .unwrap_err()
                .to_string(),
            "timed out waiting for the session workers to park"
        );
        assert_eq!(mode(&pauser), RunMode::Running);
    }

    #[test]
    fn workers_are_quiescent_only_when_absent_or_all_parked() {
        let pauser = SessionPauser::new().unwrap();
        assert!(pauser.workers_quiescent());
        let (_iterations, threads) = spawn_workers(&pauser, 2);
        assert!(!pauser.workers_quiescent());
        pauser.pause(Duration::from_secs(5)).unwrap();
        assert!(pauser.workers_quiescent());
        pauser.exit();
        for t in threads {
            t.join().unwrap();
        }
        assert!(pauser.workers_quiescent());
    }
}
