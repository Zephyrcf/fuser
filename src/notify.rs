#[allow(unused)]
use std::convert::TryInto;
#[allow(unused)]
use std::ffi::OsStr;
use std::io;

use crate::INodeNo;
use crate::Version;
use crate::channel::ChannelSender;
#[cfg(target_os = "linux")]
use crate::inflight::InflightJournal;
use crate::ll::Errno;
use crate::ll::ResponseErrno;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi::FUSE_EXPIRE_ONLY;
use crate::ll::fuse_abi::FUSE_KERNEL_MINOR_VERSION;
use crate::ll::fuse_abi::FUSE_KERNEL_VERSION;
use crate::ll::fuse_abi::FUSE_NOTIFY_INC_EPOCH_VERSION;
use crate::ll::fuse_abi::fuse_notify_code as notify_code;
use crate::ll::notify::Notification;
use crate::ll::reply::Response;
#[cfg(target_os = "linux")]
use crate::pause::SessionPauser;

/// How [`Notifier::recover_inflight`] unblocked the callers of the requests a dead
/// predecessor read but never answered.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflightRecovery {
    /// The kernel redelivers every such request itself, to be served normally; nothing
    /// was lost. Requests may reach the filesystem twice, marked with
    /// [`Request::is_resend`](crate::Request::is_resend).
    Resent,
    /// The kernel is too old to resend, so the journaled requests were answered with an
    /// error instead, this many of them still being open. The callers unblock and retry.
    ErroredOut(usize),
}

/// A handle to a pending `poll()` request.
#[derive(Copy, Clone, Debug)]
pub struct PollHandle(pub u64);

/// A [handle](PollHandle) to a pending `poll()` request coupled with notifier reference.
/// Can be saved and used to notify the kernel when a poll is ready.
#[derive(Clone)]
pub struct PollNotifier {
    handle: PollHandle,
    notifier: Notifier,
}

impl PollNotifier {
    pub(crate) fn new(
        cs: ChannelSender,
        kh: PollHandle,
        kernel_capabilities: InitFlags,
        kernel_abi: Option<Version>,
    ) -> Self {
        Self {
            handle: kh,
            notifier: Notifier::new(cs, kernel_capabilities, kernel_abi),
        }
    }

    /// Handle associated with this poll notifier.
    pub fn handle(&self) -> PollHandle {
        self.handle
    }

    /// Notify the kernel that the associated file handle is ready to be polled.
    /// # Errors
    /// Returns an error if the kernel rejects the notification.
    pub fn notify(self) -> io::Result<()> {
        self.notifier.poll(self.handle)
    }
}

impl std::fmt::Debug for PollNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PollHandle").field(&self.handle).finish()
    }
}

/// A handle by which the application can send notifications to the server
#[derive(Debug, Clone)]
pub struct Notifier {
    sender: ChannelSender,
    reply_senders: Vec<ChannelSender>,
    /// Everything the kernel advertised during init. Some notifications are only
    /// meaningful on a kernel that supports them, and the kernel reports success
    /// regardless, so they are refused here rather than silently doing something else
    kernel_capabilities: InitFlags,
    /// The ABI version the kernel offered during init, or `None` before init has run.
    /// Notifications added after a given version have no capability bit to key on, so the
    /// version is what says whether the kernel will understand them. This is what the kernel
    /// advertised, not what the connection settled on: see [`Notifier::negotiated_abi`]
    kernel_abi: Option<Version>,
    /// The workers and inflight journal of the session this notifier belongs
    /// to, if any: recovering the journal must not race with the workers.
    #[cfg(target_os = "linux")]
    pauser: Option<SessionPauser>,
    #[cfg(target_os = "linux")]
    journal: Option<InflightJournal>,
}

impl Notifier {
    pub(crate) fn new(
        cs: ChannelSender,
        kernel_capabilities: InitFlags,
        kernel_abi: Option<Version>,
    ) -> Self {
        Self {
            sender: cs,
            reply_senders: Vec::new(),
            kernel_capabilities,
            kernel_abi,
            #[cfg(target_os = "linux")]
            pauser: None,
            #[cfg(target_os = "linux")]
            journal: None,
        }
    }

    pub(crate) fn with_reply_senders(mut self, senders: Vec<ChannelSender>) -> Self {
        self.reply_senders = senders;
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_recovery(
        mut self,
        pauser: SessionPauser,
        journal: Option<InflightJournal>,
    ) -> Self {
        self.pauser = Some(pauser);
        self.journal = journal;
        self
    }

    /// Completes an outstanding request with `error`, identified by its id
    /// alone, on whichever of the session's devices read it. This lets a
    /// successor unblock the callers of requests a crashed predecessor read.
    ///
    /// # Errors
    /// Returns `ENOENT` if no device has the request in flight, i.e. it was
    /// already answered, or an error if the kernel rejects the reply.
    pub fn reply_error(&self, unique: crate::RequestId, error: Errno) -> io::Result<()> {
        ResponseErrno(error).with_iovec(unique, |iov| {
            for sender in std::iter::once(&self.sender).chain(&self.reply_senders) {
                match sender.send(iov) {
                    Err(err) if err.raw_os_error() == Some(libc::ENOENT) => continue,
                    result => return result,
                }
            }
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        })
    }

    /// Notify poll clients of I/O readiness
    /// # Errors
    /// Returns an error if the kernel rejects the notification.
    pub fn poll(&self, kh: PollHandle) -> io::Result<()> {
        let notif = Notification::new_poll(kh);
        self.send(notify_code::FUSE_POLL, &notif)
    }

    /// Invalidate the kernel cache for a given directory entry
    /// # Errors
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn inval_entry(&self, parent: INodeNo, name: &OsStr) -> io::Result<()> {
        let notif = Notification::new_inval_entry(parent, name, 0).map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_ENTRY, &notif)
    }

    /// Expire the kernel cache for a given directory entry, rather than invalidating it.
    ///
    /// The entry is marked for revalidation on next use instead of being forcibly
    /// detached, so anything mounted beneath it stays mounted. Use this in preference to
    /// [`inval_entry()`](Self::inval_entry) when the entry is merely believed to be stale
    /// rather than known to be gone.
    ///
    /// # Errors
    /// Returns `ENOTSUP` if the kernel did not advertise `InitFlags::FUSE_HAS_EXPIRE_ONLY`.
    /// Such a kernel reads the flag as the padding it used to be and invalidates the entry,
    /// detaching any submounts, while still reporting success, so this refuses to send
    /// rather than quietly doing the destructive thing this call exists to avoid.
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn expire_entry(&self, parent: INodeNo, name: &OsStr) -> io::Result<()> {
        if !self
            .kernel_capabilities
            .contains(InitFlags::FUSE_HAS_EXPIRE_ONLY)
        {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        let notif = Notification::new_inval_entry(parent, name, FUSE_EXPIRE_ONLY)
            .map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_ENTRY, &notif)
    }

    /// Invalidate every cached directory entry at once, by incrementing the connection's
    /// epoch.
    ///
    /// The kernel stamps each dentry with the epoch current when it was looked up, and
    /// treats one stamped with an older epoch as stale. Incrementing therefore invalidates
    /// the whole dentry and readdir cache in constant time, where
    /// [`inval_entry()`](Self::inval_entry) costs a notification per entry and needs the
    /// filesystem to know the names to begin with. That suits a backing store that has
    /// changed wholesale, or one whose changes cannot be enumerated.
    ///
    /// Invalidation is lazy, as with [`expire_entry()`](Self::expire_entry): entries are
    /// revalidated on next use rather than forcibly detached, so anything mounted beneath
    /// one stays mounted. A kernel configured with the `inval_wq` module parameter also
    /// prunes unused entries in the background.
    ///
    /// # Errors
    /// Returns `ENOTSUP` if the connection settled on an ABI older than 7.44, which has no
    /// case for this notification. Such a kernel does reject it, unlike the one
    /// [`expire_entry()`](Self::expire_entry) guards against, but only with an `EINVAL`
    /// that says nothing about why, and a caller holding a `Notifier` has no way to check
    /// the version for itself.
    /// Returns an error if the kernel rejects the notification.
    pub fn inc_epoch(&self) -> io::Result<()> {
        // None before init has run, which is also a connection nothing can be sent on yet
        if self
            .negotiated_abi()
            .is_none_or(|v| v < FUSE_NOTIFY_INC_EPOCH_VERSION)
        {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        let notif = Notification::new_bare();
        self.send(notify_code::FUSE_NOTIFY_INC_EPOCH, &notif)
    }

    /// Asks the kernel to deliver again every request it handed out but has not
    /// had answered, e.g. those a crashed predecessor read. They come back
    /// marked by [`Request::is_resend`](crate::Request::is_resend) and may have
    /// been acted on once already.
    ///
    /// # Errors
    /// Returns `ENOTSUP` if the kernel did not advertise
    /// `InitFlags::FUSE_HAS_RESEND` (kernel 6.9+), or an error if the kernel
    /// rejects the notification.
    pub fn resend(&self) -> io::Result<()> {
        if !self
            .kernel_capabilities
            .contains(InitFlags::FUSE_HAS_RESEND)
        {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        let notif = Notification::new_bare();
        self.send(notify_code::FUSE_NOTIFY_RESEND, &notif)
    }

    /// Unblocks the callers of every request a crashed predecessor read but
    /// never answered: asks the kernel to [`resend`](Self::resend) them where it
    /// can, and otherwise answers each id in the session's
    /// [`InflightJournal`](crate::InflightJournal) with `error`. The journal is
    /// cleared once that succeeds and kept on failure, so retrying is safe.
    ///
    /// With a journal attached, the session's workers must be parked, e.g. by
    /// [`Session::spawn_paused`](crate::Session::spawn_paused).
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::ResourceBusy`] if a journal is attached while the
    /// workers run, [`io::ErrorKind::InvalidInput`] if the kernel cannot resend
    /// and no journal is attached, or the error of a rejected notification or
    /// reply.
    #[cfg(target_os = "linux")]
    pub fn recover_inflight(&self, error: Errno) -> io::Result<InflightRecovery> {
        if self.journal.is_some()
            && self
                .pauser
                .as_ref()
                .is_some_and(|pauser| !pauser.workers_quiescent())
        {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "inflight recovery requires the session workers to be parked",
            ));
        }
        match self.resend() {
            Ok(()) => return Ok(InflightRecovery::Resent),
            Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => {}
            Err(e) => return Err(e),
        }
        let journal = self.journal.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "inflight recovery requires a journal when resend is unavailable",
            )
        })?;
        let mut open = 0;
        for unique in journal.pending_requests()? {
            match self.reply_error(unique, error) {
                Ok(()) => open += 1,
                // Answered by the predecessor but not struck before the crash
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        journal.clear();
        Ok(InflightRecovery::ErroredOut(open))
    }

    /// What the connection actually speaks: the lower of what the kernel offered during init
    /// and what this crate replied with.
    ///
    /// Both halves matter. The kernel dispatches a notification on its code alone, without
    /// consulting the version, so what it offered is what decides whether it has a case for
    /// one at all. But it records the replied version verbatim as the connection's, so
    /// sending something newer than that is out of protocol however tolerant the dispatch
    /// happens to be. Taking the lower keeps to both.
    fn negotiated_abi(&self) -> Option<Version> {
        self.kernel_abi.map(|kernel| {
            Version(
                kernel.0.min(FUSE_KERNEL_VERSION),
                kernel.1.min(FUSE_KERNEL_MINOR_VERSION),
            )
        })
    }

    /// Invalidate the kernel cache for a given inode (metadata and
    /// data in the given range)
    /// # Errors
    /// Returns an error if the kernel rejects the notification.
    pub fn inval_inode(&self, ino: INodeNo, offset: i64, len: i64) -> io::Result<()> {
        let notif = Notification::new_inval_inode(ino, offset, len);
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_INODE, &notif)
    }

    /// Update the kernel's cached copy of a given inode's data
    /// # Errors
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn store(&self, ino: INodeNo, offset: u64, data: &[u8]) -> io::Result<()> {
        let notif = Notification::new_store(ino, offset, data).map_err(Self::too_big_err)?;
        // Not strictly an invalidate, but the inode we're operating
        // on may have been evicted anyway, so treat is as such
        self.send_inval(notify_code::FUSE_NOTIFY_STORE, &notif)
    }

    /// Invalidate the kernel cache for a given directory entry and inform
    /// inotify watchers of a file deletion.
    /// # Errors
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn delete(&self, parent: INodeNo, child: INodeNo, name: &OsStr) -> io::Result<()> {
        let notif = Notification::new_delete(parent, child, name).map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_DELETE, &notif)
    }

    #[allow(unused)]
    fn send_inval(&self, code: notify_code, notification: &Notification<'_>) -> io::Result<()> {
        match self.send(code, notification) {
            // ENOENT is harmless for an invalidation (the
            // kernel may have already dropped the cached
            // entry on its own anyway), so ignore it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            x => x,
        }
    }

    fn send(&self, code: notify_code, notification: &Notification<'_>) -> io::Result<()> {
        notification
            .with_iovec(code, |iov| self.sender.send(iov))
            .map_err(Self::too_big_err)?
    }

    /// Create an error for indicating when a notification message
    /// would exceed the capacity that its length descriptor field is
    /// capable of encoding.
    fn too_big_err(tfie: std::num::TryFromIntError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("Data too large: {tfie:?}"))
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::sync::Arc;

    use super::*;
    use crate::channel::Channel;
    use crate::dev_fuse::DevFuse;

    fn notifier(kernel_capabilities: InitFlags) -> Notifier {
        notifier_with_abi(kernel_capabilities, Some(FUSE_NOTIFY_INC_EPOCH_VERSION))
    }

    fn notifier_with_abi(kernel_capabilities: InitFlags, kernel_abi: Option<Version>) -> Notifier {
        // /dev/null stands in for the FUSE device: the cases below either return before
        // sending, or send a notification whose fate is not what is under test
        let dev = Arc::new(DevFuse(
            File::options().write(true).open("/dev/null").unwrap(),
        ));
        Notifier::new(Channel::new(dev).sender(), kernel_capabilities, kernel_abi)
    }

    /// A kernel that never advertised expiring would invalidate the entry and report
    /// success, so the request is refused here instead of being sent.
    #[test]
    fn expire_entry_refused_without_kernel_support() {
        let err = notifier(InitFlags::empty())
            .expire_entry(INodeNo::ROOT, OsStr::new("x"))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTSUP));
    }

    #[test]
    fn expire_entry_sent_with_kernel_support() {
        notifier(InitFlags::FUSE_HAS_EXPIRE_ONLY)
            .expire_entry(INodeNo::ROOT, OsStr::new("x"))
            .unwrap();
    }

    /// A kernel that never advertised resending has no handler for the notification and
    /// answers `EINVAL`, so the request is refused here with something more telling.
    #[test]
    fn resend_refused_without_kernel_support() {
        let err = notifier(InitFlags::empty()).resend().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTSUP));
    }

    #[test]
    fn resend_sent_with_kernel_support() {
        notifier(InitFlags::FUSE_HAS_RESEND).resend().unwrap();
    }

    /// Attaches `journal` as a session with no running workers would.
    #[cfg(target_os = "linux")]
    fn with_journal(notifier: Notifier, journal: &InflightJournal) -> Notifier {
        notifier.with_recovery(SessionPauser::new().unwrap(), Some(journal.clone()))
    }

    /// A kernel that resends handles everything itself: no journal is needed.
    #[test]
    #[cfg(target_os = "linux")]
    fn recover_inflight_resends_where_the_kernel_can() {
        let recovery = notifier(InitFlags::FUSE_HAS_RESEND)
            .recover_inflight(Errno::EIO)
            .unwrap();
        assert_eq!(recovery, InflightRecovery::Resent);
    }

    /// Without resend the journal is what there is; nothing journaled means nothing
    /// to answer, and the count says so.
    #[test]
    #[cfg(target_os = "linux")]
    fn recover_inflight_falls_back_to_the_journal() {
        let journal = InflightJournal::create().unwrap();
        let recovery = with_journal(notifier(InitFlags::empty()), &journal)
            .recover_inflight(Errno::EIO)
            .unwrap();
        assert_eq!(recovery, InflightRecovery::ErroredOut(0));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn recover_inflight_requires_a_journal_without_resend() {
        let error = notifier(InitFlags::empty())
            .recover_inflight(Errno::EIO)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn recover_inflight_refuses_a_journal_while_workers_run() {
        let pauser = SessionPauser::new().unwrap();
        pauser.register_workers(1);
        let journal = InflightJournal::create().unwrap();
        let error = notifier(InitFlags::empty())
            .with_recovery(pauser, Some(journal))
            .recover_inflight(Errno::EIO)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ResourceBusy);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn recovery_keeps_the_journal_on_reply_failure() {
        let journal = InflightJournal::create().unwrap();
        journal.reserve().unwrap().publish(crate::RequestId(42));
        let full = Channel::new(Arc::new(DevFuse(
            File::options().write(true).open("/dev/full").unwrap(),
        )));
        let notifier = Notifier::new(full.sender(), InitFlags::empty(), Some(Version(7, 31)))
            .with_reply_senders(vec![notifier(InitFlags::empty()).sender]);
        let error = with_journal(notifier, &journal)
            .recover_inflight(Errno::EIO)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(journal.pending_requests().unwrap(), [crate::RequestId(42)]);
    }

    /// Invalidating is unconditional: it does not depend on the expire capability.
    #[test]
    fn inval_entry_needs_no_capability() {
        notifier(InitFlags::empty())
            .inval_entry(INodeNo::ROOT, OsStr::new("x"))
            .unwrap();
    }

    /// Incrementing the epoch keys on the ABI version rather than a capability, since the
    /// kernel advertises no bit for it.
    #[test]
    fn inc_epoch_refused_below_its_abi_version() {
        for abi in [None, Some(Version(7, 43)), Some(Version(7, 6))] {
            let err = notifier_with_abi(InitFlags::all(), abi)
                .inc_epoch()
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::ENOTSUP), "{abi:?}");
        }
    }

    /// Both sides have to reach 7.44, so what this crate replies with decides it just as much
    /// as what the kernel offers. On macOS that is 7.19 and never enough, which is the answer
    /// there however new the kernel is.
    #[test]
    fn inc_epoch_sent_only_when_this_crate_reports_its_abi_version() {
        let reported = Version(FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
        let this_crate_reaches_it = reported >= FUSE_NOTIFY_INC_EPOCH_VERSION;
        for abi in [Version(7, 44), Version(7, 45), Version(7, 99)] {
            let sent = notifier_with_abi(InitFlags::empty(), Some(abi))
                .inc_epoch()
                .is_ok();
            assert_eq!(sent, this_crate_reaches_it, "{abi:?}");
        }
    }

    /// A kernel offering more than this crate replies with does not make the extra versions
    /// part of the connection, since the kernel records the reply as its own.
    #[test]
    fn negotiated_abi_is_capped_by_what_this_crate_replies_with() {
        let notifier = notifier_with_abi(InitFlags::empty(), Some(Version(7, 99)));
        assert_eq!(
            notifier.negotiated_abi(),
            Some(Version(FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION))
        );
        // ...and a kernel offering less caps it the other way round. 7.8 is below what every
        // platform replies with, macOS included, so this does not depend on which one it is
        let notifier = notifier_with_abi(InitFlags::empty(), Some(Version(7, 8)));
        assert_eq!(notifier.negotiated_abi(), Some(Version(7, 8)));
    }
}
