//! A process-shared journal of requests read from `/dev/fuse` but not yet answered.
//!
//! Each slot holds one atomic state word and the request unique. The state word
//! packs a tag (empty, reserved or inflight) in its low bits and a generation
//! above them; every reservation bumps the generation, so a completion that
//! raced with recovery and slot reuse fails its compare-exchange instead of
//! erasing another request's entry.
//!
//! Other targets get the uninhabited stand-ins of `inflight_stub.rs`, which must
//! offer the same crate-internal API as this module.

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use log::debug;
use nix::errno::Errno;
use nix::fcntl::FcntlArg;
use nix::fcntl::SealFlag;
use nix::fcntl::fcntl;
use nix::sys::memfd::MFdFlags;
use nix::sys::memfd::memfd_create;
use nix::sys::mman::MapFlags;
use nix::sys::mman::ProtFlags;
use nix::sys::mman::mmap;
use nix::sys::mman::munmap;
use nix::sys::stat::fstat;
use nix::sys::uio::pread;
use nix::sys::uio::pwrite;
use nix::unistd::ftruncate;

use crate::RequestId;
use crate::channel::Channel;
use crate::ll::fuse_abi::fuse_in_header;

const JOURNAL_MAGIC: [u8; 8] = *b"FUSRIFL\0";
const JOURNAL_VERSION: u32 = 1;
/// Magic, version and capacity; the slots follow.
const HEADER_LEN: usize = 16;
const DEFAULT_CAPACITY: usize = 65_536;
const MAX_CAPACITY: usize = 1_048_576;
const UNIQUE_LEN: usize = mem::size_of::<u64>();

const TAG_BITS: u32 = 2;
const TAG_MASK: u64 = (1 << TAG_BITS) - 1;
const TAG_EMPTY: u64 = 0;
const TAG_RESERVED: u64 = 1;
const TAG_INFLIGHT: u64 = 2;

fn required_seals() -> SealFlag {
    SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_SEAL
}

/// Returns `word` with its tag replaced and its generation kept.
fn retag(word: u64, tag: u64) -> u64 {
    (word & !TAG_MASK) | tag
}

#[repr(C)]
struct JournalSlot {
    state: AtomicU64,
    unique: UnsafeCell<[u8; UNIQUE_LEN]>,
}

// SAFETY: `unique` is written only by the worker holding the slot reserved,
// and published to other threads with a release store of the state word.
// Readers load the state with acquire ordering first. Recovery reads a
// reserved slot only once its writer process has exited.
unsafe impl Sync for JournalSlot {}

/// A shared mapping of the journal file, unmapped on drop.
struct Mapping {
    ptr: NonNull<c_void>,
    len: NonZeroUsize,
}

impl Mapping {
    fn new(fd: &OwnedFd, len: usize) -> io::Result<Self> {
        let len = NonZeroUsize::new(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty journal"))?;
        // SAFETY: a fresh shared mapping chosen by the kernel aliases no Rust
        // object; the file length was validated against `len` by the caller.
        let ptr = unsafe {
            mmap(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                fd,
                0,
            )
        }?;
        Ok(Self { ptr, len })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping was created by `Mapping::new` with this length,
        // and no slot reference outlives the `JournalInner` owning it.
        let result = unsafe { munmap(self.ptr, self.len.get()) };
        debug_assert_eq!(result, Ok(()));
    }
}

// SAFETY: the mapping holds only plain header bytes and `JournalSlot`s,
// whose shared access is synchronized as described on `JournalSlot`.
unsafe impl Send for Mapping {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for Mapping {}

struct JournalInner {
    fd: OwnedFd,
    mapping: Mapping,
    capacity: usize,
    next_slot: AtomicUsize,
}

/// A process-shared record of requests read from a FUSE connection but not yet answered.
///
/// The journal is backed by an anonymous file descriptor so an external failover holder can
/// retain it alongside the live `/dev/fuse` descriptor. Importing that descriptor maps the
/// same request state in a successor process.
#[derive(Clone)]
pub struct InflightJournal {
    inner: Arc<JournalInner>,
}

impl fmt::Debug for InflightJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InflightJournal")
            .field("capacity", &self.inner.capacity)
            .finish_non_exhaustive()
    }
}

impl AsFd for InflightJournal {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.fd.as_fd()
    }
}

impl InflightJournal {
    /// Creates an empty journal suitable for sharing with a failover holder.
    ///
    /// # Errors
    /// Returns an error if the anonymous backing file cannot be created, sized, or mapped.
    pub fn create() -> io::Result<Self> {
        Self::create_with_capacity(DEFAULT_CAPACITY)
    }

    /// Creates an empty journal with room for `capacity` concurrent requests.
    fn create_with_capacity(capacity: usize) -> io::Result<Self> {
        let len = mapping_len(capacity)?;
        let fd = memfd_create(
            c"fuser-inflight",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )?;
        ftruncate(&fd, file_offset(len)?)?;
        // A fresh file reads as zeros, which is an empty slot of generation 0
        let header = encode_header(capacity);
        if pwrite(&fd, &header, 0)? != header.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short inflight journal header write",
            ));
        }
        fcntl(&fd, FcntlArg::F_ADD_SEALS(required_seals()))?;
        Self::map(fd, capacity, len)
    }

    /// Imports a journal descriptor received from another process.
    ///
    /// # Errors
    /// Returns an error if the descriptor does not contain a supported journal or cannot be
    /// mapped read-write.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        validate_seals(&fd)?;
        let capacity = read_header(&fd)?;
        let len = mapping_len(capacity)?;
        let actual_len = fstat(&fd)?.st_size;
        if actual_len != file_offset(len)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("inflight journal length is {actual_len}, expected {len}"),
            ));
        }
        Self::map(fd, capacity, len)
    }

    fn map(fd: OwnedFd, capacity: usize, len: usize) -> io::Result<Self> {
        let mapping = Mapping::new(&fd, len)?;
        Ok(Self {
            inner: Arc::new(JournalInner {
                fd,
                mapping,
                capacity,
                next_slot: AtomicUsize::new(0),
            }),
        })
    }

    /// Duplicates the backing descriptor for transfer to another process.
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be duplicated.
    pub fn try_clone_fd(&self) -> io::Result<OwnedFd> {
        self.inner.fd.try_clone()
    }

    /// Returns the ids of the requests read but not yet answered.
    ///
    /// A worker reserves its slot before `read(2)`, and the kernel writes the
    /// request id straight into it, so a request whose reader died before
    /// publishing the slot is still listed. A reservation still holding a zero
    /// id never consumed a request and is skipped.
    ///
    /// # Errors
    /// Returns an error if a slot holds an invalid state.
    pub fn pending_requests(&self) -> io::Result<Vec<RequestId>> {
        let mut pending = Vec::new();
        for slot in self.slots() {
            if slot_tag(slot)? == TAG_EMPTY {
                continue;
            }
            let unique = slot_request_id(slot);
            if unique.0 != 0 {
                pending.push(unique);
            }
        }
        Ok(pending)
    }

    fn slots(&self) -> &[JournalSlot] {
        // SAFETY: the mapping is `HEADER_LEN + capacity * size_of::<JournalSlot>()`
        // bytes long (checked against the file size on import), page aligned, and
        // lives as long as `self.inner`. `JournalSlot` is `repr(C)` with only
        // atomics and bytes, so any bit pattern written by another process is a
        // valid value.
        unsafe {
            std::slice::from_raw_parts(
                self.inner
                    .mapping
                    .ptr
                    .as_ptr()
                    .cast::<u8>()
                    .add(HEADER_LEN)
                    .cast::<JournalSlot>(),
                self.inner.capacity,
            )
        }
    }

    fn slot(&self, index: usize) -> &JournalSlot {
        &self.slots()[index]
    }

    /// Claims an empty slot for the next `read(2)` of one worker.
    pub(crate) fn reserve(&self) -> io::Result<InflightReservation> {
        let start = self.inner.next_slot.fetch_add(1, Ordering::Relaxed) % self.inner.capacity;
        for offset in 0..self.inner.capacity {
            let index = (start + offset) % self.inner.capacity;
            let slot = self.slot(index);
            let current = slot.state.load(Ordering::Relaxed);
            if current & TAG_MASK != TAG_EMPTY {
                continue;
            }
            let reserved = retag(current.wrapping_add(1 << TAG_BITS), TAG_RESERVED);
            if slot
                .state
                .compare_exchange(current, reserved, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // SAFETY: the successful compare-exchange gives this worker
                // exclusive write access to `unique` until it publishes.
                unsafe {
                    *slot.unique.get() = [0; UNIQUE_LEN];
                }
                return Ok(InflightReservation {
                    journal: self.clone(),
                    index,
                    word: reserved,
                    published: false,
                });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "inflight journal is full",
        ))
    }

    /// Empties slot `index` unless recovery already cleared or reused it.
    fn release(&self, index: usize, word: u64) {
        if self
            .slot(index)
            .state
            .compare_exchange(
                word,
                retag(word, TAG_EMPTY),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            debug!("inflight slot was already cleared by recovery");
        }
    }

    /// Empties every slot, keeping generations so stale completions cannot match.
    ///
    /// Only call this while no worker of any process attached to the journal
    /// is between reserving a slot and publishing it.
    pub(crate) fn clear(&self) {
        for slot in self.slots() {
            slot.state.fetch_and(!TAG_MASK, Ordering::AcqRel);
        }
    }
}

/// A slot claimed for one `read(2)`; released on drop unless published.
#[derive(Debug)]
pub(crate) struct InflightReservation {
    journal: InflightJournal,
    index: usize,
    word: u64,
    published: bool,
}

impl InflightReservation {
    /// Reads one request from `channel` into `buffer`, with the kernel writing
    /// the request unique straight into this slot: a crash right after the
    /// read still leaves the id for recovery.
    pub(crate) fn receive(&mut self, channel: &Channel, buffer: &mut [u8]) -> nix::Result<usize> {
        const UNIQUE_OFFSET: usize = mem::offset_of!(fuse_in_header, unique);
        const AFTER_UNIQUE: usize = UNIQUE_OFFSET + UNIQUE_LEN;
        if buffer.len() < AFTER_UNIQUE {
            return Err(Errno::EINVAL);
        }
        // Only raw pointers reach the slot: a reader of the shared mapping may
        // look at it during the read, so no reference to it may exist.
        let unique = self.journal.slot(self.index).unique.get().cast::<u8>();
        let (prefix, rest) = buffer.split_at_mut(UNIQUE_OFFSET);
        let suffix = &mut rest[UNIQUE_LEN..];
        let iov = [
            libc::iovec {
                iov_base: prefix.as_mut_ptr().cast(),
                iov_len: prefix.len(),
            },
            libc::iovec {
                iov_base: unique.cast(),
                iov_len: UNIQUE_LEN,
            },
            libc::iovec {
                iov_base: suffix.as_mut_ptr().cast(),
                iov_len: suffix.len(),
            },
        ];
        // SAFETY: every iovec points to writable memory of its length: two
        // disjoint parts of `buffer`, and the unique of the slot this
        // reservation alone writes.
        let size = unsafe {
            libc::readv(
                channel.as_fd().as_raw_fd(),
                iov.as_ptr(),
                iov.len() as libc::c_int,
            )
        };
        let size = Errno::result(size)? as usize;
        // SAFETY: as above; concurrent readers only read the slot.
        unsafe {
            std::ptr::copy_nonoverlapping(
                unique,
                buffer[UNIQUE_OFFSET..AFTER_UNIQUE].as_mut_ptr(),
                UNIQUE_LEN,
            );
        }
        Ok(size)
    }

    /// Marks the slot inflight under `unique` until the reply reaches the kernel.
    pub(crate) fn publish(mut self, unique: RequestId) -> InflightRequest {
        let slot = self.journal.slot(self.index);
        // SAFETY: the slot is still reserved by this worker.
        unsafe {
            *slot.unique.get() = unique.0.to_ne_bytes();
        }
        let word = retag(self.word, TAG_INFLIGHT);
        slot.state.store(word, Ordering::Release);
        self.published = true;
        InflightRequest {
            journal: self.journal.clone(),
            index: self.index,
            word,
        }
    }
}

impl Drop for InflightReservation {
    fn drop(&mut self) {
        if !self.published {
            self.journal.release(self.index, self.word);
        }
    }
}

/// A published journal entry, removed once the request's reply is accepted.
#[derive(Clone, Debug)]
pub(crate) struct InflightRequest {
    journal: InflightJournal,
    index: usize,
    word: u64,
}

impl InflightRequest {
    /// Removes the entry unless recovery already cleared or reused the slot.
    pub(crate) fn complete(&self) {
        self.journal.release(self.index, self.word);
    }
}

fn slot_tag(slot: &JournalSlot) -> io::Result<u64> {
    match slot.state.load(Ordering::Acquire) & TAG_MASK {
        tag @ (TAG_EMPTY | TAG_RESERVED | TAG_INFLIGHT) => Ok(tag),
        tag => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid inflight journal slot tag {tag}"),
        )),
    }
}

fn slot_request_id(slot: &JournalSlot) -> RequestId {
    // SAFETY: the pointer is valid and aligned. A concurrent writer can only
    // be a worker that reserved the slot after this load observed it; a
    // volatile read then returns some byte pattern, which is a valid u64.
    let bytes = unsafe { std::ptr::read_volatile(slot.unique.get()) };
    RequestId(u64::from_ne_bytes(bytes))
}

fn mapping_len(capacity: usize) -> io::Result<usize> {
    if capacity == 0 || capacity > MAX_CAPACITY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid inflight journal capacity {capacity}"),
        ));
    }
    mem::size_of::<JournalSlot>()
        .checked_mul(capacity)
        .and_then(|slots| slots.checked_add(HEADER_LEN))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "journal size overflow"))
}

fn file_offset(len: usize) -> io::Result<libc::off_t> {
    libc::off_t::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "journal size overflow"))
}

fn encode_header(capacity: usize) -> [u8; HEADER_LEN] {
    let mut header = [0; HEADER_LEN];
    header[..8].copy_from_slice(&JOURNAL_MAGIC);
    header[8..12].copy_from_slice(&JOURNAL_VERSION.to_ne_bytes());
    // mapping_len() bounds the capacity by MAX_CAPACITY, well within u32
    header[12..].copy_from_slice(&(capacity as u32).to_ne_bytes());
    header
}

/// Reads and validates the header, returning the journal capacity.
fn read_header(fd: &OwnedFd) -> io::Result<usize> {
    let mut header = [0; HEADER_LEN];
    if pread(fd, &mut header, 0)? != HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "inflight journal header is truncated",
        ));
    }
    if header[..8] != JOURNAL_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid inflight journal magic",
        ));
    }
    let version = u32::from_ne_bytes(header[8..12].try_into().expect("4 bytes"));
    if version != JOURNAL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported inflight journal version {version}"),
        ));
    }
    let capacity = u32::from_ne_bytes(header[12..].try_into().expect("4 bytes"));
    Ok(capacity as usize)
}

fn validate_seals(fd: &OwnedFd) -> io::Result<()> {
    let seals = fcntl(fd, FcntlArg::F_GET_SEALS).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("inflight journal is not a sealed anonymous file: {err}"),
        )
    })?;
    if !SealFlag::from_bits_retain(seals).contains(required_seals()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inflight journal size is not sealed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIQUE: RequestId = RequestId(0x1234_5678_9abc_def0);

    #[test]
    fn recovery_skips_a_reservation_that_consumed_no_request() {
        let journal = InflightJournal::create_with_capacity(1).unwrap();
        mem::forget(journal.reserve().unwrap());

        assert_eq!(journal.pending_requests().unwrap(), []);
    }

    /// The read itself puts the unique in shared memory, so a reader dying
    /// before it publishes the slot still leaves the request recoverable.
    #[test]
    fn recovery_keeps_the_unique_of_an_unpublished_read() {
        use std::fs::File;
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        use crate::dev_fuse::DevFuse;
        use crate::ll::fuse_abi::fuse_opcode;

        let (mut kernel, daemon) = UnixStream::pair().unwrap();
        let channel = Channel::new(Arc::new(DevFuse(File::from(OwnedFd::from(daemon)))));
        const LEN: usize = mem::size_of::<fuse_in_header>();
        let mut request = [0u8; LEN];
        request[..4].copy_from_slice(&(LEN as u32).to_ne_bytes());
        request[4..8].copy_from_slice(&(fuse_opcode::FUSE_LOOKUP as u32).to_ne_bytes());
        request[8..16].copy_from_slice(&UNIQUE.0.to_ne_bytes());
        kernel.write_all(&request).unwrap();

        let journal = InflightJournal::create_with_capacity(1).unwrap();
        let mut reservation = journal.reserve().unwrap();
        let mut received = [0u8; LEN];
        assert_eq!(reservation.receive(&channel, &mut received).unwrap(), LEN);
        assert_eq!(received, request);
        mem::forget(reservation);

        assert_eq!(journal.pending_requests().unwrap(), [UNIQUE]);
    }

    #[test]
    fn a_stale_completion_leaves_a_reused_slot_alone() {
        let journal = InflightJournal::create_with_capacity(1).unwrap();
        let stale = journal.reserve().unwrap().publish(UNIQUE);
        journal.clear();
        let _current = journal.reserve().unwrap().publish(UNIQUE);

        stale.complete();
        assert_eq!(journal.pending_requests().unwrap(), [UNIQUE]);
    }

    #[test]
    fn import_rejects_an_unsealed_file() {
        let fd = memfd_create(c"unsealed", MFdFlags::MFD_CLOEXEC).unwrap();
        assert_eq!(
            InflightJournal::from_fd(fd).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

/// Journal tracking and recovery driven through a session, with one end of a
/// socket pair standing in for `/dev/fuse`.
#[cfg(test)]
mod session_tests {
    use std::ffi::OsStr;
    use std::io::Read;
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::InflightJournal;
    use crate::BackgroundSession;
    use crate::Config;
    use crate::Errno;
    use crate::Filesystem;
    use crate::INodeNo;
    use crate::InflightRecovery;
    use crate::InitFlags;
    use crate::InitState;
    use crate::ReplyEntry;
    use crate::Request;
    use crate::RequestId;
    use crate::Session;
    use crate::SessionACL;
    use crate::Version;
    use crate::ll::fuse_abi::fuse_forget_in;
    use crate::ll::fuse_abi::fuse_in_header;
    use crate::ll::fuse_abi::fuse_notify_code;
    use crate::ll::fuse_abi::fuse_opcode;
    use crate::ll::fuse_abi::fuse_out_header;

    const IN_HEADER_LEN: usize = size_of::<fuse_in_header>();
    const OUT_HEADER_LEN: usize = size_of::<fuse_out_header>();

    struct BlockingLookup {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Filesystem for BlockingLookup {
        fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            reply.error(Errno::ENOENT);
        }
    }

    struct SignalingForget {
        completed: mpsc::SyncSender<()>,
    }

    impl Filesystem for SignalingForget {
        fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {
            self.completed.send(()).unwrap();
        }
    }

    struct FailingReply {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        attempted: mpsc::SyncSender<()>,
    }

    impl Filesystem for FailingReply {
        fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            reply.error(Errno::ENOENT);
            self.attempted.send(()).unwrap();
        }
    }

    #[derive(Debug)]
    struct DroppedReply;

    impl Filesystem for DroppedReply {
        fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
            drop(reply);
        }
    }

    #[test]
    fn session_tracks_a_request_until_its_reply_reaches_the_kernel() {
        let (daemon, mut kernel) = UnixStream::pair().unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let (background, imported) = spawn_journaled(
            BlockingLookup {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            },
            daemon,
        );

        const UNIQUE: u64 = 0x1234;
        kernel.write_all(&lookup_request(UNIQUE, b"held")).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(imported.pending_requests().unwrap(), [RequestId(UNIQUE)]);

        release_tx.send(()).unwrap();
        assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
        wait_until_empty(&imported);

        destroy_and_join(&mut kernel, background, 0x1235);
    }

    #[test]
    fn recovery_flushes_and_removes_every_journaled_request() {
        let (daemon, mut kernel) = UnixStream::pair().unwrap();
        let successor_fd = OwnedFd::from(daemon.try_clone().unwrap());
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let (predecessor, imported) = spawn_journaled(
            BlockingLookup {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            },
            daemon,
        );

        const UNIQUE: u64 = 0x2234;
        kernel.write_all(&lookup_request(UNIQUE, b"held")).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let mut successor = adopt(DroppedReply, successor_fd, init(31, InitFlags::empty()));
        successor.set_inflight_journal(imported.clone());
        let successor = successor.spawn_paused(Duration::from_secs(5)).unwrap();
        assert_eq!(
            successor.notifier().recover_inflight(Errno::EIO).unwrap(),
            InflightRecovery::ErroredOut(1)
        );
        assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::EIO));
        wait_until_empty(&imported);
        successor.pauser().exit();
        successor.join().unwrap();

        // The stale answer of the predecessor leaves the cleared journal empty
        release_tx.send(()).unwrap();
        assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
        wait_until_empty(&imported);
        destroy_and_join(&mut kernel, predecessor, 0x2235);
    }

    /// A journal attached without knowing the kernel stays unused where the kernel can
    /// resend, and recovery then needs no parked workers.
    #[test]
    fn resend_kernel_ignores_the_journal() {
        let journal = InflightJournal::create().unwrap();
        let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
        let (daemon, mut kernel) = UnixStream::pair().unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let mut session = adopt(
            BlockingLookup {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            },
            OwnedFd::from(daemon),
            init(40, InitFlags::FUSE_HAS_RESEND),
        );
        session.set_inflight_journal(journal);
        let background = session.spawn().unwrap();

        const UNIQUE: u64 = 0x2a34;
        kernel
            .write_all(&lookup_request(UNIQUE, b"resend"))
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(imported.pending_requests().unwrap(), []);

        assert_eq!(
            background.notifier().recover_inflight(Errno::EIO).unwrap(),
            InflightRecovery::Resent
        );
        assert_eq!(
            read_reply(&mut kernel),
            (0, fuse_notify_code::FUSE_NOTIFY_RESEND as i32)
        );

        release_tx.send(()).unwrap();
        assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
        destroy_and_join(&mut kernel, background, 0x2a35);
    }

    #[test]
    fn cloned_devices_survive_repeated_handoffs() {
        let config = Config {
            n_threads: Some(3),
            clone_fd: true,
            ..Config::default()
        };
        let mut kernels = Vec::new();
        let mut devices = Vec::new();
        for _ in 0..3 {
            let (daemon, kernel) = UnixStream::pair().unwrap();
            kernel
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            kernels.push(kernel);
            devices.push(OwnedFd::from(daemon));
        }
        let adopt = |devices| {
            Session::from_initialized_fds(
                DroppedReply,
                devices,
                SessionACL::All,
                config.clone(),
                init(40, InitFlags::FUSE_HAS_RESEND),
            )
            .unwrap()
        };

        let mut predecessor = adopt(devices);
        let saved = predecessor.try_clone_fds().unwrap();
        assert_eq!(saved.len(), 3);
        drop(predecessor);

        let mut middle = adopt(saved);
        let saved = middle.try_clone_fds().unwrap();
        assert_eq!(saved.len(), 3);
        let background = middle.spawn_paused(Duration::from_secs(5)).unwrap();
        background.pauser().exit();
        background.join().unwrap();

        let successor = adopt(saved).spawn_paused(Duration::from_secs(5)).unwrap();
        assert_eq!(
            successor.notifier().recover_inflight(Errno::EIO).unwrap(),
            InflightRecovery::Resent
        );
        // A connection-wide resend is sent only on the main device.
        assert_eq!(
            read_reply(&mut kernels[0]),
            (0, fuse_notify_code::FUSE_NOTIFY_RESEND as i32)
        );
        successor.pauser().resume();
        for (index, kernel) in kernels.iter_mut().enumerate() {
            let unique = 0x7000 + index as u64;
            kernel
                .write_all(&lookup_request(unique, b"restored"))
                .unwrap();
            assert_eq!(read_reply(kernel), (unique, -libc::EIO));
        }
        successor.pauser().exit();
        successor.join().unwrap();
    }

    #[test]
    fn shared_workers_export_only_the_main_device() {
        let config = Config {
            n_threads: Some(3),
            ..Config::default()
        };
        let (daemon, _kernel) = UnixStream::pair().unwrap();
        let mut session = Session::from_initialized_fd(
            DroppedReply,
            OwnedFd::from(daemon),
            SessionACL::All,
            config,
            init(31, InitFlags::empty()),
        )
        .unwrap();
        assert_eq!(session.try_clone_fds().unwrap().len(), 1);
    }

    #[test]
    fn adoption_rejects_missing_or_extra_devices() {
        for (clone_fd, count) in [(true, 0), (true, 1), (true, 3), (false, 2)] {
            let config = Config {
                n_threads: Some(2),
                clone_fd,
                ..Config::default()
            };
            let devices = (0..count)
                .map(|_| OwnedFd::from(UnixStream::pair().unwrap().0))
                .collect();
            let error = Session::from_initialized_fds(
                DroppedReply,
                devices,
                SessionACL::All,
                config,
                init(31, InitFlags::empty()),
            )
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn no_reply_requests_leave_no_journal_entry() {
        let (daemon, mut kernel) = UnixStream::pair().unwrap();
        let (completed_tx, completed_rx) = mpsc::sync_channel(0);
        let (background, imported) = spawn_journaled(
            SignalingForget {
                completed: completed_tx,
            },
            daemon,
        );

        kernel.write_all(&forget_request(0x3234, 1)).unwrap();
        completed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        wait_until_empty(&imported);

        destroy_and_join(&mut kernel, background, 0x3235);
    }

    #[test]
    fn failed_reply_keeps_the_request_journaled() {
        let (daemon, kernel) = UnixStream::pair().unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let (attempted_tx, attempted_rx) = mpsc::sync_channel(0);
        let (background, imported) = spawn_journaled(
            FailingReply {
                entered: entered_tx,
                release: Mutex::new(release_rx),
                attempted: attempted_tx,
            },
            daemon,
        );

        const UNIQUE: u64 = 0x5234;
        (&kernel)
            .write_all(&lookup_request(UNIQUE, b"failed"))
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        kernel.shutdown(Shutdown::Read).unwrap();
        release_tx.send(()).unwrap();
        attempted_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert_eq!(imported.pending_requests().unwrap(), [RequestId(UNIQUE)]);

        kernel.shutdown(Shutdown::Write).unwrap();
        // End of stream is not a valid request
        assert_eq!(
            background.join().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn automatic_error_reply_completes_the_journal_entry() {
        let (daemon, mut kernel) = UnixStream::pair().unwrap();
        let (background, imported) = spawn_journaled(DroppedReply, daemon);

        const UNIQUE: u64 = 0x6234;
        kernel
            .write_all(&lookup_request(UNIQUE, b"dropped"))
            .unwrap();
        assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::EIO));
        wait_until_empty(&imported);

        destroy_and_join(&mut kernel, background, 0x6235);
    }

    fn init(minor: u32, kernel_capabilities: InitFlags) -> InitState {
        InitState {
            proto_version: Version(7, minor),
            negotiated: InitFlags::empty(),
            kernel_capabilities,
        }
    }

    fn adopt<FS: Filesystem>(fs: FS, fd: OwnedFd, init: InitState) -> Session<FS> {
        Session::from_initialized_fd(fs, fd, SessionACL::All, Config::default(), init).unwrap()
    }

    /// Serves `daemon` with a journal, returning an imported view of the journal.
    fn spawn_journaled<FS: Filesystem + Send + 'static>(
        fs: FS,
        daemon: UnixStream,
    ) -> (BackgroundSession, InflightJournal) {
        let journal = InflightJournal::create().unwrap();
        let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
        let mut session = adopt(fs, OwnedFd::from(daemon), init(31, InitFlags::empty()));
        session.set_inflight_journal(journal);
        (session.spawn().unwrap(), imported)
    }

    fn destroy_and_join(kernel: &mut UnixStream, background: BackgroundSession, unique: u64) {
        kernel
            .write_all(&request_header(
                IN_HEADER_LEN,
                fuse_opcode::FUSE_DESTROY,
                unique,
                0,
            ))
            .unwrap();
        assert_eq!(read_reply(kernel), (unique, 0));
        background.join().unwrap();
    }

    fn lookup_request(unique: u64, name: &[u8]) -> Vec<u8> {
        let len = IN_HEADER_LEN + name.len() + 1;
        let mut request = request_header(len, fuse_opcode::FUSE_LOOKUP, unique, 1);
        request.extend_from_slice(name);
        request.push(0);
        request
    }

    fn forget_request(unique: u64, nodeid: u64) -> Vec<u8> {
        let len = IN_HEADER_LEN + size_of::<fuse_forget_in>();
        let mut request = request_header(len, fuse_opcode::FUSE_FORGET, unique, nodeid);
        request.extend_from_slice(&1u64.to_ne_bytes());
        request
    }

    fn request_header(len: usize, opcode: fuse_opcode, unique: u64, nodeid: u64) -> Vec<u8> {
        let mut header = Vec::with_capacity(IN_HEADER_LEN);
        header.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        header.extend_from_slice(&(opcode as u32).to_ne_bytes());
        header.extend_from_slice(&unique.to_ne_bytes());
        header.extend_from_slice(&nodeid.to_ne_bytes());
        header.extend_from_slice(&0u32.to_ne_bytes());
        header.extend_from_slice(&0u32.to_ne_bytes());
        header.extend_from_slice(&std::process::id().to_ne_bytes());
        header.extend_from_slice(&0u32.to_ne_bytes());
        header
    }

    /// Returns the unique and error of a reply that carries no payload.
    fn read_reply(kernel: &mut UnixStream) -> (u64, i32) {
        let mut header = [0u8; OUT_HEADER_LEN];
        kernel.read_exact(&mut header).unwrap();
        let len = u32::from_ne_bytes(header[0..4].try_into().unwrap());
        assert_eq!(len as usize, OUT_HEADER_LEN);
        let error = i32::from_ne_bytes(header[4..8].try_into().unwrap());
        let unique = u64::from_ne_bytes(header[8..16].try_into().unwrap());
        (unique, error)
    }

    fn wait_until_empty(journal: &InflightJournal) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match journal.pending_requests() {
                Ok(pending) if pending.is_empty() => return,
                Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => panic!("journal did not become empty: {result:?}"),
            }
        }
    }
}
