use std::fmt;
use std::io;
use std::mem;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use crate::RequestId;

const JOURNAL_MAGIC: [u8; 8] = *b"FUSRIFL\0";
const JOURNAL_VERSION: u32 = 1;
const DEFAULT_CAPACITY: usize = 65_536;
const MAX_CAPACITY: usize = 1_048_576;

const SLOT_EMPTY: u32 = 0;
const SLOT_RESERVED: u32 = 1;
const SLOT_INFLIGHT: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct JournalHeader {
    magic: [u8; 8],
    version: u32,
    capacity: u32,
}

#[repr(C)]
struct JournalSlot {
    state: AtomicU32,
    unique_low: AtomicU32,
    unique_high: AtomicU32,
}

struct JournalInner {
    fd: OwnedFd,
    mapping: NonNull<u8>,
    mapping_len: usize,
    capacity: usize,
    next_slot: AtomicUsize,
}

// The mapping contains only immutable header fields and process-shared atomics.
unsafe impl Send for JournalInner {}
unsafe impl Sync for JournalInner {}

impl Drop for JournalInner {
    fn drop(&mut self) {
        let result = unsafe { libc::munmap(self.mapping.as_ptr().cast(), self.mapping_len) };
        debug_assert_eq!(result, 0);
    }
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

    fn create_with_capacity(capacity: usize) -> io::Result<Self> {
        let mapping_len = mapping_len(capacity)?;
        let raw_fd = unsafe {
            libc::memfd_create(
                c"fuser-inflight".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        if unsafe { libc::ftruncate(fd.as_raw_fd(), mapping_len as libc::off_t) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mapping = map_shared(&fd, mapping_len)?;
        unsafe {
            mapping
                .as_ptr()
                .cast::<JournalHeader>()
                .write(JournalHeader {
                    magic: JOURNAL_MAGIC,
                    version: JOURNAL_VERSION,
                    capacity: capacity as u32,
                });
            let slots = mapping
                .as_ptr()
                .add(mem::size_of::<JournalHeader>())
                .cast::<JournalSlot>();
            for index in 0..capacity {
                slots.add(index).write(JournalSlot {
                    state: AtomicU32::new(SLOT_EMPTY),
                    unique_low: AtomicU32::new(0),
                    unique_high: AtomicU32::new(0),
                });
            }
        }

        let seals = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            unsafe {
                libc::munmap(mapping.as_ptr().cast(), mapping_len);
            }
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            inner: Arc::new(JournalInner {
                fd,
                mapping,
                mapping_len,
                capacity,
                next_slot: AtomicUsize::new(0),
            }),
        })
    }

    /// Imports a journal descriptor received from another process.
    ///
    /// # Errors
    /// Returns an error if the descriptor does not contain a supported journal or cannot be
    /// mapped read-write.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        validate_seals(&fd)?;
        let header = read_header(&fd)?;
        if header.magic != JOURNAL_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid inflight journal magic",
            ));
        }
        if header.version != JOURNAL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported inflight journal version {}", header.version),
            ));
        }

        let capacity = header.capacity as usize;
        let mapping_len = mapping_len(capacity)?;
        let actual_len = fd_len(&fd)?;
        if actual_len != mapping_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("inflight journal length is {actual_len}, expected {mapping_len}"),
            ));
        }
        let mapping = map_shared(&fd, mapping_len)?;

        Ok(Self {
            inner: Arc::new(JournalInner {
                fd,
                mapping,
                mapping_len,
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

    /// Returns the request IDs currently known to be awaiting replies.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::WouldBlock`] when a worker reserved a slot before reading but
    /// did not publish the request ID. A failover path cannot safely flush that unknown request.
    pub fn pending_requests(&self) -> io::Result<Vec<RequestId>> {
        let mut pending = Vec::new();
        for slot in self.slots() {
            match slot.state.load(Ordering::Acquire) {
                SLOT_EMPTY => {}
                SLOT_RESERVED => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "an inflight request ID was not published",
                    ));
                }
                SLOT_INFLIGHT => {
                    pending.push(slot_request_id(slot));
                }
                state => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid inflight journal slot state {state}"),
                    ));
                }
            }
        }
        Ok(pending)
    }

    fn slots(&self) -> &[JournalSlot] {
        unsafe {
            std::slice::from_raw_parts(
                self.inner
                    .mapping
                    .as_ptr()
                    .add(mem::size_of::<JournalHeader>())
                    .cast::<JournalSlot>(),
                self.inner.capacity,
            )
        }
    }

    pub(crate) fn reserve(&self) -> io::Result<InflightReservation> {
        let start = self.inner.next_slot.fetch_add(1, Ordering::Relaxed) % self.inner.capacity;
        for offset in 0..self.inner.capacity {
            let index = (start + offset) % self.inner.capacity;
            let slot = &self.slots()[index];
            if slot
                .state
                .compare_exchange(
                    SLOT_EMPTY,
                    SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(InflightReservation {
                    journal: self.clone(),
                    index,
                    reserved: true,
                });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "inflight journal is full",
        ))
    }

    fn slot(&self, index: usize) -> &JournalSlot {
        &self.slots()[index]
    }

    pub(crate) fn clear(&self) {
        for slot in self.slots() {
            slot.state.store(SLOT_EMPTY, Ordering::Release);
        }
    }
}

#[derive(Debug)]
pub(crate) struct InflightReservation {
    journal: InflightJournal,
    index: usize,
    reserved: bool,
}

impl InflightReservation {
    pub(crate) fn publish(mut self, unique: RequestId) -> InflightRequest {
        let slot = self.journal.slot(self.index);
        slot.unique_low.store(unique.0 as u32, Ordering::Relaxed);
        slot.unique_high
            .store((unique.0 >> 32) as u32, Ordering::Relaxed);
        slot.state.store(SLOT_INFLIGHT, Ordering::Release);
        self.reserved = false;
        InflightRequest {
            journal: self.journal.clone(),
            index: self.index,
            unique,
        }
    }
}

impl Drop for InflightReservation {
    fn drop(&mut self) {
        if self.reserved {
            self.journal
                .slot(self.index)
                .state
                .store(SLOT_EMPTY, Ordering::Release);
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InflightRequest {
    journal: InflightJournal,
    index: usize,
    unique: RequestId,
}

impl InflightRequest {
    pub(crate) fn complete(&self) {
        let slot = self.journal.slot(self.index);
        if slot.state.load(Ordering::Acquire) != SLOT_INFLIGHT {
            return;
        }
        if slot_request_id(slot) != self.unique {
            return;
        }
        let _ = slot.state.compare_exchange(
            SLOT_INFLIGHT,
            SLOT_EMPTY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn slot_request_id(slot: &JournalSlot) -> RequestId {
    let low = slot.unique_low.load(Ordering::Relaxed) as u64;
    let high = slot.unique_high.load(Ordering::Relaxed) as u64;
    RequestId(low | (high << 32))
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
        .and_then(|slots| slots.checked_add(mem::size_of::<JournalHeader>()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "journal size overflow"))
}

fn map_shared(fd: &OwnedFd, len: usize) -> io::Result<NonNull<u8>> {
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    NonNull::new(mapping.cast()).ok_or_else(|| io::Error::other("mmap returned a null pointer"))
}

fn read_header(fd: &OwnedFd) -> io::Result<JournalHeader> {
    let mut header = mem::MaybeUninit::<JournalHeader>::uninit();
    let expected = mem::size_of::<JournalHeader>();
    let read = unsafe { libc::pread(fd.as_raw_fd(), header.as_mut_ptr().cast(), expected, 0) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read as usize != expected {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "inflight journal header is truncated",
        ));
    }
    Ok(unsafe { header.assume_init() })
}

fn fd_len(fd: &OwnedFd) -> io::Result<usize> {
    let mut stat = mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let len = unsafe { stat.assume_init() }.st_size;
    usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid journal length"))
}

fn validate_seals(fd: &OwnedFd) -> io::Result<()> {
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "inflight journal is not a sealed anonymous file: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    let required = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if seals & required != required {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inflight journal size is not sealed",
        ));
    }
    Ok(())
}
