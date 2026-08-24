#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use fuser::Config;
use fuser::Errno;
use fuser::Filesystem;
use fuser::INodeNo;
use fuser::InflightJournal;
use fuser::InflightRecovery;
use fuser::InitFlags;
use fuser::ReplyEntry;
use fuser::Request;
use fuser::RequestId;
use fuser::Session;
use fuser::SessionACL;
use fuser::Version;

#[test]
fn imported_journal_reads_the_same_shared_state() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();

    assert_eq!(imported.pending_requests().unwrap(), []);
}

struct BlockingLookup {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

struct SignalingForget {
    completed: mpsc::SyncSender<()>,
}

impl Filesystem for SignalingForget {
    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {
        self.completed.send(()).unwrap();
    }
}

impl Filesystem for BlockingLookup {
    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        reply.error(Errno::ENOENT);
    }
}

struct AsyncLookup {
    entered: mpsc::SyncSender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

struct FailingReply {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    attempted: mpsc::SyncSender<()>,
}

struct DroppedReply;

impl Filesystem for DroppedReply {
    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        drop(reply);
    }
}

impl Filesystem for FailingReply {
    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        reply.error(Errno::ENOENT);
        self.attempted.send(()).unwrap();
    }
}

impl Filesystem for AsyncLookup {
    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        let entered = self.entered.clone();
        let release = Arc::clone(&self.release);
        std::thread::spawn(move || {
            entered.send(()).unwrap();
            release.lock().unwrap().recv().unwrap();
            reply.error(Errno::ENOENT);
        });
    }
}

#[test]
fn session_tracks_a_request_until_its_reply_reaches_the_kernel() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, mut kernel) = UnixStream::pair().unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let mut session = Session::from_initialized_fd(
        BlockingLookup {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        },
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 31),
        InitFlags::empty(),
        InitFlags::empty(),
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

    const UNIQUE: u64 = 0x1234;
    kernel.write_all(&lookup_request(UNIQUE, b"held")).unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(imported.pending_requests().unwrap(), [RequestId(UNIQUE)]);

    release_tx.send(()).unwrap();
    assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
    wait_until_empty(&imported);

    const DESTROY_UNIQUE: u64 = 0x1235;
    kernel
        .write_all(&request_header(40, 38, DESTROY_UNIQUE, 0))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (DESTROY_UNIQUE, 0));
    background.join().unwrap();
}

#[test]
fn recovery_flushes_and_removes_every_journaled_request() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, mut kernel) = UnixStream::pair().unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let mut session = Session::from_initialized_fd(
        BlockingLookup {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        },
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 31),
        InitFlags::empty(),
        InitFlags::empty(),
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

    const UNIQUE: u64 = 0x2234;
    kernel.write_all(&lookup_request(UNIQUE, b"held")).unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(
        background
            .notifier()
            .recover_inflight(&imported, Errno::EIO)
            .unwrap(),
        InflightRecovery::ErroredOut(1)
    );
    assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::EIO));
    wait_until_empty(&imported);

    release_tx.send(()).unwrap();
    assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
    const DESTROY_UNIQUE: u64 = 0x2235;
    kernel
        .write_all(&request_header(40, 38, DESTROY_UNIQUE, 0))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (DESTROY_UNIQUE, 0));
    background.join().unwrap();
}

#[test]
fn resend_retires_the_predecessor_journal_entries() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, mut kernel) = UnixStream::pair().unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let mut session = Session::from_initialized_fd(
        BlockingLookup {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        },
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 40),
        InitFlags::empty(),
        InitFlags::FUSE_HAS_RESEND,
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

    const UNIQUE: u64 = 0x2a34;
    kernel
        .write_all(&lookup_request(UNIQUE, b"resend"))
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(
        background
            .notifier()
            .recover_inflight(&imported, Errno::EIO)
            .unwrap(),
        InflightRecovery::Resent
    );
    assert_eq!(read_reply(&mut kernel), (0, 7));
    wait_until_empty(&imported);

    release_tx.send(()).unwrap();
    assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
    const DESTROY_UNIQUE: u64 = 0x2a35;
    kernel
        .write_all(&request_header(40, 38, DESTROY_UNIQUE, 0))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (DESTROY_UNIQUE, 0));
    background.join().unwrap();
}

#[test]
fn no_reply_requests_leave_no_journal_entry() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, mut kernel) = UnixStream::pair().unwrap();
    let (completed_tx, completed_rx) = mpsc::sync_channel(0);
    let mut session = Session::from_initialized_fd(
        SignalingForget {
            completed: completed_tx,
        },
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 31),
        InitFlags::empty(),
        InitFlags::empty(),
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

    kernel.write_all(&forget_request(0x3234, 1)).unwrap();
    completed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_until_empty(&imported);

    const DESTROY_UNIQUE: u64 = 0x3235;
    kernel
        .write_all(&request_header(40, 38, DESTROY_UNIQUE, 0))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (DESTROY_UNIQUE, 0));
    background.join().unwrap();
}

#[test]
fn asynchronous_reply_keeps_the_request_journaled() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, mut kernel) = UnixStream::pair().unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let mut session = Session::from_initialized_fd(
        AsyncLookup {
            entered: entered_tx,
            release: Arc::new(Mutex::new(release_rx)),
        },
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 31),
        InitFlags::empty(),
        InitFlags::empty(),
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

    const UNIQUE: u64 = 0x4234;
    kernel.write_all(&lookup_request(UNIQUE, b"async")).unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(imported.pending_requests().unwrap(), [RequestId(UNIQUE)]);

    release_tx.send(()).unwrap();
    assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::ENOENT));
    wait_until_empty(&imported);

    const DESTROY_UNIQUE: u64 = 0x4235;
    kernel
        .write_all(&request_header(40, 38, DESTROY_UNIQUE, 0))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (DESTROY_UNIQUE, 0));
    background.join().unwrap();
}

#[test]
fn failed_reply_keeps_the_request_journaled() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, kernel) = UnixStream::pair().unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let (attempted_tx, attempted_rx) = mpsc::sync_channel(0);
    let mut session = Session::from_initialized_fd(
        FailingReply {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            attempted: attempted_tx,
        },
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 31),
        InitFlags::empty(),
        InitFlags::empty(),
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

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
    assert!(background.join().is_err());
}

#[test]
fn automatic_error_reply_completes_the_journal_entry() {
    let journal = InflightJournal::create().unwrap();
    let imported = InflightJournal::from_fd(journal.try_clone_fd().unwrap()).unwrap();
    let (daemon, mut kernel) = UnixStream::pair().unwrap();
    let mut session = Session::from_initialized_fd(
        DroppedReply,
        OwnedFd::from(daemon),
        SessionACL::All,
        Config::default(),
        Version(7, 31),
        InitFlags::empty(),
        InitFlags::empty(),
    )
    .unwrap();
    session.set_inflight_journal(journal);
    let background = session.spawn().unwrap();

    const UNIQUE: u64 = 0x6234;
    kernel
        .write_all(&lookup_request(UNIQUE, b"dropped"))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (UNIQUE, -libc::EIO));
    wait_until_empty(&imported);

    const DESTROY_UNIQUE: u64 = 0x6235;
    kernel
        .write_all(&request_header(40, 38, DESTROY_UNIQUE, 0))
        .unwrap();
    assert_eq!(read_reply(&mut kernel), (DESTROY_UNIQUE, 0));
    background.join().unwrap();
}

fn lookup_request(unique: u64, name: &[u8]) -> Vec<u8> {
    let len = 40 + name.len() + 1;
    let mut request = request_header(len as u32, 1, unique, 1);
    request.extend_from_slice(name);
    request.push(0);
    request
}

fn forget_request(unique: u64, nodeid: u64) -> Vec<u8> {
    let mut request = request_header(48, 2, unique, nodeid);
    request.extend_from_slice(&1u64.to_ne_bytes());
    request
}

fn request_header(len: u32, opcode: u32, unique: u64, nodeid: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(40);
    header.extend_from_slice(&len.to_ne_bytes());
    header.extend_from_slice(&opcode.to_ne_bytes());
    header.extend_from_slice(&unique.to_ne_bytes());
    header.extend_from_slice(&nodeid.to_ne_bytes());
    header.extend_from_slice(&0u32.to_ne_bytes());
    header.extend_from_slice(&0u32.to_ne_bytes());
    header.extend_from_slice(&std::process::id().to_ne_bytes());
    header.extend_from_slice(&0u32.to_ne_bytes());
    header
}

fn read_reply(kernel: &mut UnixStream) -> (u64, i32) {
    let mut header = [0u8; 16];
    kernel.read_exact(&mut header).unwrap();
    let len = u32::from_ne_bytes(header[0..4].try_into().unwrap());
    assert_eq!(len, 16);
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
