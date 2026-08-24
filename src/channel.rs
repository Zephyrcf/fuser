use std::io;
use std::io::IoSliceMut;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::sync::Arc;

use nix::errno::Errno;

use crate::dev_fuse::DevFuse;
#[cfg(target_os = "linux")]
use crate::inflight::InflightReservation;
use crate::passthrough::BackingId;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug, Clone)]
pub(crate) struct Channel(Arc<DevFuse>);

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<DevFuse>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        nix::unistd::read(&self.0, buffer)
    }

    /// Receives one request while placing its unique ID directly in a
    /// process-shared journal reservation.
    #[cfg(target_os = "linux")]
    pub(crate) fn receive_journaled(
        &self,
        buffer: &mut [u8],
        reservation: &mut InflightReservation,
    ) -> nix::Result<usize> {
        const UNIQUE_OFFSET: usize = 8;
        const UNIQUE_BYTES: usize = std::mem::size_of::<u64>();
        const AFTER_UNIQUE: usize = UNIQUE_OFFSET + UNIQUE_BYTES;
        if buffer.len() < AFTER_UNIQUE {
            return Err(nix::errno::Errno::EINVAL);
        }

        let (prefix, remainder) = buffer.split_at_mut(UNIQUE_OFFSET);
        let (_, suffix) = remainder.split_at_mut(UNIQUE_BYTES);
        let mut slices = [
            IoSliceMut::new(prefix),
            IoSliceMut::new(reservation.unique_buffer()),
            IoSliceMut::new(suffix),
        ];
        let size = nix::sys::uio::readv(&self.0, &mut slices)?;
        drop(slices);
        reservation.copy_unique_to(&mut buffer[UNIQUE_OFFSET..AFTER_UNIQUE]);
        Ok(size)
    }

    /// Receives data up to the capacity of the given buffer (can block),
    /// retrying on errors that are safe to retry (ENOENT, EINTR, EAGAIN).
    ///
    /// - ENOENT: Operation interrupted. According to FUSE, this is safe to retry.
    /// - EINTR: Interrupted system call, retry.
    /// - EAGAIN: Explicitly instructed to try again.
    pub(crate) fn receive_retrying(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        loop {
            match self.receive(buffer) {
                Ok(size) => return Ok(size),
                Err(Errno::ENOENT | Errno::EINTR | Errno::EAGAIN) => continue,
                Err(err) => return Err(err),
            }
        }
    }

    /// Returns the FUSE device of this channel.
    pub(crate) fn device(&self) -> Arc<DevFuse> {
        self.0.clone()
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub(crate) fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }

    /// Clone the FUSE device fd using FUSE_DEV_IOC_CLONE ioctl.
    ///
    /// This creates a new fd that can read FUSE requests independently,
    /// enabling true parallel request processing. The kernel distributes
    /// requests across all cloned fds.
    ///
    /// Requires Linux 4.5+. Returns an error on older kernels or non-Linux.
    #[cfg(target_os = "linux")]
    pub(crate) fn clone_fd(&self) -> io::Result<Channel> {
        use std::os::fd::AsRawFd;

        let new_dev = DevFuse::open()?;

        let mut source_fd = self.0.as_raw_fd() as u32;
        // SAFETY: fuse_dev_ioc_clone is a valid ioctl for /dev/fuse
        unsafe {
            crate::ll::ioctl::fuse_dev_ioc_clone(new_dev.as_raw_fd(), &mut source_fd)?;
        }

        Ok(Channel::new(Arc::new(new_dev)))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChannelSender(Arc<DevFuse>);

impl ChannelSender {
    pub(crate) fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = nix::sys::uio::writev(&self.0, bufs)?;
        // writev is atomic, so do not need to check how many bytes are written.
        // libfuse does not do it either
        // https://github.com/libfuse/libfuse/blob/6278995cca991978abd25ebb2c20ebd3fc9e8a13/lib/fuse_lowlevel.c#L267
        debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc);
        Ok(())
    }

    pub(crate) fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }

    pub(crate) unsafe fn wrap_backing(&self, id: u32) -> BackingId {
        unsafe { BackingId::wrap_raw(&self.0, id) }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::inflight::InflightJournal;
    use crate::ll::RequestId;

    #[test]
    fn journaled_receive_writes_the_request_unique_to_shared_memory() {
        let (mut kernel, daemon) = UnixStream::pair().unwrap();
        let channel = Channel::new(Arc::new(DevFuse(File::from(OwnedFd::from(daemon)))));
        let journal = InflightJournal::create().unwrap();
        let mut reservation = journal.reserve().unwrap();
        let mut request = [0u8; 40];
        let request_len = request.len();
        request[..4].copy_from_slice(&(request_len as u32).to_ne_bytes());
        request[4..8].copy_from_slice(&1u32.to_ne_bytes());
        request[8..16].copy_from_slice(&0x1234_5678_9abc_def0u64.to_ne_bytes());
        kernel.write_all(&request).unwrap();

        let mut received = [0u8; 40];
        assert_eq!(
            channel
                .receive_journaled(&mut received, &mut reservation)
                .unwrap(),
            request_len
        );
        assert_eq!(received, request);
        std::mem::forget(reservation);
        assert_eq!(
            journal.recoverable_requests().unwrap(),
            [RequestId(0x1234_5678_9abc_def0)]
        );
    }
}
