//! Deadline-bounded Unix seqpacket control channel. One packet is one message;
//! the kernel preserves boundaries, so no framing or partial reads exist.
use super::wire::MAX_PACKET_BYTES;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Instant;

pub(crate) struct Channel(OwnedFd);

impl Channel {
    pub(crate) fn from_owned(fd: OwnedFd) -> Self {
        Self(fd)
    }

    pub(crate) fn connect(path: &Path) -> io::Result<Self> {
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let (address, length) = unix_address(path)?;
        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub(crate) fn send(&self, bytes: &[u8], deadline: Instant) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid control packet size",
            ));
        }
        loop {
            wait(self.raw_fd(), libc::POLLOUT, deadline)?;
            let written = unsafe {
                libc::send(
                    self.raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            if written as usize != bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "incomplete control packet",
                ));
            }
            return Ok(());
        }
    }

    /// Ok(None) is orderly peer close.
    pub(crate) fn receive(&self, deadline: Option<Instant>) -> io::Result<Option<Vec<u8>>> {
        loop {
            match deadline {
                Some(deadline) => wait(self.raw_fd(), libc::POLLIN, deadline)?,
                None => wait_forever(self.raw_fd())?,
            }
            let mut bytes = vec![0u8; MAX_PACKET_BYTES + 1];
            let count = unsafe {
                libc::recv(
                    self.raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            if count == 0 {
                return Ok(None);
            }
            // MSG_TRUNC reports the real datagram length; never accept a cut.
            if count as usize > MAX_PACKET_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control packet too large",
                ));
            }
            bytes.truncate(count as usize);
            return Ok(Some(bytes));
        }
    }

    /// True when the peer has closed or the socket failed. Never blocks.
    pub(crate) fn closed(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        ready < 0 || poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    }

    pub(crate) fn shutdown(&self) {
        unsafe {
            libc::shutdown(self.raw_fd(), libc::SHUT_RDWR);
        }
    }
}

pub(crate) fn unix_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Ok((address, length))
}

fn wait(fd: RawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control deadline expired",
            ));
        }
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        if poll_once(fd, events, millis)? {
            return Ok(());
        }
    }
}

fn wait_forever(fd: RawFd) -> io::Result<()> {
    while !poll_once(fd, libc::POLLIN, -1)? {}
    Ok(())
}

fn poll_once(fd: RawFd, events: libc::c_short, millis: i32) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut poll, 1, millis) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    // POLLHUP with pending data still reads the data first, then 0 = close.
    Ok(ready > 0 && poll.revents & (events | libc::POLLHUP | libc::POLLERR) != 0)
}
