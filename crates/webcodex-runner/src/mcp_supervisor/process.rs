//! Launch one fixed provider into a fresh generation under its dedicated
//! identity. The post-fork child performs only async-signal-safe syscalls.
use super::generation::Generation;
use super::profile::Provider;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

pub(crate) struct ProviderProcess {
    pidfd: OwnedFd,
    pid: libc::pid_t,
    pub(crate) input: OwnedFd,
    pub(crate) output: OwnedFd,
    reaped: bool,
}

impl ProviderProcess {
    pub(crate) fn launch(provider: &Provider, generation: &Generation) -> io::Result<Self> {
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let (report_read, report_write) = pipe()?;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        let argv: Vec<*const libc::c_char> = provider
            .argv
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = provider
            .environment
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let membership = generation.membership_fd();
        let report_fd = report_write.as_raw_fd();
        let parent = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                child(
                    provider,
                    membership,
                    report_fd,
                    parent,
                    input_read.as_raw_fd(),
                    output_write.as_raw_fd(),
                    null.as_raw_fd(),
                    &argv,
                    &envp,
                )
            }
        }
        // The child is unreaped, so its pid cannot be reused before pidfd_open.
        let pidfd = match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(error) => {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                return Err(error);
            }
        };
        drop(report_write);
        drop(input_read);
        drop(output_write);
        let mut process = Self {
            pidfd,
            pid,
            input: input_write,
            output: output_read,
            reaped: false,
        };
        if let Err(error) = await_exec(
            report_read.as_raw_fd(),
            Instant::now() + Duration::from_secs(5),
        ) {
            process.kill_and_reap(Duration::from_millis(500));
            return Err(error);
        }
        nonblocking(process.input.as_raw_fd())?;
        nonblocking(process.output.as_raw_fd())?;
        Ok(process)
    }

    pub(crate) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub(crate) fn exited(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut poll, 1, 0) > 0 }
    }

    pub(crate) fn kill_and_reap(&mut self, budget: Duration) {
        if self.reaped {
            return;
        }
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        let deadline = Instant::now() + budget;
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if result == 0 && unsafe { info.si_pid() } != 0 {
                self.reaped = true;
                return;
            }
            if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for ProviderProcess {
    fn drop(&mut self) {
        self.kill_and_reap(Duration::from_millis(500));
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn child(
    provider: &Provider,
    membership: RawFd,
    report: RawFd,
    parent: libc::pid_t,
    input: RawFd,
    output: RawFd,
    null: RawFd,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> ! {
    macro_rules! check {
        ($call:expr) => {
            if ($call as i64) < 0 {
                fail(report, *libc::__errno_location());
            }
        };
    }
    check!(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL));
    if libc::getppid() != parent {
        fail(report, libc::ECHILD);
    }
    // Join the generation before any provider code runs, so every descendant
    // is born inside it.
    if libc::write(membership, b"0".as_ptr().cast(), 1) != 1 {
        fail(report, *libc::__errno_location());
    }
    check!(libc::chdir(provider.cwd.as_ptr()));
    check!(libc::dup2(input, 0));
    check!(libc::dup2(output, 1));
    check!(libc::dup2(null, 2));
    // Close everything except stdio and the CLOEXEC exec report descriptor.
    if report > 3 {
        check!(libc::syscall(
            libc::SYS_close_range,
            3u32,
            (report - 1) as u32,
            0u32
        ));
    }
    check!(libc::syscall(
        libc::SYS_close_range,
        (report + 1) as u32,
        u32::MAX,
        0u32
    ));
    if libc::geteuid() == 0 {
        check!(libc::setgroups(0, std::ptr::null()));
        check!(libc::setresgid(provider.gid, provider.gid, provider.gid));
        check!(libc::setresuid(provider.uid, provider.uid, provider.uid));
    } else if libc::getuid() != provider.uid || libc::getgid() != provider.gid {
        // Unprivileged test harness: the identity cannot change, so refuse
        // any profile that would require it.
        fail(report, libc::EPERM);
    }
    check!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    // Identity change clears PDEATHSIG; re-arm and recheck the parent.
    check!(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL));
    if libc::getppid() != parent {
        fail(report, libc::ECHILD);
    }
    libc::execve(provider.executable.as_ptr(), argv.as_ptr(), envp.as_ptr());
    fail(report, *libc::__errno_location())
}

unsafe fn fail(report: RawFd, errno: libc::c_int) -> ! {
    let bytes = if errno > 0 { errno } else { libc::EIO }.to_ne_bytes();
    libc::write(report, bytes.as_ptr().cast(), bytes.len());
    libc::_exit(127)
}

fn await_exec(fd: RawFd, deadline: Instant) -> io::Result<()> {
    let mut bytes = [0u8; 4];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "provider exec acknowledgement expired",
            ));
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        if unsafe { libc::poll(&mut poll, 1, millis) } <= 0 {
            continue;
        }
        let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        // EOF without a report: CLOEXEC closed the pipe at a successful exec.
        if count == 0 {
            return Ok(());
        }
        if count as usize == bytes.len() {
            return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(bytes)));
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid provider exec report",
        ));
    }
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
