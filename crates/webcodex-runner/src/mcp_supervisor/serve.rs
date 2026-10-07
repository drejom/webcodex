//! Root supervisor service. One Runner control connection owns at most one
//! provider generation; the generation dies with the connection.
use super::channel::{unix_address, Channel};
use super::generation::{self, Generation};
use super::process::ProviderProcess;
use super::profile::{PeerPolicy, Profile, Provider};
use super::provider_io::{Failure, ProviderIo};
use super::servicing::{self, Outcome};
use super::wire::{Command, Dispatch, Reply};
use serde_json::json;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_CONNECTIONS: usize = 16;
const CONTROL_REPLY_BUDGET: Duration = Duration::from_secs(5);

pub(crate) fn run(profile_path: &Path) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "supervisor requires root",
        ));
    }
    let profile = Profile::load(profile_path)?;
    let cgroup_parent = generation::own_cgroup()?;
    let listener = bind(&profile.socket, &profile.peer)?;
    serve(listener, Arc::new(profile), cgroup_parent)
}

pub(crate) fn serve(
    listener: OwnedFd,
    profile: Arc<Profile>,
    cgroup_parent: PathBuf,
) -> io::Result<()> {
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let channel = Channel::from_owned(unsafe { OwnedFd::from_raw_fd(fd) });
        if !peer_allowed(&channel, &profile.peer) {
            continue;
        }
        if active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            continue;
        }
        let profile = profile.clone();
        let cgroup_parent = cgroup_parent.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            Session::new(&profile, &cgroup_parent).serve(&channel);
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}

fn bind(path: &Path, peer: &PeerPolicy) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (address, length) = unix_address(path)?;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // Only the Runner identity may connect; per-connection peer checks follow.
    let uid = match peer {
        PeerPolicy::RunnerUnit { uid, .. } => *uid,
        #[cfg(test)]
        PeerPolicy::Uid(uid) => *uid,
    };
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path"))?;
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::chown(c_path.as_ptr(), uid, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::chmod(c_path.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 16) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub(crate) fn peer_credentials(channel: &Channel) -> Option<libc::ucred> {
    let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            channel.raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    (result == 0).then_some(credential)
}

fn peer_allowed(channel: &Channel, policy: &PeerPolicy) -> bool {
    let Some(credential) = peer_credentials(channel) else {
        return false;
    };
    match policy {
        PeerPolicy::RunnerUnit { uid, unit } => {
            credential.uid == *uid && unit_main_pid(unit) == Some(credential.pid)
        }
        #[cfg(test)]
        PeerPolicy::Uid(uid) => credential.uid == *uid,
    }
}

/// Only the configured Runner unit's main process may control generations;
/// other processes running as the Runner uid (its jobs, shells) may not.
fn unit_main_pid(unit: &str) -> Option<libc::pid_t> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", "--property=MainPID", "--value", "--", unit])
        .env_clear()
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let pid: libc::pid_t = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    (pid > 0).then_some(pid)
}

struct Active {
    provider: Provider,
    io: ProviderIo,
    // Drop order: process before generation, so the leaf can be removed.
    process: ProviderProcess,
    generation: Generation,
}

pub(crate) struct Session<'a> {
    profile: &'a Profile,
    cgroup_parent: &'a Path,
    active: Option<Active>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(profile: &'a Profile, cgroup_parent: &'a Path) -> Self {
        Self {
            profile,
            cgroup_parent,
            active: None,
        }
    }

    pub(crate) fn serve(mut self, channel: &Channel) {
        while let Ok(Some(bytes)) = channel.receive(None) {
            let reply = match Command::decode(&bytes) {
                Ok(command) => self.handle(command, channel),
                Err(_) => Reply::failed("invalid_control", Dispatch::NotStarted),
            };
            let fatal = matches!(
                &reply,
                Reply::Failed { dispatch, .. } if *dispatch != Dispatch::Completed
            ) && self.active.is_some()
                && self.desynchronized(&reply);
            let Ok(encoded) = reply.encode() else { break };
            if channel
                .send(&encoded, Instant::now() + CONTROL_REPLY_BUDGET)
                .is_err()
            {
                break;
            }
            if fatal {
                break;
            }
        }
        channel.shutdown();
        if let Some(mut active) = self.active.take() {
            active.process.kill_and_reap(Duration::from_millis(500));
            let _ = active.generation.terminate(Duration::from_secs(2));
        }
    }

    fn desynchronized(&self, reply: &Reply) -> bool {
        matches!(
            reply,
            Reply::Failed {
                dispatch: Dispatch::OutcomeUnknown,
                ..
            }
        )
    }

    fn handle(&mut self, command: Command, channel: &Channel) -> Reply {
        match command {
            Command::Open { provider } => self.open(&provider),
            Command::Request {
                method,
                params,
                timeout_ms,
            } => {
                let Some(active) = self.active.as_mut() else {
                    return Reply::failed("generation_not_open", Dispatch::NotStarted);
                };
                let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                match active
                    .io
                    .request(&active.process, &method, params, deadline)
                {
                    Ok(message) => Reply::Response { message },
                    Err(failure) => failed(failure),
                }
            }
            Command::Notify { method } => {
                let Some(active) = self.active.as_mut() else {
                    return Reply::failed("generation_not_open", Dispatch::NotStarted);
                };
                match active.io.notify(
                    &active.process,
                    &method,
                    Instant::now() + CONTROL_REPLY_BUDGET,
                ) {
                    Ok(()) => Reply::Notified,
                    Err(failure) => failed(failure),
                }
            }
            Command::Call {
                native,
                name,
                arguments,
                timeout_ms,
            } => {
                let Some(active) = self.active.as_mut() else {
                    return Reply::failed("generation_not_open", Dispatch::NotStarted);
                };
                let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                let selection = servicing::Selection {
                    provider: &active.provider.id,
                    generation: active.generation.id(),
                    cgroup: active.generation.cgroup_path(),
                    native: &native,
                    tool: &name,
                    arguments: &arguments,
                    deadline,
                };
                let preparation =
                    match servicing::prepare(&active.provider.servicing_socket, &selection) {
                        Outcome::Ok(preparation) => preparation,
                        Outcome::Refused(code) => {
                            return Reply::Failed {
                                code: format!("servicing_{code}"),
                                dispatch: Dispatch::NotStarted,
                            }
                        }
                        // The provider was never written. The authority may
                        // hold an unconsumed preparation that expires at the
                        // original deadline; no call can consume it because
                        // none is sent on this generation.
                        Outcome::Unknown => {
                            return Reply::failed("servicing_prepare_unknown", Dispatch::NotStarted)
                        }
                    };
                // The Runner disconnecting while prepare was in flight cancels.
                let result = if channel.closed() {
                    Err(Failure {
                        code: "runner_disconnected",
                        dispatch: Dispatch::NotStarted,
                    })
                } else {
                    active.io.request(
                        &active.process,
                        "tools/call",
                        json!({"name": name, "arguments": arguments}),
                        deadline,
                    )
                };
                // Revoke unconditionally. A consumed preparation stays
                // consumed; revoke only prevents later consumption.
                let _ = servicing::revoke(&active.provider.servicing_socket, &preparation);
                match result {
                    Ok(message) => Reply::Response { message },
                    Err(failure) => failed(failure),
                }
            }
        }
    }

    fn open(&mut self, provider_id: &str) -> Reply {
        if self.active.is_some() {
            return Reply::failed("generation_already_open", Dispatch::NotStarted);
        }
        let Some(provider) = self.profile.provider(provider_id).cloned() else {
            return Reply::failed("provider_unknown", Dispatch::NotStarted);
        };
        let generation = match Generation::create(self.cgroup_parent) {
            Ok(generation) => generation,
            Err(_) => return Reply::failed("generation_unavailable", Dispatch::NotStarted),
        };
        let process = match ProviderProcess::launch(&provider, &generation) {
            Ok(process) => process,
            Err(_) => return Reply::failed("provider_spawn_failed", Dispatch::NotStarted),
        };
        // Isolation is a precondition, not a best effort.
        match generation::process_cgroup(process.pid()) {
            Ok(path) if path == generation.cgroup_path() => {}
            _ => return Reply::failed("generation_unavailable", Dispatch::NotStarted),
        }
        let id = generation.id().to_string();
        self.active = Some(Active {
            provider,
            io: ProviderIo::new(),
            process,
            generation,
        });
        Reply::Opened { generation: id }
    }
}

fn failed(failure: Failure) -> Reply {
    Reply::failed(failure.code, failure.dispatch)
}

#[cfg(test)]
pub(crate) fn bind_for_test(path: &Path) -> io::Result<OwnedFd> {
    bind(path, &PeerPolicy::Uid(unsafe { libc::getuid() }))
}
