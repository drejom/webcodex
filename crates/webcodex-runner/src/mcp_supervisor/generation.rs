//! One physical provider connection = one fresh cgroup-v2 leaf. The service
//! identifies the provider by this cgroup, never by uid, pid or timing.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

pub(crate) struct Generation {
    id: String,
    directory: PathBuf,
    relative: String,
    procs: File,
    kill: File,
}

impl Generation {
    /// Create `<parent>/wc-gen-<uuid>`. An existing directory is never adopted.
    pub(crate) fn create(parent: &Path) -> io::Result<Self> {
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        let directory = parent.join(format!("wc-gen-{id}"));
        fs::create_dir(&directory)?;
        let opened = (|| {
            let procs = OpenOptions::new()
                .write(true)
                .open(directory.join("cgroup.procs"))?;
            let kill = OpenOptions::new()
                .write(true)
                .open(directory.join("cgroup.kill"))?;
            Ok::<_, io::Error>((procs, kill))
        })();
        let (procs, kill) = match opened {
            Ok(files) => files,
            Err(error) => {
                let _ = fs::remove_dir(&directory);
                return Err(error);
            }
        };
        let relative = relative_to_mount(&directory)?;
        Ok(Self {
            id,
            directory,
            relative,
            procs,
            kill,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Path as it appears in `/proc/<pid>/cgroup` (`0::<relative>`).
    pub(crate) fn cgroup_path(&self) -> &str {
        &self.relative
    }

    /// Opened before fork. cgroup v2 checks migration permission against the
    /// opener's credentials, so the child may write it after dropping identity.
    pub(crate) fn membership_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    pub(crate) fn populated(&self) -> io::Result<bool> {
        let events = fs::read_to_string(self.directory.join("cgroup.events"))?;
        events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
            .map(|value| value.trim() == "1")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cgroup.events invalid"))
    }

    /// Kill every member, including escaped descendants, then remove the leaf.
    pub(crate) fn terminate(&mut self, budget: Duration) -> io::Result<()> {
        let deadline = Instant::now() + budget;
        self.kill.write_all(b"1")?;
        while self.populated()? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "generation cleanup unconfirmed",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        match fs::remove_dir(&self.directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        let _ = self.terminate(Duration::from_millis(500));
    }
}

/// The supervisor's own cgroup. With `Delegate=yes` systemd hands it to the
/// service; generations are created beneath it.
pub(crate) fn own_cgroup() -> io::Result<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup")?;
    let relative = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "cgroup v2 unavailable"))?;
    Ok(Path::new(CGROUP_MOUNT).join(relative.trim_start_matches('/')))
}

/// The cgroup v2 path of a live process, as the kernel reports it.
pub(crate) fn process_cgroup(pid: libc::pid_t) -> io::Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "cgroup v2 unavailable"))
}

fn relative_to_mount(path: &Path) -> io::Result<String> {
    let relative = path
        .strip_prefix(CGROUP_MOUNT)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "generation outside cgroup2"))?;
    Ok(format!("/{}", relative.display()))
}
