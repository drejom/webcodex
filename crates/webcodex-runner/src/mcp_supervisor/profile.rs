//! Operator-owned supervisor profile. Only this file selects executables,
//! identities and the servicing authority; the Runner selects a provider id.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const PROFILE_BYTES: u64 = 64 * 1024;
const MAX_PROVIDERS: usize = 8;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ENV: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskProfile {
    socket: PathBuf,
    runner_uid: u32,
    /// systemd unit whose MainPID is the only accepted control peer.
    runner_unit: String,
    providers: Vec<DiskProvider>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskProvider {
    id: String,
    executable: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    cwd: PathBuf,
    uid: u32,
    gid: u32,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    servicing_socket: PathBuf,
}

pub(crate) struct Profile {
    pub socket: PathBuf,
    pub peer: PeerPolicy,
    pub providers: Vec<Provider>,
}

#[derive(Clone)]
pub(crate) enum PeerPolicy {
    /// Production: uid plus the exact live MainPID of this systemd unit.
    RunnerUnit { uid: u32, unit: String },
    /// Tests only; never constructed from an operator profile.
    #[cfg(test)]
    Uid(u32),
}

#[derive(Clone)]
pub(crate) struct Provider {
    pub id: String,
    pub executable: CString,
    pub argv: Vec<CString>,
    pub environment: Vec<CString>,
    pub cwd: CString,
    pub uid: u32,
    pub gid: u32,
    pub servicing_socket: PathBuf,
}

impl Profile {
    pub(crate) fn load(path: &Path) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        require_operator_owned(&file.metadata()?)?;
        let mut text = String::new();
        file.take(PROFILE_BYTES + 1).read_to_string(&mut text)?;
        if text.len() as u64 > PROFILE_BYTES {
            return Err(invalid("supervisor profile too large"));
        }
        Self::parse(&text)
    }

    fn parse(text: &str) -> io::Result<Self> {
        let disk: DiskProfile =
            toml::from_str(text).map_err(|_| invalid("supervisor profile invalid"))?;
        absolute(&disk.socket)?;
        if disk.runner_uid == 0 {
            return Err(invalid("runner_uid must not be root"));
        }
        if disk.runner_unit.is_empty()
            || disk.runner_unit.len() > 256
            || !disk.runner_unit.ends_with(".service")
            || !disk
                .runner_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        {
            return Err(invalid("runner_unit invalid"));
        }
        if disk.providers.is_empty() || disk.providers.len() > MAX_PROVIDERS {
            return Err(invalid("supervisor providers count invalid"));
        }
        let mut providers = Vec::with_capacity(disk.providers.len());
        for provider in disk.providers {
            providers.push(Provider::from_disk(provider, disk.runner_uid)?);
        }
        let mut ids: Vec<_> = providers.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("supervisor provider ids must be unique"));
        }
        Ok(Self {
            socket: disk.socket,
            peer: PeerPolicy::RunnerUnit {
                uid: disk.runner_uid,
                unit: disk.runner_unit,
            },
            providers,
        })
    }

    pub(crate) fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|provider| provider.id == id)
    }
}

impl Provider {
    fn from_disk(disk: DiskProvider, runner_uid: u32) -> io::Result<Self> {
        super::wire::identifier(&disk.id).map_err(|_| invalid("provider id invalid"))?;
        // A provider sharing the Runner identity is the unqualified path.
        if disk.uid == 0 || disk.gid == 0 || disk.uid == runner_uid {
            return Err(invalid(
                "provider identity must be dedicated and unprivileged",
            ));
        }
        absolute(&disk.executable)?;
        absolute(&disk.cwd)?;
        absolute(&disk.servicing_socket)?;
        if disk.args.len() > MAX_ARGS
            || disk
                .args
                .iter()
                .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
        {
            return Err(invalid("provider args invalid"));
        }
        if disk.environment.len() > MAX_ENV {
            return Err(invalid("provider environment too large"));
        }
        let mut argv = vec![c_path(&disk.executable)?];
        for arg in &disk.args {
            argv.push(CString::new(arg.as_bytes()).map_err(|_| invalid("provider arg invalid"))?);
        }
        let mut environment = Vec::with_capacity(disk.environment.len());
        for (key, value) in &disk.environment {
            if key.is_empty()
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || value.len() > MAX_ARG_BYTES
            {
                return Err(invalid("provider environment invalid"));
            }
            environment.push(
                CString::new(format!("{key}={value}"))
                    .map_err(|_| invalid("provider environment invalid"))?,
            );
        }
        Ok(Self {
            id: disk.id,
            executable: c_path(&disk.executable)?,
            argv,
            environment,
            cwd: c_path(&disk.cwd)?,
            uid: disk.uid,
            gid: disk.gid,
            servicing_socket: disk.servicing_socket,
        })
    }
}

fn require_operator_owned(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "supervisor profile must be a root-owned file not writable by others",
        ));
    }
    Ok(())
}

fn absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.as_os_str().len() > 1024 {
        return Err(invalid("supervisor paths must be absolute"));
    }
    Ok(())
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path contains NUL"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
pub(crate) fn test_provider(
    id: &str,
    executable: &Path,
    args: &[String],
    servicing_socket: &Path,
) -> Provider {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut argv = vec![c_path(executable).unwrap()];
    argv.extend(args.iter().map(|arg| CString::new(arg.as_str()).unwrap()));
    Provider {
        id: id.into(),
        executable: c_path(executable).unwrap(),
        argv,
        environment: vec![CString::new("WEBCODEX_SUPERVISED=1").unwrap()],
        cwd: c_path(Path::new("/")).unwrap(),
        uid,
        gid,
        servicing_socket: servicing_socket.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(uid: u32) -> DiskProvider {
        DiskProvider {
            id: "acg".into(),
            executable: "/usr/bin/python3".into(),
            args: vec![],
            cwd: "/".into(),
            uid,
            gid: 990,
            environment: BTreeMap::new(),
            servicing_socket: "/run/acg/servicing.sock".into(),
        }
    }

    #[test]
    fn provider_identity_must_differ_from_runner_and_root() {
        assert!(Provider::from_disk(disk(1001), 1001).is_err());
        assert!(Provider::from_disk(disk(0), 1001).is_err());
        assert!(Provider::from_disk(disk(1002), 1001).is_ok());
    }

    #[test]
    fn omhq_workbench_rendered_profile_parses() {
        // Rendered by OMHQ ansible/roles/workbench/templates/webcodex-mcp-supervisor.toml.j2.
        let text = r#"
socket = "/run/webcodex-mcp-supervisor-other-cloud-personal/supervisor.sock"
runner_uid = 1011
runner_unit = "webcodex-runner-other-cloud-personal.service"

[[providers]]
id = "omhq"
executable = "/opt/omhq-acg/venv/bin/python"
args = ["/usr/local/libexec/webcodex_acg_mcp.py"]
cwd = "/"
uid = 1013
gid = 1013
servicing_socket = "/run/omhq-acg-other-cloud-personal/servicing.sock"

[providers.environment]
OMHQ_ACG_SOCKET = "/run/omhq-acg-other-cloud-personal/acg.sock"
HOME = "/nonexistent"
"#;
        let profile = Profile::parse(text).unwrap();
        let provider = profile.provider("omhq").unwrap();
        assert_eq!((provider.uid, provider.gid), (1013, 1013));
        assert!(matches!(
            profile.peer,
            PeerPolicy::RunnerUnit { uid: 1011, .. }
        ));
    }

    #[test]
    fn environment_and_paths_are_validated() {
        let mut bad = disk(1002);
        bad.environment.insert("A=B".into(), "x".into());
        assert!(Provider::from_disk(bad, 1001).is_err());
        let mut relative = disk(1002);
        relative.cwd = "tmp".into();
        assert!(Provider::from_disk(relative, 1001).is_err());
    }
}
