//! Prepare/revoke client for the external servicing authority (for OMHQ, the
//! ACG service). The authority, not this supervisor, performs authenticated
//! consume + operation reservation when the provider later calls it from
//! inside the prepared generation.
//!
//! Wire: one newline-terminated JSON request and response per stream
//! connection. The authority authenticates this peer by its own means
//! (for ACG: SO_PEERCRED uid 0).
use super::wire::NativeFence;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const PROTOCOL: &str = "webcodex.servicing.v1";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024;

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request<'a> {
    Prepare {
        protocol: &'static str,
        provider: &'a str,
        generation: &'a str,
        cgroup: &'a str,
        native: &'a NativeFence,
        tool: &'a str,
        arguments_sha256: String,
        /// Unix milliseconds; the authority refuses consume after this.
        expires_at_ms: u64,
    },
    Revoke {
        protocol: &'static str,
        preparation_id: &'a str,
    },
}

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum Response {
    Prepared { preparation_id: String },
    Revoked { state: String },
    Refused { code: String },
}

pub(crate) enum Outcome<T> {
    Ok(T),
    /// Authoritative refusal: the provider call must not start.
    Refused(String),
    /// Transport failed after the request may have been delivered.
    Unknown,
}

pub(crate) struct Preparation {
    pub id: String,
}

pub(crate) struct Selection<'a> {
    pub provider: &'a str,
    pub generation: &'a str,
    pub cgroup: &'a str,
    pub native: &'a NativeFence,
    pub tool: &'a str,
    pub arguments: &'a Value,
    pub deadline: Instant,
}

pub(crate) fn prepare(socket: &Path, selection: &Selection<'_>) -> Outcome<Preparation> {
    let remaining = selection.deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Outcome::Refused("deadline_expired".into());
    }
    let expires_at_ms = match SystemTime::now()
        .checked_add(remaining)
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
    {
        Some(time) => time.as_millis() as u64,
        None => return Outcome::Refused("clock_unavailable".into()),
    };
    let request = Request::Prepare {
        protocol: PROTOCOL,
        provider: selection.provider,
        generation: selection.generation,
        cgroup: selection.cgroup,
        native: selection.native,
        tool: selection.tool,
        arguments_sha256: arguments_digest(selection.arguments),
        expires_at_ms,
    };
    match exchange(socket, &request, selection.deadline) {
        Exchange::Response(Response::Prepared { preparation_id })
            if !preparation_id.is_empty() && preparation_id.len() <= 128 =>
        {
            Outcome::Ok(Preparation { id: preparation_id })
        }
        Exchange::Response(Response::Refused { code }) => Outcome::Refused(bounded_code(code)),
        Exchange::NotSent => Outcome::Refused("servicing_unavailable".into()),
        Exchange::Response(_) | Exchange::Uncertain => Outcome::Unknown,
    }
}

/// Revoke has its own short budget: it runs after the call deadline too.
pub(crate) fn revoke(socket: &Path, preparation: &Preparation) -> Outcome<String> {
    let request = Request::Revoke {
        protocol: PROTOCOL,
        preparation_id: &preparation.id,
    };
    match exchange(socket, &request, Instant::now() + Duration::from_secs(2)) {
        Exchange::Response(Response::Revoked { state }) => Outcome::Ok(bounded_code(state)),
        Exchange::Response(Response::Refused { code }) => Outcome::Refused(bounded_code(code)),
        Exchange::NotSent | Exchange::Response(_) | Exchange::Uncertain => Outcome::Unknown,
    }
}

/// Digest of the call arguments in canonical form: compact JSON, object keys
/// sorted at every level, UTF-8 unescaped. The authority recomputes it from
/// the arguments the provider forwards. Key order is canonicalized here
/// because serde_json may preserve insertion order in this build.
pub(crate) fn arguments_digest(arguments: &Value) -> String {
    let bytes = serde_json::to_vec(&canonical(arguments)).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            let mut sorted = serde_json::Map::with_capacity(object.len());
            for key in keys {
                sorted.insert(key.clone(), canonical(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

enum Exchange {
    NotSent,
    Uncertain,
    Response(Response),
}

fn exchange(socket: &Path, request: &impl Serialize, deadline: Instant) -> Exchange {
    let Ok(mut body) = serde_json::to_vec(request) else {
        return Exchange::NotSent;
    };
    body.push(b'\n');
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Exchange::NotSent;
    }
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return Exchange::NotSent;
    };
    if stream.set_write_timeout(Some(remaining)).is_err()
        || stream.set_read_timeout(Some(remaining)).is_err()
    {
        return Exchange::NotSent;
    }
    if stream.write_all(&body).is_err() {
        return Exchange::Uncertain;
    }
    let mut response = Vec::new();
    if (&mut stream)
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .is_err()
        || response.len() as u64 > MAX_RESPONSE_BYTES
        || response.last() != Some(&b'\n')
        || Instant::now() > deadline
    {
        return Exchange::Uncertain;
    }
    response.pop();
    match serde_json::from_slice(&response) {
        Ok(parsed) => Exchange::Response(parsed),
        Err(_) => Exchange::Uncertain,
    }
}

fn bounded_code(code: String) -> String {
    if code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        code
    } else {
        "invalid_code".into()
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! In-process authority for tests: records requests, answers by script.
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Mode {
        Prepare,
        Refuse,
        HangUp,
    }

    pub(crate) struct Authority {
        pub requests: Arc<Mutex<Vec<Value>>>,
        pub path: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Authority {
        pub(crate) fn start(mode: Mode) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("servicing.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = requests.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut line = Vec::new();
                    let mut byte = [0u8; 1];
                    while stream.read_exact(&mut byte).is_ok() && byte[0] != b'\n' {
                        line.push(byte[0]);
                    }
                    let request: Value = serde_json::from_slice(&line).unwrap();
                    let action = request["action"].as_str().unwrap_or("").to_string();
                    seen.lock().unwrap().push(request);
                    let reply = match (mode, action.as_str()) {
                        (Mode::HangUp, _) => continue,
                        (Mode::Refuse, "prepare") => {
                            r#"{"outcome":"refused","code":"not_authorized"}"#
                        }
                        (_, "prepare") => r#"{"outcome":"prepared","preparation_id":"prep-1"}"#,
                        (_, "revoke") => r#"{"outcome":"revoked","state":"unconsumed"}"#,
                        _ => r#"{"outcome":"refused","code":"invalid"}"#,
                    };
                    let _ = stream.write_all(reply.as_bytes());
                    let _ = stream.write_all(b"\n");
                }
            });
            Self {
                requests,
                path,
                _dir: dir,
            }
        }

        pub(crate) fn actions(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| request["action"].as_str().unwrap().to_string())
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{Authority, Mode};
    use super::*;
    use serde_json::json;

    fn selection<'a>(native: &'a NativeFence, arguments: &'a Value) -> Selection<'a> {
        Selection {
            provider: "acg",
            generation: "gen",
            cgroup: "/x/wc-gen-gen",
            native,
            tool: "echo",
            arguments,
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }

    fn native() -> NativeFence {
        NativeFence {
            request_id: "req".into(),
            client_id: "client".into(),
            runner_instance_id: "inst".into(),
        }
    }

    #[test]
    fn prepare_carries_physical_generation_and_argument_digest() {
        let authority = Authority::start(Mode::Prepare);
        let native = native();
        let arguments = json!({"value": "hello"});
        let Outcome::Ok(preparation) = prepare(&authority.path, &selection(&native, &arguments))
        else {
            panic!("prepare failed");
        };
        assert_eq!(preparation.id, "prep-1");
        let sent = authority.requests.lock().unwrap()[0].clone();
        assert_eq!(sent["cgroup"], "/x/wc-gen-gen");
        assert_eq!(sent["native"]["request_id"], "req");
        assert_eq!(sent["arguments_sha256"], arguments_digest(&arguments));
        assert!(sent.get("arguments").is_none(), "raw arguments never leave");
    }

    #[test]
    fn argument_digest_matches_service_canonical_form() {
        // Shared vector with OMHQ scripts/test_acg_servicing.py: compact JSON,
        // sorted keys, UTF-8 unescaped.
        let arguments =
            json!({"value": "h\u{e9}llo", "n": 3, "nested": {"b": [1, true, null], "a": "x\n"}});
        assert_eq!(
            arguments_digest(&arguments),
            "ffdd66c0192996899d52da410eb56b110a662e014b111feeae954e50e0412cce"
        );
    }

    #[test]
    fn refusal_and_lost_response_are_distinct() {
        let native = native();
        let arguments = json!({});
        let refused = Authority::start(Mode::Refuse);
        assert!(matches!(
            prepare(&refused.path, &selection(&native, &arguments)),
            Outcome::Refused(code) if code == "not_authorized"
        ));
        let lost = Authority::start(Mode::HangUp);
        assert!(matches!(
            prepare(&lost.path, &selection(&native, &arguments)),
            Outcome::Unknown
        ));
        let missing = Path::new("/nonexistent/servicing.sock");
        assert!(matches!(
            prepare(missing, &selection(&native, &arguments)),
            Outcome::Refused(code) if code == "servicing_unavailable"
        ));
    }
}
