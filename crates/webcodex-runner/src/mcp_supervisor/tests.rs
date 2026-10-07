//! End-to-end supervisor tests without root: the test process runs the
//! supervisor serve loop in a thread inside its own delegated user cgroup and
//! launches the real fake MCP provider under the test uid. Root-only identity
//! change is covered by the privileged suite on the deployment host.
use super::channel::Channel;
use super::client::SupervisedConnection;
use super::generation;
use super::profile::{test_provider, PeerPolicy, Profile};
use super::serve;
use super::servicing::fake::{Authority, Mode};
use super::wire::{Dispatch, NativeFence};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

struct Harness {
    socket: PathBuf,
    authority: Authority,
    _dir: tempfile::TempDir,
}

fn cgroup_parent() -> Option<PathBuf> {
    // Generations must live in a cgroup this uid may write. Skip (not pass)
    // where the test runner was not given a delegated cgroup.
    let own = generation::own_cgroup().ok()?;
    let probe = own.join(format!("wc-probe-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&probe).ok()?;
    let _ = std::fs::remove_dir(&probe);
    Some(own)
}

fn fake_provider() -> PathBuf {
    crate::webcodex_runner::mcp_gateway::tests_support::fake_binary_path()
}

fn harness(mode: Mode, scenario: &str, marker: &Path) -> Option<Harness> {
    let cgroup = cgroup_parent()?;
    let authority = Authority::start(mode);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("supervisor.sock");
    let provider = test_provider(
        "fake",
        &fake_provider(),
        &[scenario.to_string(), marker.to_string_lossy().to_string()],
        &authority.path,
    );
    let profile = Arc::new(Profile {
        socket: socket.clone(),
        peer: PeerPolicy::Uid(unsafe { libc::getuid() }),
        providers: vec![provider],
    });
    let listener = serve::bind_for_test(&socket).unwrap();
    std::thread::spawn(move || serve::serve(listener, profile, cgroup));
    Some(Harness {
        socket,
        authority,
        _dir: dir,
    })
}

fn native(request_id: &str) -> NativeFence {
    NativeFence {
        request_id: request_id.into(),
        client_id: "client".into(),
        runner_instance_id: "instance".into(),
    }
}

fn open(harness: &Harness) -> SupervisedConnection {
    let mut connection =
        SupervisedConnection::open(&harness.socket, "fake", Duration::from_secs(5))
            .ok()
            .unwrap();
    connection
        .request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
            Duration::from_secs(5),
        )
        .ok()
        .unwrap();
    connection
        .notify("notifications/initialized", Duration::from_secs(5))
        .ok()
        .unwrap();
    connection
}

macro_rules! require_cgroup {
    ($harness:expr) => {
        match $harness {
            Some(harness) => harness,
            None => {
                eprintln!("skipped: no delegated writable cgroup for this uid");
                return;
            }
        }
    };
}

#[test]
fn provider_runs_in_fresh_generation_and_call_is_prepared_then_revoked() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("marker.log");
    let harness = require_cgroup!(harness(Mode::Prepare, "normal", &marker));
    let mut first = open(&harness);
    let mut second = open(&harness);
    assert_ne!(
        first.generation(),
        second.generation(),
        "one generation per connection"
    );

    let response = first
        .call(
            &native("req-1"),
            "echo",
            json!({"value": "hello"}),
            Duration::from_secs(5),
        )
        .ok()
        .expect("call succeeds");
    assert!(response.get("result").is_some());
    assert_eq!(harness.authority.actions(), vec!["prepare", "revoke"]);
    let prepare = harness.authority.requests.lock().unwrap()[0].clone();
    assert_eq!(prepare["native"]["request_id"], "req-1");
    assert!(prepare["cgroup"]
        .as_str()
        .unwrap()
        .ends_with(&format!("wc-gen-{}", first.generation())));
    let _ = second.request("tools/list", json!({}), Duration::from_secs(5));
}

#[test]
fn refused_servicing_never_writes_the_call_to_the_provider() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("marker.log");
    let harness = require_cgroup!(harness(Mode::Refuse, "normal", &marker));
    let mut connection = open(&harness);
    let failure = connection
        .call(
            &native("req-2"),
            "echo",
            json!({"value": "x"}),
            Duration::from_secs(5),
        )
        .err()
        .unwrap_or_else(|| panic!("refused"));
    assert_eq!(failure.dispatch, Dispatch::NotStarted);
    assert!(failure.code.starts_with("servicing_"));
    let log = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(!log.contains("call"), "provider saw no tools/call: {log}");
    assert_eq!(harness.authority.actions(), vec!["prepare"]);
}

#[test]
fn unknown_prepare_outcome_is_not_started_and_not_retried() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("marker.log");
    let harness = require_cgroup!(harness(Mode::HangUp, "normal", &marker));
    let mut connection = open(&harness);
    let failure = connection
        .call(&native("req-3"), "echo", json!({}), Duration::from_secs(5))
        .err()
        .unwrap_or_else(|| panic!("unknown"));
    assert_eq!(failure.code, "servicing_prepare_unknown");
    assert_eq!(failure.dispatch, Dispatch::NotStarted);
    assert_eq!(harness.authority.actions(), vec!["prepare"]);
    assert!(!std::fs::read_to_string(&marker)
        .unwrap_or_default()
        .contains("call"));
}

#[test]
fn closing_control_kills_and_removes_the_generation() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("marker.log");
    let harness = require_cgroup!(harness(Mode::Prepare, "normal", &marker));
    let connection = open(&harness);
    let leaf = generation::own_cgroup()
        .unwrap()
        .join(format!("wc-gen-{}", connection.generation()));
    assert!(leaf.exists());
    drop(connection);
    for _ in 0..200 {
        if !leaf.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "generation {} not removed after control close",
        leaf.display()
    );
}

#[test]
fn runner_cannot_select_unlisted_provider_or_method() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("marker.log");
    let harness = require_cgroup!(harness(Mode::Prepare, "normal", &marker));
    assert!(SupervisedConnection::open(&harness.socket, "other", Duration::from_secs(5)).is_err());
    let channel = Channel::connect(&harness.socket).unwrap();
    channel
        .send(
            br#"{"command":"request","method":"tools/call","params":{},"timeout_ms":1000}"#,
            std::time::Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let reply = channel
        .receive(Some(std::time::Instant::now() + Duration::from_secs(2)))
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&reply).contains("invalid_control"));
}

mod gateway {
    //! The Runner gateway path: McpGatewayManager -> ProviderEntry ->
    //! ProviderConnection(Supervised) -> supervisor -> provider.
    use super::*;
    use crate::webcodex_runner::config::{McpGatewayConfig, McpGatewayProviderConfig};
    use crate::webcodex_runner::mcp_gateway::{McpGatewayManager, NativeDispatch};
    use std::collections::BTreeMap;
    use webcodex_core::mcp_gateway::{
        McpGatewayDispatchState, McpGatewayRequest, McpGatewayResponsePayload,
    };

    fn manager(socket: &Path) -> McpGatewayManager {
        McpGatewayManager::new(&McpGatewayConfig {
            request_timeout_secs: 10,
            providers: vec![McpGatewayProviderConfig {
                id: "fake".into(),
                name: "Fake provider".into(),
                // Ignored for a supervised provider; the profile decides.
                executable: "/nonexistent/never-run".into(),
                args: Vec::new(),
                cwd: None,
                env_from_env: BTreeMap::new(),
                timeout_secs: None,
                supervisor_socket: Some(socket.to_string_lossy().into_owned()),
            }],
        })
    }

    fn call(
        manager: &McpGatewayManager,
        native: Option<NativeDispatch<'_>>,
    ) -> webcodex_core::mcp_gateway::McpGatewayResponse {
        let provider = manager.provider_inventory().remove(0);
        let McpGatewayResponsePayload::Tools { tools } = manager
            .handle(McpGatewayRequest::ToolsList {
                provider_id: provider.provider_id.clone(),
                provider_instance_id: provider.provider_instance_id.clone(),
            })
            .payload
            .expect("tools listed")
        else {
            panic!("not tools");
        };
        let echo = tools.iter().find(|tool| tool.name == "echo").unwrap();
        manager.handle_dispatched(
            McpGatewayRequest::ToolsCall {
                provider_id: provider.provider_id,
                provider_instance_id: provider.provider_instance_id,
                name: "echo".into(),
                arguments: json!({"value": "hello"}),
                expected_schema: echo.schema_observation(),
            },
            native,
        )
    }

    #[test]
    fn dispatched_call_carries_native_identity_to_servicing() {
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("marker.log");
        let harness = require_cgroup!(harness(Mode::Prepare, "normal", &marker));
        let manager = manager(&harness.socket);
        let response = call(
            &manager,
            Some(NativeDispatch {
                request_id: "native-req-7",
                client_id: "client-a",
                runner_instance_id: "runner-inst",
            }),
        );
        assert_eq!(
            response.dispatch_state,
            McpGatewayDispatchState::Completed,
            "{response:?}"
        );
        assert!(matches!(
            response.payload,
            Some(McpGatewayResponsePayload::ToolResult { .. })
        ));
        let prepare = harness.authority.requests.lock().unwrap()[0].clone();
        assert_eq!(prepare["native"]["request_id"], "native-req-7");
        assert_eq!(prepare["native"]["client_id"], "client-a");
        assert_eq!(prepare["native"]["runner_instance_id"], "runner-inst");
        assert_eq!(prepare["tool"], "echo");
        assert_eq!(harness.authority.actions(), vec!["prepare", "revoke"]);
    }

    #[test]
    fn supervised_call_without_native_identity_is_not_started() {
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("marker.log");
        let harness = require_cgroup!(harness(Mode::Prepare, "normal", &marker));
        let response = call(&manager(&harness.socket), None);
        assert_eq!(response.dispatch_state, McpGatewayDispatchState::NotStarted);
        assert!(harness.authority.actions().is_empty());
        assert!(!std::fs::read_to_string(&marker)
            .unwrap_or_default()
            .contains("call"));
    }

    #[test]
    fn servicing_refusal_maps_to_not_started_bridge_error() {
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("marker.log");
        let harness = require_cgroup!(harness(Mode::Refuse, "normal", &marker));
        let response = call(
            &manager(&harness.socket),
            Some(NativeDispatch {
                request_id: "r",
                client_id: "c",
                runner_instance_id: "i",
            }),
        );
        assert_eq!(response.dispatch_state, McpGatewayDispatchState::NotStarted);
        assert_eq!(response.error.unwrap().code, "provider_servicing_refused");
    }

    #[test]
    fn unavailable_supervisor_never_falls_back_to_local_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(&dir.path().join("absent.sock"));
        let provider = manager.provider_inventory().remove(0);
        let response = manager.handle(McpGatewayRequest::ToolsList {
            provider_id: provider.provider_id,
            provider_instance_id: provider.provider_instance_id,
        });
        assert_eq!(response.dispatch_state, McpGatewayDispatchState::NotStarted);
        assert_eq!(
            response.error.unwrap().code,
            "provider_supervisor_unavailable"
        );
    }
}
