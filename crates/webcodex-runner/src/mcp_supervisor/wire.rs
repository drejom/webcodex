//! Private Runner<->supervisor control messages. Never a model tool or a
//! generic execution endpoint: the Runner can select only an operator-declared
//! provider reference and send MCP requests to the generation it opened.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use webcodex_core::mcp_gateway::{validate_json_value, MCP_GATEWAY_MAX_MESSAGE_BYTES};

/// Seqpacket bound. Large enough for one maximal provider result plus framing.
pub(crate) const MAX_PACKET_BYTES: usize =
    webcodex_core::mcp_gateway::MCP_GATEWAY_MAX_PROVIDER_MESSAGE_BYTES + 64 * 1024;
pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;

/// Native identity of the dispatched WebCodex invocation. The supervisor
/// forwards it to the servicing authority; it does not authenticate it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeFence {
    pub request_id: String,
    pub client_id: String,
    pub runner_instance_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Command {
    Open {
        provider: String,
    },
    Request {
        method: String,
        params: Value,
        timeout_ms: u64,
    },
    Call {
        native: NativeFence,
        name: String,
        arguments: Value,
        timeout_ms: u64,
    },
    Notify {
        method: String,
    },
}

/// `NotStarted`/`OutcomeUnknown`/`Completed` mirror `McpGatewayDispatchState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Dispatch {
    NotStarted,
    OutcomeUnknown,
    Completed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Reply {
    Opened { generation: String },
    Response { message: Value },
    Notified,
    Failed { code: String, dispatch: Dispatch },
}

impl Command {
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid());
        }
        let command: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        command.validate()?;
        Ok(command)
    }

    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        encode_bounded(self)
    }

    fn validate(&self) -> io::Result<()> {
        match self {
            Self::Open { provider } => identifier(provider),
            Self::Request {
                method,
                params,
                timeout_ms,
            } => {
                if !matches!(method.as_str(), "initialize" | "tools/list") {
                    return Err(invalid());
                }
                timeout(*timeout_ms)?;
                bounded(params)
            }
            Self::Call {
                native,
                name,
                arguments,
                timeout_ms,
            } => {
                identifier(&native.request_id)?;
                identifier(&native.client_id)?;
                identifier(&native.runner_instance_id)?;
                if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES || name.contains('\0') {
                    return Err(invalid());
                }
                if !arguments.is_object() {
                    return Err(invalid());
                }
                timeout(*timeout_ms)?;
                bounded(arguments)
            }
            Self::Notify { method } => {
                if method != "notifications/initialized" {
                    return Err(invalid());
                }
                Ok(())
            }
        }
    }
}

impl Reply {
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid());
        }
        serde_json::from_slice(bytes).map_err(|_| invalid())
    }

    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        encode_bounded(self)
    }

    pub(crate) fn failed(code: &str, dispatch: Dispatch) -> Self {
        Self::Failed {
            code: code.to_string(),
            dispatch,
        }
    }
}

fn encode_bounded(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > MAX_PACKET_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(crate) fn identifier(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid());
    }
    Ok(())
}

fn timeout(timeout_ms: u64) -> io::Result<()> {
    if timeout_ms == 0 || timeout_ms > 120_000 {
        return Err(invalid());
    }
    Ok(())
}

fn bounded(value: &Value) -> io::Result<()> {
    validate_json_value(
        value,
        MCP_GATEWAY_MAX_MESSAGE_BYTES,
        "supervised MCP params",
    )
    .map_err(|_| invalid())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid supervisor control")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_unlisted_methods_and_unknown_fields() {
        let call = Command::Request {
            method: "tools/call".into(),
            params: json!({}),
            timeout_ms: 1000,
        };
        assert!(call.encode().is_err());
        assert!(
            Command::decode(br#"{"command":"open","provider":"acg","executable":"/bin/sh"}"#)
                .is_err()
        );
        assert!(Command::decode(br#"{"command":"notify","method":"x"}"#).is_err());
    }

    #[test]
    fn call_requires_native_identity_and_object_arguments() {
        let native = NativeFence {
            request_id: "req-1".into(),
            client_id: "client".into(),
            runner_instance_id: "inst".into(),
        };
        let ok = Command::Call {
            native: native.clone(),
            name: "echo".into(),
            arguments: json!({"value": 1}),
            timeout_ms: 1000,
        };
        assert!(Command::decode(&ok.encode().unwrap()).is_ok());
        let bad = Command::Call {
            native: NativeFence {
                request_id: "has space".into(),
                ..native.clone()
            },
            name: "echo".into(),
            arguments: json!({}),
            timeout_ms: 1000,
        };
        assert!(bad.encode().is_err());
        let not_object = Command::Call {
            native,
            name: "echo".into(),
            arguments: json!([1]),
            timeout_ms: 1000,
        };
        assert!(not_object.encode().is_err());
    }
}
