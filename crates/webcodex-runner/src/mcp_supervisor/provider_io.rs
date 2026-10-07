//! Bounded newline JSON-RPC to one supervised provider. The supervisor owns
//! request ids; the Runner never selects them.
use super::process::ProviderProcess;
use super::wire::Dispatch;
use serde_json::{json, Value};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;
use webcodex_core::mcp_gateway::{
    MCP_GATEWAY_MAX_MESSAGE_BYTES, MCP_GATEWAY_MAX_PROVIDER_MESSAGE_BYTES,
};

const MAX_NOTIFICATIONS: usize = 32;

pub(crate) struct Failure {
    pub code: &'static str,
    pub dispatch: Dispatch,
}

impl Failure {
    fn before(code: &'static str) -> Self {
        Self {
            code,
            dispatch: Dispatch::NotStarted,
        }
    }
    fn after(code: &'static str) -> Self {
        Self {
            code,
            dispatch: Dispatch::OutcomeUnknown,
        }
    }
}

pub(crate) struct ProviderIo {
    next_id: u64,
    buffered: Vec<u8>,
}

impl ProviderIo {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            buffered: Vec::new(),
        }
    }

    /// Returns the provider's complete JSON-RPC response object; the Runner
    /// keeps its existing response validation.
    pub(crate) fn request(
        &mut self,
        process: &ProviderProcess,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.drain(process)?;
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or(Failure::before("provider_request_id_exhausted"))?;
        let mut bytes = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params,
        }))
        .map_err(|_| Failure::before("provider_request_invalid"))?;
        if bytes.len() > MCP_GATEWAY_MAX_MESSAGE_BYTES {
            return Err(Failure::before("provider_request_too_large"));
        }
        bytes.push(b'\n');
        self.write_all(process, &bytes, deadline)?;
        let mut notifications = 0;
        loop {
            let message = self
                .read_message(process, deadline)
                .map_err(Failure::after)?;
            if is_notification(&message) {
                notifications += 1;
                if notifications > MAX_NOTIFICATIONS {
                    return Err(Failure::after("provider_notification_flood"));
                }
                continue;
            }
            if message.get("method").is_some() {
                return Err(Failure::after("provider_callbacks_unsupported"));
            }
            // Correlation is checked here so a stale response cannot be
            // returned for a later request.
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                return Err(Failure::after("provider_unknown_response_id"));
            }
            return Ok(message);
        }
    }

    pub(crate) fn notify(
        &mut self,
        process: &ProviderProcess,
        method: &str,
        deadline: Instant,
    ) -> Result<(), Failure> {
        let mut bytes = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "method": method, "params": {},
        }))
        .map_err(|_| Failure::before("provider_request_invalid"))?;
        bytes.push(b'\n');
        self.write_all(process, &bytes, deadline)
            .map_err(|failure| Failure::before(failure.code))
    }

    fn write_all(
        &mut self,
        process: &ProviderProcess,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), Failure> {
        let fd = process.input.as_raw_fd();
        let mut written = 0;
        while written < bytes.len() {
            if let Err(code) = ready(fd, libc::POLLOUT, deadline) {
                return Err(if written == 0 {
                    Failure::before(code)
                } else {
                    Failure::after(code)
                });
            }
            let count =
                unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
            if count > 0 {
                written += count as usize;
            } else if count < 0 && retryable() {
                continue;
            } else {
                return Err(if written == 0 {
                    Failure::before("provider_stdin_failed")
                } else {
                    Failure::after("provider_stdin_failed")
                });
            }
        }
        Ok(())
    }

    /// Unsolicited non-notification output before a request desynchronizes
    /// the connection.
    fn drain(&mut self, process: &ProviderProcess) -> Result<(), Failure> {
        let mut notifications = 0;
        loop {
            while let Some(line) = self.pop_line().map_err(Failure::before)? {
                let value: Value = serde_json::from_slice(&line)
                    .map_err(|_| Failure::before("provider_malformed_json"))?;
                if !is_notification(&value) {
                    return Err(Failure::before("provider_unexpected_message"));
                }
                notifications += 1;
                if notifications > MAX_NOTIFICATIONS {
                    return Err(Failure::before("provider_notification_flood"));
                }
            }
            match self.read_available(process.output.as_raw_fd()) {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(code) => return Err(Failure::before(code)),
            }
        }
    }

    fn read_message(
        &mut self,
        process: &ProviderProcess,
        deadline: Instant,
    ) -> Result<Value, &'static str> {
        loop {
            if let Some(line) = self.pop_line()? {
                return serde_json::from_slice(&line).map_err(|_| "provider_malformed_json");
            }
            ready(process.output.as_raw_fd(), libc::POLLIN, deadline)?;
            if !self.read_available(process.output.as_raw_fd())? && process.exited() {
                return Err("provider_eof");
            }
        }
    }

    fn read_available(&mut self, fd: RawFd) -> Result<bool, &'static str> {
        let mut bytes = [0u8; 16 * 1024];
        let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            return if retryable() {
                Ok(false)
            } else {
                Err("provider_stdout_failed")
            };
        }
        if count == 0 {
            return Err("provider_eof");
        }
        // +2 allows the terminating CRLF of a maximal message.
        if self.buffered.len() + count as usize > MCP_GATEWAY_MAX_PROVIDER_MESSAGE_BYTES + 2 {
            return Err("provider_message_too_large");
        }
        self.buffered.extend_from_slice(&bytes[..count as usize]);
        Ok(true)
    }

    fn pop_line(&mut self) -> Result<Option<Vec<u8>>, &'static str> {
        let Some(end) = self.buffered.iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };
        let rest = self.buffered.split_off(end + 1);
        let mut line = std::mem::replace(&mut self.buffered, rest);
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            return Err("provider_malformed_json");
        }
        if line.len() > MCP_GATEWAY_MAX_PROVIDER_MESSAGE_BYTES {
            return Err("provider_message_too_large");
        }
        Ok(Some(line))
    }
}

fn ready(fd: RawFd, events: libc::c_short, deadline: Instant) -> Result<(), &'static str> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("provider_timeout");
        }
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("provider_unavailable");
        }
        if result > 0 {
            if poll.revents & events != 0 {
                return Ok(());
            }
            // POLLHUP on stdout still lets read() report EOF.
            if events == libc::POLLIN && poll.revents & libc::POLLHUP != 0 {
                return Ok(());
            }
            return Err("provider_unavailable");
        }
    }
}

fn retryable() -> bool {
    matches!(
        io::Error::last_os_error().kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

fn is_notification(value: &Value) -> bool {
    value.is_object()
        && value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && value.get("id").is_none()
        && value.get("method").is_some_and(Value::is_string)
}
