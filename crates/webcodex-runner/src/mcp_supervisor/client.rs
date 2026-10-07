//! Runner side of one supervised provider connection. Closing the channel is
//! the cancellation signal: the supervisor then kills the whole generation.
use super::channel::Channel;
use super::wire::{Command, Dispatch, NativeFence, Reply};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

/// Extra time for the supervisor's own servicing exchange and reply.
const CONTROL_SLACK: Duration = Duration::from_secs(3);

pub(crate) struct SupervisedConnection {
    channel: Channel,
    generation: String,
}

pub(crate) struct ClientFailure {
    pub code: String,
    pub dispatch: Dispatch,
}

impl SupervisedConnection {
    pub(crate) fn open(
        socket: &Path,
        provider: &str,
        timeout: Duration,
    ) -> Result<Self, ClientFailure> {
        let channel = Channel::connect(socket).map_err(|_| ClientFailure {
            code: "supervisor_unavailable".into(),
            dispatch: Dispatch::NotStarted,
        })?;
        let mut connection = Self {
            channel,
            generation: String::new(),
        };
        match connection.exchange(
            &Command::Open {
                provider: provider.into(),
            },
            timeout,
        )? {
            Reply::Opened { generation } => {
                connection.generation = generation;
                Ok(connection)
            }
            _ => Err(protocol()),
        }
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }

    pub(crate) fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ClientFailure> {
        let command = Command::Request {
            method: method.into(),
            params,
            timeout_ms: millis(timeout),
        };
        match self.exchange(&command, timeout)? {
            Reply::Response { message } => Ok(message),
            _ => Err(protocol()),
        }
    }

    pub(crate) fn notify(&mut self, method: &str, timeout: Duration) -> Result<(), ClientFailure> {
        match self.exchange(
            &Command::Notify {
                method: method.into(),
            },
            timeout,
        )? {
            Reply::Notified => Ok(()),
            _ => Err(protocol()),
        }
    }

    pub(crate) fn call(
        &mut self,
        native: &NativeFence,
        name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> Result<Value, ClientFailure> {
        let command = Command::Call {
            native: native.clone(),
            name: name.into(),
            arguments,
            timeout_ms: millis(timeout),
        };
        match self.exchange(&command, timeout)? {
            Reply::Response { message } => Ok(message),
            _ => Err(protocol()),
        }
    }

    pub(crate) fn closed(&self) -> bool {
        self.channel.closed()
    }

    pub(crate) fn close(&self) {
        self.channel.shutdown();
    }

    fn exchange(&mut self, command: &Command, timeout: Duration) -> Result<Reply, ClientFailure> {
        let encoded = command.encode().map_err(|_| ClientFailure {
            code: "provider_request_invalid".into(),
            dispatch: Dispatch::NotStarted,
        })?;
        let deadline = Instant::now() + timeout + CONTROL_SLACK;
        self.channel
            .send(&encoded, deadline)
            .map_err(|_| ClientFailure {
                code: "supervisor_unavailable".into(),
                dispatch: Dispatch::NotStarted,
            })?;
        let reply = match self.channel.receive(Some(deadline)) {
            Ok(Some(bytes)) => Reply::decode(&bytes).map_err(|_| protocol())?,
            Ok(None) => {
                return Err(ClientFailure {
                    code: "supervisor_closed".into(),
                    dispatch: Dispatch::OutcomeUnknown,
                })
            }
            Err(_) => {
                // A late reply must not be read as the next command's reply.
                self.close();
                return Err(ClientFailure {
                    code: "supervisor_timeout".into(),
                    dispatch: Dispatch::OutcomeUnknown,
                });
            }
        };
        if let Reply::Failed { code, dispatch } = reply {
            return Err(ClientFailure { code, dispatch });
        }
        Ok(reply)
    }
}

impl Drop for SupervisedConnection {
    fn drop(&mut self) {
        self.close();
    }
}

fn millis(timeout: Duration) -> u64 {
    timeout.as_millis().clamp(1, 120_000) as u64
}

fn protocol() -> ClientFailure {
    ClientFailure {
        code: "supervisor_protocol_error".into(),
        dispatch: Dispatch::OutcomeUnknown,
    }
}
