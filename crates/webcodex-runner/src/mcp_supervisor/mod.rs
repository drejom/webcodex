//! Protected MCP-only provider supervisor (Linux, opt-in).
//!
//! `ProviderConnection` keeps ownership of request dispatch, but a provider
//! marked `supervisor_socket` is launched by a separate root service instead of
//! the Runner. The service starts only operator-profile providers, places each
//! physical connection in a fresh cgroup generation under a dedicated uid, and
//! before every `tools/call` prepares a single-use servicing association with
//! the external authority, revoking it afterwards. The authority performs
//! authenticated consume and operation reservation before effects; this module
//! grants no execution permission. If isolation is unavailable the provider is
//! unavailable: there is no fallback to a Runner-spawned process.
pub(crate) mod channel;
pub(crate) mod client;
pub(crate) mod generation;
pub(crate) mod process;
pub(crate) mod profile;
pub(crate) mod provider_io;
pub(crate) mod serve;
pub(crate) mod servicing;
pub(crate) mod wire;

pub(crate) use client::SupervisedConnection;
pub(crate) use wire::NativeFence;

#[cfg(test)]
mod tests;
