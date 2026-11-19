// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! Blocking wrapper (feature `blocking`). Each client owns a tokio runtime with one worker
//! thread, so background work (lease renewal, secret watchers, retries' timers) keeps running
//! between blocking calls.
//!
//! Do not use it from inside an async runtime (calls would panic); use the async client there.
//!
//! The core calls (`health`, `ping`, `server_version`, `close`) have blocking methods. Every
//! service module is reached through [`VaultClient::block_on`] with the async API, so the
//! blocking client always offers exactly the async surface:
//!
//! ```no_run
//! # fn demo() -> grow_hashicorp_vault::Result<()> {
//! use grow_hashicorp_vault::blocking::VaultClient;
//! use grow_hashicorp_vault::secrets::SecretsProvider;
//!
//! let client = VaultClient::from_env()?;
//! let vault = client.async_client();
//! let ct = client.block_on(vault.transit().encrypt("app-key", b"hello", None))?;
//! let value = client.block_on(vault.secrets().get_string("api-key", None))?;
//! # let _ = (ct, value);
//! client.close();
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::time::Duration;

use crate::core::{Error, HealthStatus, Result};
use crate::{VaultClient as AsyncClient, VaultConfig};

/// Blocking client for Vault with the same methods as the async client.
#[derive(Debug)]
pub struct VaultClient {
    inner: AsyncClient,
    runtime: tokio::runtime::Runtime,
}

impl VaultClient {
    /// Creates a client from a configuration.
    pub fn new(config: VaultConfig) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("grow-hashicorp-vault-blocking")
            .enable_all()
            .build()
            .map_err(|e| Error::config("cannot start the tokio runtime").with_source(e))?;
        let inner = {
            let _guard = runtime.enter();
            AsyncClient::new(config)?
        };
        Ok(VaultClient { inner, runtime })
    }

    /// Creates a client from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::new(VaultConfig::from_env()?)
    }

    /// The wrapped async client.
    pub fn async_client(&self) -> &AsyncClient {
        &self.inner
    }

    /// Runs a future of the async API to completion on this client's runtime.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// See [`AsyncClient::health`].
    pub fn health(&self) -> Result<HealthStatus> {
        self.block_on(self.inner.health())
    }

    /// See [`AsyncClient::ping`].
    pub fn ping(&self) -> Result<Duration> {
        self.block_on(self.inner.ping())
    }

    /// See [`AsyncClient::server_version`].
    pub fn server_version(&self) -> Result<String> {
        self.block_on(self.inner.server_version())
    }

    /// See [`AsyncClient::close`]. Idempotent.
    pub fn close(&self) {
        self.block_on(self.inner.close());
    }
}

impl Drop for VaultClient {
    fn drop(&mut self) {
        self.inner.transport().close();
    }
}
