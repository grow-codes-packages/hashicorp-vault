// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! # grow-hashicorp-vault
//!
//! Rust SDK for [HashiCorp Vault](https://grow-codes-packages.github.io/hashicorp-vault/) by
//! Grow Codes: one async client (tokio) for auth, KV v1/v2, transit, dynamic database
//! credentials with a lease manager, PKI, policies and mounts, response wrapping,
//! [capabilities](Sys::capabilities_self) checks, Enterprise
//! [namespaces](VaultClient::with_namespace) and the Grow
//! [`SecretsProvider`](secrets::SecretsProvider) over KV.
//!
//! Not affiliated with or endorsed by HashiCorp, Inc. or IBM; Vault is a trademark of
//! HashiCorp, Inc.
//!
//! ```no_run
//! # async fn demo() -> grow_hashicorp_vault::Result<()> {
//! use grow_hashicorp_vault::secrets::SecretsProvider;
//! use grow_hashicorp_vault::{VaultClient, VaultConfig};
//!
//! // explicit > GROW_HASHICORP_VAULT_* > VAULT_* > defaults
//! let client = VaultClient::new(VaultConfig::from_env()?)?;
//! println!("healthy: {}", client.health().await?.healthy);
//!
//! // KV v2 (auto-detected per mount)
//! let kv = client.kv().await?;
//! kv.write("app/db", serde_json::json!({"password": "s3cr3t"}), None).await?;
//! let secret = kv.read("app/db", None).await?;
//! assert_eq!(secret.data["password"], "s3cr3t");
//!
//! // transit
//! let ct = client.transit().encrypt("app-key", b"hello", None).await?;
//! let pt = client.transit().decrypt("app-key", &ct.ciphertext, None).await?;
//! assert_eq!(pt, b"hello");
//!
//! // the Grow SecretsProvider over KV
//! let secrets = client.secrets();
//! secrets.set("api-key", "abc123".into(), None).await?;
//! assert_eq!(secrets.get_string("api-key", None).await?.as_deref(), Some("abc123"));
//!
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes, the conformance
//! runner and the [`testing::init`] / [`testing::unseal`] server lifecycle helpers).
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod api;
mod auth;
mod client;
mod config;
mod database;
mod kv;
mod lease;
mod pki;
mod provider;
mod renew;
mod sys;
mod transit;
mod wrapping;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

// The generated test support (`src/testing/mod.rs`, owned by sdk-kit) is compiled as a
// private module and re-exported together with the service-owned server lifecycle helpers
// (`init`, `unseal`, `seal`, ...), so `grow_hashicorp_vault::testing` matches the `testing` module of
// the other four languages without editing the generated file.
#[cfg(feature = "testing")]
#[path = "testing/mod.rs"]
mod testing_generated;

#[cfg(feature = "testing")]
mod operator;

/// Test support (feature `testing`): in-memory fakes, the conformance runner (SPEC §6) and
/// the Vault server lifecycle helpers ([`testing::init`], [`testing::unseal`],
/// [`testing::seal`], [`testing::init_status`], [`testing::wait_for_active`]) used by test
/// fixtures and bootstrap scripts.
///
/// ```no_run
/// # async fn demo() -> grow_hashicorp_vault::Result<()> {
/// use grow_hashicorp_vault::testing::{self, InitOptions};
/// use grow_hashicorp_vault::{VaultClient, VaultConfig};
///
/// let client = VaultClient::new(VaultConfig::builder().url("http://hashicorp-vault:8200").build()?)?;
/// if !testing::init_status(&client).await? {
///     let init = testing::init(&client, &InitOptions::default()).await?;
///     testing::unseal(&client, init.keys[0].expose_secret()).await?;
///     client.set_token(Some(init.root_token.clone()));
/// }
/// testing::wait_for_active(&client, std::time::Duration::from_secs(30)).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing {
    pub use crate::operator::{
        init, init_status, seal, unseal, unseal_reset, wait_for_active, InitOptions, InitResult,
    };
    pub use crate::testing_generated::*;
}

pub mod secrets;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::{DEFAULT_KV_MOUNT, DEFAULT_URL, DEFAULT_VALUE_FIELD};

pub use crate::client::VaultClient;

pub use crate::config::VaultConfig;

pub use crate::config::VaultConfigBuilder;

pub use crate::auth::{
    AppRoleAuth, Auth, AuthInfo, AuthMethod, JwtAuth, KubernetesAuth, TokenAuth,
    TokenCreateOptions, TokenInfo, UserpassAuth, DEFAULT_KUBERNETES_JWT_PATH,
};
pub use crate::database::{Database, DatabaseConnectionConfig, DatabaseRole, Lease};
pub use crate::kv::{Kv, KvMetadata, KvMetadataOptions, KvSecret, KvV1, KvV2, KvVersionMetadata};
pub use crate::lease::{
    LeaseInfo, LeaseLookup, LeaseManager, ManageOptions, ManagedLease, OnLeaseError, OnLeaseExpire,
    OnLeaseRenew,
};
pub use crate::pki::{
    Certificate, CertificateInfo, IssueOptions, Pki, Revocation, TidyOptions, TidyStatus,
};
pub use crate::provider::{KvSecretsProvider, SecretsProviderOptions};
pub use crate::renew::{OnExpire, OnRenew, OnRenewError, TokenRenewer, TokenRenewerOptions};
pub use crate::sys::{
    capability, AppRoleOptions, Capabilities, HealthResponse, LeaderStatus, MountInfo,
    MountOptions, Policy, SealStatus, SecretId, SecretIdOptions, Sys,
};
pub use crate::transit::{
    CreateKeyOptions, DataKey, DataKeyOptions, EncryptOptions, HashOptions, HmacOptions,
    SignOptions, Transit, TransitBatchItem, TransitBatchResult, TransitCiphertext, TransitKey,
    TransitKeyConfig, TransitKeyVersion, TransitSignature,
};
pub use crate::wrapping::{SecretResponse, WrapInfo, WrapLookup, Wrapping};

/// Service-prefixed alias of [`Error`].
pub type VaultError = Error;
