# grow-hashicorp-vault (Rust)

Rust SDK for HashiCorp Vault by [Grow Codes](https://grow.codes). Async on tokio, with an
optional blocking client. Auth (token, AppRole, userpass, JWT, Kubernetes), KV v1/v2, transit,
database credentials with a lease manager, PKI, policies/mounts admin, response wrapping,
capabilities checks, Enterprise namespaces (`with_namespace`) and the Grow `SecretsProvider`.

```toml
[dependencies]
grow-hashicorp-vault = "0.1.0"
# blocking client:   features = ["blocking"]
# test fakes/runner: features = ["testing"] (dev-dependency)
```

```rust,no_run
use grow_hashicorp_vault::{VaultClient, VaultConfig};

#[tokio::main]
async fn main() -> grow_hashicorp_vault::Result<()> {
    // explicit > GROW_HASHICORP_VAULT_* > vendor variables > defaults
    let client = VaultClient::new(VaultConfig::from_env()?)?;
    println!("{:?}", client.health().await?);
    client.close().await;
    Ok(())
}
```

- Errors: one `Error` enum with `code()`, `http_status()`, `request_id()`, `is_retryable()`,
  `retry_after()`; messages never contain credentials.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation (drop the future or pass a `CancellationToken`), request hooks, `tracing` debug
  events.
- Tested against `hashicorp/vault:2.2.2`. Namespaces are Vault Enterprise only: Vault OSS
  ignores `X-Vault-Namespace` and serves the root namespace.
- MSRV 1.88. Licence Apache-2.0. Documentation: https://grow-codes-packages.github.io/hashicorp-vault/

Not affiliated with or endorsed by HashiCorp, Inc. or IBM; Vault is a trademark of HashiCorp,
Inc.

Development: `make deps build lint test coverage license pack docs` (see `Makefile`).
