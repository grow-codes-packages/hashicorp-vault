---
name: hashicorp-vault-sdk
description: Add and use the Grow Codes SDK for HashiCorp Vault (`hashicorp-vault`) in TypeScript, Rust, Go, Python or Java projects. Use when code must talk to HashiCorp Vault - installing @grow-codes/hashicorp-vault, the grow-hashicorp-vault crate or PyPI package, the Go module github.com/grow-codes-packages/hashicorp-vault/go or Maven codes.grow.packages:hashicorp-vault, configuring it with GROW_HASHICORP_VAULT_* variables, handling VaultError codes, testing with the bundled fakes, or running the Docker integration suite of this repository.
---

# HashiCorp Vault SDK (Grow Codes)

One API for HashiCorp Vault in five languages (categories: secrets). Pick the package for the
project's language, configure it from the environment, and handle errors by their canonical code.

## 1. Add the package

| Language | Command | Import |
| - | - | - |
| TypeScript | `npm install @grow-codes/hashicorp-vault` | `import { VaultClient } from "@grow-codes/hashicorp-vault"` |
| Rust | `cargo add grow-hashicorp-vault` (add `tokio` with `macros,rt-multi-thread`) | `use grow_hashicorp_vault::VaultClient;` |
| Go | `go get github.com/grow-codes-packages/hashicorp-vault/go` | `vault "github.com/grow-codes-packages/hashicorp-vault/go"` |
| Python | `pip install grow-hashicorp-vault` (or `uv add grow-hashicorp-vault`) | `from grow_hashicorp_vault import VaultClient` |
| Java | Maven `codes.grow.packages:hashicorp-vault` (Gradle `implementation("codes.grow.packages:hashicorp-vault:<version>")`) | `import codes.grow.packages.vault.VaultClient;` |

Check the latest version in the README badges before pinning one.

## 2. Configure

Prefer environment configuration so no credential is written into code:

```sh
export GROW_HASHICORP_VAULT_URL=https://vault.example.internal
export GROW_HASHICORP_VAULT_TOKEN=...            # from your secret store, never committed
```

Precedence: explicit config value > `GROW_HASHICORP_VAULT_*` > vendor variables (`VAULT_ADDR`,
`VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY`,
`VAULT_SKIP_VERIFY`; OpenBao's `BAO_*` names are not read) > default. Vault-specific:
`GROW_HASHICORP_VAULT_NAMESPACE` (Vault Enterprise),
`GROW_HASHICORP_VAULT_KV_MOUNT` (default `secret`), `GROW_HASHICORP_VAULT_KV_VERSION` (`1`/`2`, default
auto-detect) and `GROW_HASHICORP_VAULT_SECRETS_PATH` (base path of `client.secrets()`). Leave the token
unset when the application logs in with AppRole, JWT, Kubernetes or userpass.
Other variables: `…_CONNECT_TIMEOUT`, `…_REQUEST_TIMEOUT`, `…_TOTAL_TIMEOUT` (`10s`, `1500`),
`…_MAX_RETRIES`, `…_CA_CERT`, `…_CLIENT_CERT`, `…_CLIENT_KEY`, `…_PROXY`. Environment proxies
(`HTTPS_PROXY`) are ignored unless `proxy` is set.

## 3. Use

Create one client per process and close it on shutdown (TypeScript `await client.close()`, Rust
`client.close().await`, Go `defer client.Close()`, Python `with …`/`close()`, Java
try-with-resources).

- `health()` never throws for an unhealthy service; check `healthy`.
- `ping()` verifies credentials (`AUTHENTICATION` error when they are wrong).
- All I/O is retried with jitter on 429/502/503/504 and connection errors; only idempotent calls
  are retried on 500.
- Errors carry `code` (`CONFIG`, `AUTHENTICATION`, `PERMISSION_DENIED`, `NOT_FOUND`, `CONFLICT`,
  `RATE_LIMITED`, `VALIDATION`, `UNAVAILABLE`, `TIMEOUT`, `UNSUPPORTED`, `CANCELLED`), `retryable`,
  `httpStatus` and `requestId`. Branch on the code, not on the message text. Go:
  `errors.Is(err, vault.ErrNotFound)`.

### Secrets

Read with `get`/`getString`/`getJson`/`require` (missing → `null`/`None`/`nil`, `require` →
`NOT_FOUND`), write with `set`, list with `list`, load into the environment with `loadEnv`, watch
with `watch`. Wrap the provider in `SecretCache` for hot paths. Values are `SecretValue` objects:
call `reveal()` only where the plain value is needed and never log it.

<!-- service:skill-usage — the service adds its own functions and examples here. -->

### HashiCorp Vault modules

| Need | Use (TypeScript names; other languages per their convention) |
| - | - |
| Log in without a static token | `client.auth.login(new AppRoleAuth(roleId, secretId))` (also `JwtAuth`, `KubernetesAuth(role)`, `UserpassAuth`, `TokenAuth`), then `client.auth.startRenewer({ onExpire })` |
| One secret value per path (portable code) | `client.secrets()` — the shared SecretsProvider over KV (`{"value": ...}`; versions = KV v2 versions) |
| Raw KV maps, versions, check-and-set | `client.kv(mount)` (`read`, `write(path, data, {cas})`, `patch`, `list`, `readMetadata`, `deleteVersions`, `undelete`, `destroy`) |
| Encrypt data without holding keys | `client.transit().encrypt(key, plaintext)` / `decrypt` / `rewrap`; `sign` / `verify`; `generateDataKey` |
| Short-lived database users | `client.database().getCredentials(role)` + `client.leases.manage(lease, { onExpire })` |
| TLS certificates | `client.pki().issueCertificate(role, commonName, { ttl })`, `revokeCertificate(serial)` |
| Policies, mounts, AppRole setup | `client.sys.writePolicy`, `enableSecretsEngine`, `enableAuthMethod`, `createAppRole`, `readRoleId`, `generateSecretId` |
| Check a policy before acting | `const caps = await client.sys.capabilitiesSelf([path])`; `caps.allows(path, Capability.Read)` (`capabilities(token, paths)` for another token) |
| Work in a Vault Enterprise namespace | `const team = client.withNamespace("team-a")` — a view with its own token (starts with the parent's); Vault Community Edition ignores the header |
| Hand a secret to another process once | `client.wrapping.wrap(data, ttl)` → token → `client.wrapping.unwrap(token)` |
| Initialise/unseal a test server | testing module: `init`, `unseal`, `seal`, `initStatus`, `waitForActive` (never in production code) |

Accessors per language: TypeScript/Python `client.auth`, `client.sys`, `client.wrapping`,
`client.leases` (properties) and `client.kv()`, `client.transit()`, `client.database()`,
`client.pki()`, `client.secrets()`; Rust/Java the same as methods (`client.auth()`, …; Rust
`client.kv().await?` detects the KV version); Go `client.Auth()`, `client.Leases()`,
`client.KV(ctx, mount)`, `client.Transit(mount)`, `client.Secrets()` / `client.SecretsWith(opts)`,
`client.WithNamespace(ns)` (returns `(*Client, error)`); Rust `client.with_namespace(ns)?`.
The same API exists for OpenBao in the `openbao` repository; the differences are listed in
`docs/compatibility.md`.

Errors to expect:

- `AUTHENTICATION`: bad, expired or revoked token (Vault answers 403 "permission denied" +
  "invalid token") and every rejected login (400/401/403).
- `UNAVAILABLE`: sealed or uninitialised server, a login whose backend failed (500, never
  retried), and Vault Enterprise 412 (retryable).
- `PERMISSION_DENIED`: a valid token whose policy does not allow the path.
- `NOT_FOUND`: missing (or soft-deleted) secret; `SecretsProvider.get` returns null instead.
- `CONFLICT`: KV check-and-set mismatch.
- `UNSUPPORTED`: a KV v2-only call on a KV v1 mount (raised before any request).
- `VALIDATION`: invalid input, a policy with bad HCL, `get(name, {version})` on KV v1, a mount path
  already in use.
- `CONFIG`: invalid configuration, e.g. a namespace that contains whitespace (`withNamespace`).

Details and examples for every function: `docs/functions/*.md` (published at
https://grow-codes-packages.github.io/hashicorp-vault/).

## 4. Test code that uses the SDK

Use the in-memory fakes from the testing module instead of a real HashiCorp Vault in unit tests:
TypeScript `@grow-codes/hashicorp-vault/testing`, Rust feature `testing`, Go package `testkit`, Python
`grow_hashicorp_vault.testing`, Java `codes.grow.packages.vault.testing`.

## 5. Work on this repository

Read `AGENTS.md` first. Short version: the five languages keep the same API; files with the
`Generated by sdk-kit` header are changed in sdk-kit, not here; `make lint coverage` must pass
(≥ 90 % lines and branches); `make test-docker LANGS="<lang>"` runs the integration suite against
`hashicorp/vault:2.2.2`. Service rules every language follows (error mapping, KV/SecretsProvider
mapping, health states, environment variables, namespace views, capabilities) are listed under
"Parity decisions" in
`docs/compatibility.md`; read them before changing behaviour in one language. Recorded responses
for unit tests live in each package's `fixtures` folder.
