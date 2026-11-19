# Grow Codes SDK for HashiCorp Vault

[![CI](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/grow-codes-packages/hashicorp-vault?sort=semver)](https://github.com/grow-codes-packages/hashicorp-vault/releases)
[![Docs](https://img.shields.io/badge/docs-grow--codes--packages.github.io-blue)](https://grow-codes-packages.github.io/hashicorp-vault/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [![npm](https://img.shields.io/npm/v/@grow-codes/hashicorp-vault)](https://www.npmjs.com/package/@grow-codes/hashicorp-vault) | [![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/hashicorp-vault/badges/coverage-typescript.json)](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml) |
| Rust | [![crates.io](https://img.shields.io/crates/v/grow-hashicorp-vault)](https://crates.io/crates/grow-hashicorp-vault) [![docs.rs](https://img.shields.io/docsrs/grow-hashicorp-vault)](https://docs.rs/grow-hashicorp-vault) | [![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/hashicorp-vault/badges/coverage-rust.json)](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml) |
| Go | [![Go Reference](https://pkg.go.dev/badge/github.com/grow-codes-packages/hashicorp-vault/go.svg)](https://pkg.go.dev/github.com/grow-codes-packages/hashicorp-vault/go) | [![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/hashicorp-vault/badges/coverage-go.json)](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml) |
| Python | [![PyPI](https://img.shields.io/pypi/v/grow-hashicorp-vault)](https://pypi.org/project/grow-hashicorp-vault/) | [![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/hashicorp-vault/badges/coverage-python.json)](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml) |
| Java | [![Maven Central](https://img.shields.io/maven-central/v/codes.grow.packages/hashicorp-vault)](https://central.sonatype.com/artifact/codes.grow.packages/hashicorp-vault) | [![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/hashicorp-vault/badges/coverage-java.json)](https://github.com/grow-codes-packages/hashicorp-vault/actions/workflows/ci.yml) |

Open-source client libraries for [HashiCorp Vault](#trademarks-and-disclaimer) in **TypeScript, Rust, Go,
Python and Java** — one API, five idiomatic packages, tested against a real HashiCorp Vault in Docker.

- **Typed client** with timeouts, retries with jitter, `Retry-After`, cancellation and one error
  model (`VaultError` with canonical codes) in every language.
- **Secrets stay secret**: credentials are redacted in `toString`, logs, hooks and error messages.
- **The HashiCorp Vault API**: AppRole / userpass / JWT / Kubernetes / token login with automatic token
  renewal, KV v1 and v2 (auto-detected per mount, check-and-set, versions, metadata), transit
  (encrypt, decrypt, rewrap, batch, data keys, sign, verify, HMAC, hash, random bytes), dynamic
  database credentials with a `LeaseManager`, PKI, policies, mounts, auth methods, AppRole
  administration, response wrapping, capability checks (`capabilitiesSelf` / `capabilities`) and
  namespace views (`withNamespace`, Vault Enterprise).
- **Secrets**: the shared Grow Codes `SecretsProvider` over KV — typed getters, `loadEnv`, change
  watching and a TTL cache with refresh-ahead.

## Contents

- [Supported service version](#supported-service-version)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Function overview](#function-overview)
- [Testing with Docker](#testing-with-docker)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Trademarks and disclaimer](#trademarks-and-disclaimer)
- [About Grow Codes](#about-grow-codes)

## Supported service version

Tested in CI against **`hashicorp/vault:2.2.2`** (the version pinned in the Grow Codes stack catalog), Vault
Community Edition in server mode (file storage, Shamir seal). Other versions with the same API usually
work. Vault Enterprise-only features (namespaces, performance standbys, eventual-consistency 412
answers) are implemented from the API documentation and covered by unit tests; see
[Compatibility](#compatibility) and [docs/compatibility.md](docs/compatibility.md).

## Install

| Language | Package | Install |
| - | - | - |
| TypeScript (Node.js ≥ 22.12) | `@grow-codes/hashicorp-vault` | `npm install @grow-codes/hashicorp-vault` |
| Rust (MSRV 1.88) | `grow-hashicorp-vault` | `cargo add grow-hashicorp-vault` |
| Go (1.26+) | `github.com/grow-codes-packages/hashicorp-vault/go` | `go get github.com/grow-codes-packages/hashicorp-vault/go` |
| Python (≥ 3.10) | `grow-hashicorp-vault` | `pip install grow-hashicorp-vault` |
| Java (17+) | `codes.grow.packages:hashicorp-vault` | see below |

Maven:

```xml
<dependency>
  <groupId>codes.grow.packages</groupId>
  <artifactId>hashicorp-vault</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("codes.grow.packages:hashicorp-vault:0.1.0")
```

## Quickstart

Every package reads its configuration from the environment (`GROW_HASHICORP_VAULT_URL`,
`GROW_HASHICORP_VAULT_TOKEN`, …, see [Configuration](#configuration)) or from an explicit config
object. The examples check the service health, make one authenticated call and store and read a
secret through the `SecretsProvider` (KV mount `secret`, version detected automatically).

### TypeScript

```ts
import { VaultClient } from "@grow-codes/hashicorp-vault";

const client = VaultClient.fromEnv();
try {
  const health = await client.health();
  console.log(health.healthy, health.status);
  console.log("latency ms:", await client.ping());
  const secrets = client.secrets();
  await secrets.set("app/db-password", "s3cret");
  const value = await secrets.require("app/db-password");
  console.log(String(value)); // SecretValue([REDACTED]); value.reveal() returns the text
} finally {
  await client.close();
}
```

### Rust

```rust
use grow_hashicorp_vault::secrets::SecretsProvider;
use grow_hashicorp_vault::VaultClient;

#[tokio::main]
async fn main() -> Result<(), grow_hashicorp_vault::Error> {
    let client = VaultClient::from_env()?;
    let health = client.health().await?;
    println!("{} {}", health.healthy, health.status);
    println!("latency: {:?}", client.ping().await?);
    let secrets = client.secrets();
    secrets.set("app/db-password", "s3cret".into(), None).await?;
    let value = secrets.require("app/db-password", None).await?;
    println!("{value}"); // SecretValue([REDACTED])
    client.close().await;
    Ok(())
}
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"

	vault "github.com/grow-codes-packages/hashicorp-vault/go"
)

func main() {
	ctx := context.Background()
	client, err := vault.NewClientFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	health, err := client.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(health.Healthy, health.Status)

	secrets := client.Secrets()
	if _, err := secrets.Set(ctx, "app/db-password", "s3cret", nil); err != nil {
		log.Fatal(err)
	}
	value, err := secrets.Require(ctx, "app/db-password", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(value) // SecretValue([REDACTED])
}
```

### Python

```python
from grow_hashicorp_vault import VaultClient

with VaultClient.from_env() as client:
    health = client.health()
    print(health.healthy, health.status)
    print("latency ms:", client.ping())
    secrets = client.secrets()
    secrets.set("app/db-password", "s3cret")
    print(secrets.require("app/db-password"))  # SecretValue([REDACTED])
```

Async code uses `AsyncVaultClient` with the same methods (`async with`, `await client.health()`).

### Java

```java
import codes.grow.packages.vault.VaultClient;

try (VaultClient client = VaultClient.fromEnv()) {
    var health = client.health();
    System.out.println(health.healthy() + " " + health.status());
    System.out.println("latency ms: " + client.ping());
    var secrets = client.secrets();
    secrets.set("app/db-password", "s3cret");
    System.out.println(secrets.require("app/db-password")); // SecretValue([REDACTED])
}
```

More complete programs live in [examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_HASHICORP_VAULT_*` variable > vendor variable > default.** A present but invalid value raises a
`ConfigError` that names the variable (never its value).

| Setting | Environment variable | Default |
| - | - | - |
| `url` | `GROW_HASHICORP_VAULT_URL`, `VAULT_ADDR` | `http://127.0.0.1:8200` |
| `token` | `GROW_HASHICORP_VAULT_TOKEN`, `VAULT_TOKEN` | none (log in with an auth method instead) |
| `namespace` (`X-Vault-Namespace`) | `GROW_HASHICORP_VAULT_NAMESPACE`, `VAULT_NAMESPACE` | root namespace (namespaces are Vault Enterprise only) |
| `kvMount` | `GROW_HASHICORP_VAULT_KV_MOUNT` | `secret` |
| `kvVersion` | `GROW_HASHICORP_VAULT_KV_VERSION` (`1`, `2`; `0` = auto) | auto-detect per mount |
| `secretsPath` (base path of `client.secrets()`) | `GROW_HASHICORP_VAULT_SECRETS_PATH` | mount root |
| `valueField` (KV field of a `client.secrets()` value) | — | `value` |
| `connectTimeout` | `GROW_HASHICORP_VAULT_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_HASHICORP_VAULT_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_HASHICORP_VAULT_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` | `GROW_HASHICORP_VAULT_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_HASHICORP_VAULT_CA_CERT`, `VAULT_CACERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_HASHICORP_VAULT_CLIENT_CERT` / `_KEY`, `VAULT_CLIENT_CERT` / `VAULT_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_HASHICORP_VAULT_INSECURE_SKIP_VERIFY`, `VAULT_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_HASHICORP_VAULT_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Only the `GROW_HASHICORP_VAULT_*` and the standard Vault (`VAULT_*`) names are read; OpenBao's `BAO_*`
names are ignored by this package. `~/.vault-token` is not read. A namespace that contains
whitespace is a `ConfigError`.

Durations accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention
(`request_timeout` in Python and Rust, `RequestTimeout` in Go). The full reference is in the
[documentation](https://grow-codes-packages.github.io/hashicorp-vault/).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`createKey` in
TypeScript and Java, `create_key` in Python and Rust, `CreateKey` in Go with `ctx` first). Each
module links to its documentation page with full examples in all five languages.

| Area | Functions | Description |
| - | - | - |
| Client | `health`, `ping`, `serverVersion`, `close` | liveness (never throws; `active`/`standby`/`perfstandby`/`sealed`/`uninitialized`/`unreachable`), authenticated round trip, server version, shutdown |
| [Auth](docs/functions/auth.md) (`client.auth`) | `TokenAuth`, `AppRoleAuth`, `UserpassAuth`, `JwtAuth`, `KubernetesAuth`; `login(method)`; `lookupSelf`, `renewSelf`, `revokeSelf`, `createToken`; `startRenewer` → `TokenRenewer` | auth methods; log in, set the token on the client, remember the method for re-login; token operations; renew at ~2/3 of the TTL, max-TTL detection, re-login, `onExpire` |
| [KV v1 + v2](docs/functions/kv.md) (`client.kv(mount)`) | `read`, `write` (`cas`), `patch`, `delete`, `list`; `deleteVersions`, `undelete`, `destroy`; `readMetadata`, `writeMetadata`, `deleteMetadata` | read and write secrets; KV version detected per mount; version lifecycle (KV v2); metadata (KV v2); v2-only calls on KV v1 → `UNSUPPORTED` |
| [Secrets (SecretsProvider over KV)](docs/functions/secrets-provider.md) (`client.secrets()`) | `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`; `list`, `set` (`cas`, `tags`), `delete` (`versions`, `permanent`), `metadata`; `loadEnv`, `watch`, `SecretCache` | typed reads; missing → null, `require` → `NOT_FOUND`; writes and metadata; versions are KV v2 versions; environment loading, change watching, TTL cache with refresh-ahead |
| [Transit](docs/functions/transit.md) (`client.transit(mount)`) | `createKey`, `readKey`, `listKeys`, `rotateKey`, `updateKeyConfig`, `deleteKey`; `encrypt`, `decrypt`, `rewrap`, `encryptBatch`, `decryptBatch`, `generateDataKey`; `hmac`, `sign`, `verify`, `hash`, `randomBytes` | key management; encryption as a service; batch items report errors per item; signatures (`verify` returns `false`, not an error), digests, random bytes |
| [Database credentials + leases](docs/functions/database.md) (`client.database(mount), client.leases`) | `getCredentials(role)` → `Lease`; `configureConnection`, `createRole` (+ read/delete); `LeaseManager`: `renew`, `revoke`, `revokePrefix`, `lookup`, `manage` | dynamic username/password with a lease; engine admin helpers; auto-renew until the max TTL, `onExpire` exactly once |
| [PKI](docs/functions/pki.md) (`client.pki(mount)`) | `issueCertificate`, `signCsr`, `revokeCertificate`; `readCaChain`, `readCertificate`, `listCertificates`; `tidy`, `tidyStatus` | issue, sign and revoke certificates; read the chain and issued certificates; asynchronous tidy |
| [System + admin](docs/functions/system.md) (`client.sys`) | `health`, `sealStatus`, `leader`, `version`; `writePolicy`, `readPolicy`, `listPolicies`, `deletePolicy`; `listMounts`, `enableSecretsEngine`, `disableSecretsEngine`, `listAuthMethods`, `enableAuthMethod`, `disableAuthMethod`; `createAppRole`, `listAppRoles`, `deleteAppRole`, `readRoleId`, `generateSecretId` | node state (no token needed); ACL policies; engines and auth methods; AppRole administration |
| [Capabilities + namespaces](docs/functions/namespaces.md) (`client.sys`, `client.withNamespace`) | `capabilitiesSelf(paths)`, `capabilities(token, paths)` → `Capabilities` (`allows(path, capability)`); `withNamespace(ns)` | check a policy before acting; a client view in a Vault Enterprise namespace (`X-Vault-Namespace`) |
| [Response wrapping](docs/functions/wrapping.md) (`client.wrapping`) | `wrap(data, ttl)`, `unwrap(token)`, `lookupWrapping(token)` | single-use handover of a secret |
| [Testing helpers](docs/functions/testing.md) (`testing module`) | `init`, `unseal`, `seal`, `initStatus`, `waitForActive`; in-memory fakes, conformance runner | server lifecycle for fixtures (not in the main client API); test code that uses the SDK without a server |

### Auth

`client.auth` — [documentation](docs/functions/auth.md)

| Function | Description |
| - | - |
| `TokenAuth`, `AppRoleAuth`, `UserpassAuth`, `JwtAuth`, `KubernetesAuth` | auth methods |
| `login(method)` | log in, set the token on the client, remember the method for re-login |
| `lookupSelf`, `renewSelf`, `revokeSelf`, `createToken` | token operations |
| `startRenewer` → `TokenRenewer` | renew at ~2/3 of the TTL, max-TTL detection, re-login, `onExpire` |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const info = await client.auth.login(new AppRoleAuth(roleId, secretId));
const renewer = await client.auth.startRenewer({ onExpire: () => console.warn("expired") });
```

**Rust**

```rust
let info = client.auth().login(AppRoleAuth::new(role_id, secret_id)).await?;
let renewer = client.auth().start_renewer(TokenRenewerOptions::default()).await?;
```

**Go**

```go
info, err := client.Auth().Login(ctx, vault.NewAppRoleAuth(roleID, secretID))
renewer, err := client.Auth().StartRenewer(ctx, nil)
```

**Python**

```python
info = client.auth.login(sdk.AppRoleAuth(role_id, secret_id))
renewer = client.auth.start_renewer(on_expire=lambda: print("expired"))
```

**Java**

```java
AuthInfo info = client.auth().login(new AppRoleAuth(roleId, secretId));
TokenRenewer renewer = client.auth().startRenewer(RenewalOptions.defaults());
```

</details>

### KV v1 + v2

`client.kv(mount)` — [documentation](docs/functions/kv.md)

| Function | Description |
| - | - |
| `read`, `write` (`cas`), `patch`, `delete`, `list` | read and write secrets; KV version detected per mount |
| `deleteVersions`, `undelete`, `destroy` | version lifecycle (KV v2) |
| `readMetadata`, `writeMetadata`, `deleteMetadata` | metadata (KV v2); v2-only calls on KV v1 → `UNSUPPORTED` |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const kv = client.kv("secret");
await kv.write("app/db", { password: "s3cret" }, { cas: 0 });
const { data, metadata } = await kv.read("app/db");
```

**Rust**

```rust
let kv = client.kv_at("secret").await?;
kv.write("app/db", json!({"password": "s3cret"}), Some(0)).await?;
let secret = kv.read("app/db", None).await?;
```

**Go**

```go
kv, err := client.KV(ctx, "secret")
_, err = kv.Write(ctx, "app/db", map[string]any{"password": "s3cret"}, &vault.KVWriteOptions{CAS: vault.Ptr(0)})
secret, err := kv.Read(ctx, "app/db", nil)
```

**Python**

```python
kv = client.kv("secret")
kv.write("app/db", {"password": "s3cret"}, cas=0)
secret = kv.read("app/db")
```

**Java**

```java
KvMount kv = client.kv("secret");
kv.write("app/db", Map.of("password", "s3cret"), 0);
KvSecret secret = kv.read("app/db");
```

</details>

### Secrets (SecretsProvider over KV)

`client.secrets()` — [documentation](docs/functions/secrets-provider.md)

| Function | Description |
| - | - |
| `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll` | typed reads; missing → null, `require` → `NOT_FOUND` |
| `list`, `set` (`cas`, `tags`), `delete` (`versions`, `permanent`), `metadata` | writes and metadata; versions are KV v2 versions |
| `loadEnv`, `watch`, `SecretCache` | environment loading, change watching, TTL cache with refresh-ahead |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const secrets = client.secrets({ path: "apps/web" });
await secrets.set("db-password", "s3cret");
const pw = await secrets.require("db-password"); // SecretValue, pw.reveal()
```

**Rust**

```rust
let secrets = client.secrets();
secrets.set("apps/web/db-password", "s3cret".into(), None).await?;
let pw = secrets.require("apps/web/db-password", None).await?;
```

**Go**

```go
secrets := client.SecretsWith(vault.SecretsProviderOptions{Path: "apps/web"})
_, err := secrets.Set(ctx, "db-password", "s3cret", nil)
pw, err := secrets.Require(ctx, "db-password", nil)
```

**Python**

```python
secrets = client.secrets(path="apps/web")
secrets.set("db-password", "s3cret")
pw = secrets.require("db-password")
```

**Java**

```java
VaultSecretsProvider secrets = client.secrets(SecretsOptions.builder().path("apps/web").build());
secrets.set("db-password", "s3cret");
SecretValue pw = secrets.require("db-password");
```

</details>

### Transit

`client.transit(mount)` — [documentation](docs/functions/transit.md)

| Function | Description |
| - | - |
| `createKey`, `readKey`, `listKeys`, `rotateKey`, `updateKeyConfig`, `deleteKey` | key management |
| `encrypt`, `decrypt`, `rewrap`, `encryptBatch`, `decryptBatch`, `generateDataKey` | encryption as a service; batch items report errors per item |
| `hmac`, `sign`, `verify`, `hash`, `randomBytes` | signatures (`verify` returns `false`, not an error), digests, random bytes |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
await client.transit().createKey("orders", "aes256-gcm96");
const { ciphertext } = await client.transit().encrypt("orders", "hello");
const plain = await client.transit().decrypt("orders", ciphertext); // Uint8Array
```

**Rust**

```rust
client.transit().create_key("orders", "aes256-gcm96", None).await?;
let ct = client.transit().encrypt("orders", b"hello", None).await?;
let plain = client.transit().decrypt("orders", &ct.ciphertext, None).await?;
```

**Go**

```go
transit := client.Transit("transit")
_, err := transit.CreateKey(ctx, "orders", "aes256-gcm96", nil)
ct, err := transit.Encrypt(ctx, "orders", []byte("hello"), nil)
plain, err := transit.Decrypt(ctx, "orders", ct.Ciphertext, nil)
```

**Python**

```python
client.transit().create_key("orders", "aes256-gcm96")
ct = client.transit().encrypt("orders", "hello")
plain = client.transit().decrypt("orders", ct.ciphertext)  # bytes
```

**Java**

```java
client.transit().createKey("orders", "aes256-gcm96");
Ciphertext ct = client.transit().encrypt("orders", "hello");
byte[] plain = client.transit().decrypt("orders", ct.ciphertext());
```

</details>

### Database credentials + leases

`client.database(mount), client.leases` — [documentation](docs/functions/database.md)

| Function | Description |
| - | - |
| `getCredentials(role)` → `Lease` | dynamic username/password with a lease |
| `configureConnection`, `createRole` (+ read/delete) | engine admin helpers |
| `LeaseManager`: `renew`, `revoke`, `revokePrefix`, `lookup`, `manage` | auto-renew until the max TTL, `onExpire` exactly once |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const lease = await client.database().getCredentials("readonly");
client.leases.manage(lease, { onExpire: () => reconnect() });
```

**Rust**

```rust
let lease = client.database().get_credentials("readonly").await?;
let managed = client.leases().manage(lease, ManageOptions::default());
```

**Go**

```go
lease, err := client.Database("database").GetCredentials(ctx, "readonly")
managed := client.Leases().Manage(lease, &vault.ManageOptions{OnExpire: func(*vault.Lease) { reconnect() }})
```

**Python**

```python
lease = client.database().get_credentials("readonly")
managed = client.leases.manage(lease, on_expire=reconnect)
```

**Java**

```java
Lease<DatabaseCredentials> lease = client.database().getCredentials("readonly");
ManagedLease managed = client.leases().manage(lease, RenewalOptions.defaults());
```

</details>

### PKI

`client.pki(mount)` — [documentation](docs/functions/pki.md)

| Function | Description |
| - | - |
| `issueCertificate`, `signCsr`, `revokeCertificate` | issue, sign and revoke certificates |
| `readCaChain`, `readCertificate`, `listCertificates` | read the chain and issued certificates |
| `tidy`, `tidyStatus` | asynchronous tidy |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const cert = await client.pki().issueCertificate("web", "app.example.test", { ttlMs: 3_600_000 });
await client.pki().revokeCertificate(cert.serialNumber);
```

**Rust**

```rust
let cert = client.pki().issue_certificate("web", "app.example.test", None).await?;
client.pki().revoke_certificate(&cert.serial_number).await?;
```

**Go**

```go
cert, err := client.PKI("pki").IssueCertificate(ctx, "web", "app.example.test", &vault.IssueOptions{TTL: time.Hour})
_, err = client.PKI("pki").RevokeCertificate(ctx, cert.SerialNumber)
```

**Python**

```python
cert = client.pki().issue_certificate("web", "app.example.test", ttl_s=3600)
client.pki().revoke_certificate(cert.serial_number)
```

**Java**

```java
IssuedCertificate cert = client.pki().issueCertificate("web", "app.example.test");
client.pki().revokeCertificate(cert.serialNumber());
```

</details>

### System + admin

`client.sys` — [documentation](docs/functions/system.md)

| Function | Description |
| - | - |
| `health`, `sealStatus`, `leader`, `version` | node state (no token needed) |
| `writePolicy`, `readPolicy`, `listPolicies`, `deletePolicy` | ACL policies |
| `listMounts`, `enableSecretsEngine`, `disableSecretsEngine`, `listAuthMethods`, `enableAuthMethod`, `disableAuthMethod` | engines and auth methods |
| `createAppRole`, `listAppRoles`, `deleteAppRole`, `readRoleId`, `generateSecretId` | AppRole administration |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
await client.sys.writePolicy("app", 'path "secret/data/app/*" { capabilities = ["read"] }');
await client.sys.createAppRole("web", { tokenPolicies: ["app"] });
const roleId = await client.sys.readRoleId("web");
```

**Rust**

```rust
client.sys().write_policy("app", r#"path "secret/data/app/*" { capabilities = ["read"] }"#).await?;
client.sys().create_app_role("web", &AppRoleOptions { token_policies: vec!["app".into()], ..Default::default() }).await?;
let role_id = client.sys().read_role_id("web", None).await?;
```

**Go**

```go
err := client.Sys().WritePolicy(ctx, "app", `path "secret/data/app/*" { capabilities = ["read"] }`)
err = client.Sys().CreateAppRole(ctx, "web", &vault.AppRoleOptions{TokenPolicies: []string{"app"}})
roleID, err := client.Sys().ReadRoleID(ctx, "web", "")
```

**Python**

```python
client.sys.write_policy("app", 'path "secret/data/app/*" { capabilities = ["read"] }')
client.sys.create_app_role("web", token_policies=["app"])
role_id = client.sys.read_role_id("web")
```

**Java**

```java
client.sys().writePolicy("app", "path \"secret/data/app/*\" { capabilities = [\"read\"] }");
client.sys().createAppRole("web", AppRoleOptions.builder().tokenPolicies("app").build());
String roleId = client.sys().readRoleId("web");
```

</details>

### Capabilities + namespaces

`client.sys`, `client.withNamespace` — [documentation](docs/functions/namespaces.md)

| Function | Description |
| - | - |
| `capabilitiesSelf(paths)`, `capabilities(token, paths)` → `Capabilities` | the capabilities of the client token (or another token) per path; `allows(path, capability)`: `root` grants everything, `deny` nothing |
| `withNamespace(ns)` | a view that sends `X-Vault-Namespace` on every request; shares the connection pool, starts with the parent's token and then owns its token. **Vault Enterprise only** — Vault Community Edition ignores the header |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const caps = await client.sys.capabilitiesSelf(["secret/data/app/db"]);
if (caps.allows("secret/data/app/db", Capability.Read)) { /* read it */ }
const team = client.withNamespace("team-a"); // X-Vault-Namespace: team-a
```

**Rust**

```rust
let caps = client.sys().capabilities_self(["secret/data/app/db"]).await?;
if caps.allows("secret/data/app/db", capability::READ) { /* read it */ }
let team = client.with_namespace("team-a")?;
```

**Go**

```go
caps, err := client.Sys().CapabilitiesSelf(ctx, "secret/data/app/db")
if err == nil && caps.Allows("secret/data/app/db", vault.CapabilityRead) { /* read it */ }
team, err := client.WithNamespace("team-a")
```

**Python**

```python
caps = client.sys.capabilities_self("secret/data/app/db")
if caps.allows("secret/data/app/db", sdk.CAPABILITY_READ): ...
team = client.with_namespace("team-a")
```

**Java**

```java
Capabilities caps = client.sys().capabilitiesSelf("secret/data/app/db");
if (caps.allows("secret/data/app/db", Capabilities.READ)) { /* read it */ }
VaultClient team = client.withNamespace("team-a");
```

</details>

### Response wrapping

`client.wrapping` — [documentation](docs/functions/wrapping.md)

| Function | Description |
| - | - |
| `wrap(data, ttl)`, `unwrap(token)`, `lookupWrapping(token)` | single-use handover of a secret |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const info = await client.wrapping.wrap({ apiKey: "k-123" }, 60_000);
const { data } = await client.wrapping.unwrap(info.token);
```

**Rust**

```rust
let info = client.wrapping().wrap(json!({"apiKey": "k-123"}), Duration::from_secs(60)).await?;
let out = client.wrapping().unwrap(info.token.expose_secret()).await?;
```

**Go**

```go
info, err := client.Wrapping().Wrap(ctx, map[string]any{"apiKey": "k-123"}, time.Minute)
out, err := client.Wrapping().Unwrap(ctx, info.Token.Reveal())
```

**Python**

```python
info = client.wrapping.wrap({"apiKey": "k-123"}, 60)
data = client.wrapping.unwrap(info.token).data
```

**Java**

```java
WrapInfo info = client.wrapping().wrap(Map.of("apiKey", "k-123"), Duration.ofMinutes(1));
UnwrapResult out = client.wrapping().unwrap(info.token());
```

</details>

### Testing helpers

`testing module` — [documentation](docs/functions/testing.md)

| Function | Description |
| - | - |
| `init`, `unseal`, `seal`, `initStatus`, `waitForActive` | server lifecycle for fixtures (not in the main client API) |
| in-memory fakes, conformance runner | test code that uses the SDK without a server |

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
import { init, unseal, waitForActive } from "@grow-codes/hashicorp-vault/testing";
const res = await init(client, { secretShares: 1, secretThreshold: 1 });
await unseal(client, res.keys[0]!);
```

**Rust**

```rust
use grow_hashicorp_vault::testing::{self, InitOptions};
let res = testing::init(&client, &InitOptions::default()).await?;
testing::unseal(&client, res.keys[0].expose_secret()).await?;
```

**Go**

```go
res, err := testkit.Init(ctx, client, &testkit.InitOptions{SecretShares: 1, SecretThreshold: 1})
_, err = testkit.Unseal(ctx, client, res.Keys[0].Reveal(), nil)
```

**Python**

```python
from grow_hashicorp_vault.testing import lifecycle
res = lifecycle.init(client, secret_shares=1, secret_threshold=1)
lifecycle.unseal(client, res.keys[0])
```

**Java**

```java
InitResult res = VaultTesting.init(client, 1, 1);
VaultTesting.unseal(client, res.keys().get(0));
```

</details>

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against a real HashiCorp Vault (`hashicorp/vault:2.2.2`) in Docker.
Each language package is packed and installed into a separate consumer project first, so the tests
use the package exactly as you would.

`docker/compose.yml` starts HashiCorp Vault in real server mode (not dev mode: `file` storage, a
1-of-1 Shamir seal), a second never-initialised server for the `init`/`unseal`/`seal` helpers,
PostgreSQL 18 for dynamic database credentials and a one-shot `bootstrap` that initialises and
unseals Vault, enables KV v1 (`kv1/`), KV v2 (`secret/`), transit, database, PKI, AppRole,
userpass, JWT (trusting Vault's own identity-token keys, so no external identity provider is
needed) and Kubernetes auth plus two scoped policies, and writes the test credentials to
`/bootstrap/env`. Vault Community Edition has no auto-unseal, so a restarted server comes back
sealed; the bootstrap unseals it again.

```sh
make test-docker                     # all five languages
make test-docker LANGS="go python"   # a subset
```

No host ports are published and every run uses its own Compose project, so runs never collide; the
stack is always removed afterwards (`docker compose down -v`). Unit tests need no Docker:
`make test` or `make coverage`.

## Compatibility

| | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.88 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` | sync + `CompletableFuture` |
| HashiCorp Vault | `hashicorp/vault:2.2.2` | `hashicorp/vault:2.2.2` | `hashicorp/vault:2.2.2` | `hashicorp/vault:2.2.2` | `hashicorp/vault:2.2.2` |

Functions that the single-node Community Edition fixture cannot serve (Kubernetes login success,
the effect of `withNamespace`, standby/412/429 answers, renewal timing edge cases) are unit-tested;
they are listed with the reason in [docs/compatibility.md](docs/compatibility.md), together with
the error mapping, the parity decisions shared by all five packages and the differences from the
[Grow Codes OpenBao SDK](https://github.com/grow-codes-packages/openbao), which has the same API.

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. All five languages keep the same API; a change lands in all of them
together. Parts of this repository are generated by
[sdk-kit](https://github.com/grow-codes-packages/sdk-kit) and changed there.

## Security

Please report vulnerabilities privately to [opensource@grow.codes](mailto:opensource@grow.codes).
See [SECURITY.md](SECURITY.md).

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks and disclaimer

This is an independent, community-maintained project. It is **not affiliated with, endorsed or
sponsored by HashiCorp, Inc. (an IBM company)**. HashiCorp Vault is a trademark of HashiCorp, Inc. (an IBM company); it is used here only to name the
service this SDK connects to. The HashiCorp Vault server is licensed separately by its owner
(BUSL-1.1 (source-available) server; `vault/api` client module is MPL-2.0).

The software is provided "AS IS", without warranties or conditions of any kind. Grow Codes is not
responsible for any damage, data loss, security incident, outage or cost that results from using it.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About Grow Codes

This SDK is built and maintained by [Grow Codes](https://grow.codes). Grow Codes publishes the
client libraries it builds as open source in the
[grow-codes-packages](https://github.com/grow-codes-packages) organisation, generated from one
shared kit so that every service and every language behaves the same way. Learn more at
[grow.codes](https://grow.codes).
