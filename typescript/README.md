# @grow-codes/hashicorp-vault

TypeScript SDK for [HashiCorp Vault](https://grow-codes-packages.github.io/hashicorp-vault/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/hashicorp-vault
```

```ts
import { VaultClient } from "@grow-codes/hashicorp-vault";

// Reads GROW_HASHICORP_VAULT_* (then VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, VAULT_CACERT, ...).
const client = VaultClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "active", details: { version: "2.2.2", ... } }
  await client.kv().write("app/db", { password: "s3cret" }); // KV v1/v2 auto-detected
  console.log((await client.kv().read("app/db")).data);
  console.log(await client.sys.capabilitiesSelf(["secret/data/app/db"]));
} finally {
  await client.close();
}
```

Every error is a `VaultError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Modules: `client.auth` (AppRole, Userpass, JWT, Kubernetes, token, `TokenRenewer`), `client.kv()`
(KV v1/v2), `client.transit()`, `client.database()` + `client.leases` (`LeaseManager`),
`client.pki()`, `client.sys` (health, policies, mounts, auth methods, AppRole admin,
`capabilities`/`capabilitiesSelf`), `client.wrapping`, `client.secrets()` (`SecretsProvider`) and
`client.withNamespace(ns)` (Vault Enterprise only; Vault OSS ignores the namespace header).

Test helpers (in-memory fakes, the conformance runner and `init`/`unseal`/`seal`/`waitForActive`)
live in `@grow-codes/hashicorp-vault/testing`.

Documentation: https://grow-codes-packages.github.io/hashicorp-vault/ · Licence: Apache-2.0.
HashiCorp Vault is a trademark of HashiCorp, Inc. (an IBM company); this package is not affiliated with or endorsed by it.
