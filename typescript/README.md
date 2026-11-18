# @grow-codes/hashicorp-vault

TypeScript SDK for [HashiCorp Vault](https://grow-codes-packages.github.io/hashicorp-vault/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/hashicorp-vault
```

```ts
import { VaultClient } from "@grow-codes/hashicorp-vault";

// Reads GROW_HASHICORP_VAULT_URL, GROW_HASHICORP_VAULT_TOKEN, timeouts, TLS and proxy settings.
const client = VaultClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `VaultError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/hashicorp-vault/testing`.

Documentation: https://grow-codes-packages.github.io/hashicorp-vault/ · Licence: Apache-2.0.
HashiCorp Vault is a trademark of HashiCorp, Inc. (an IBM company); this package is not affiliated with or endorsed by it.
