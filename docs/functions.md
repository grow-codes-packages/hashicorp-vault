# Functions

The HashiCorp Vault API of this SDK. Every function exists in all five languages with the same
behaviour; the module pages show each one with an example per language. Names follow each
language's convention (`createKey` in TypeScript and Java, `create_key` in Rust and Python,
`CreateKey` in Go with `ctx` first).

| Module | Accessor (TypeScript) | Functions | Page |
| - | - | - | - |
| Client | `client` | `health`, `ping`, `serverVersion`, `close` | [Client](client.md) |
| Auth | `client.auth` | `TokenAuth`, `AppRoleAuth`, `UserpassAuth`, `JwtAuth`, `KubernetesAuth`, `login`, `lookupSelf`, `renewSelf`, `revokeSelf`, `createToken`, `startRenewer` → `TokenRenewer` | [Auth](functions/auth.md) |
| KV v1 + v2 | `client.kv(mount?)`, `client.kvV1()`, `client.kvV2()` | `read`, `write`, `patch`, `delete`, `deleteVersions`, `undelete`, `destroy`, `list`, `readMetadata`, `writeMetadata`, `deleteMetadata` | [KV](functions/kv.md) |
| SecretsProvider | `client.secrets(options?)` | the shared [Secrets](secrets.md) interface over KV | [Secrets over KV](functions/secrets-provider.md) |
| Transit | `client.transit(mount?)` | `createKey`, `readKey`, `listKeys`, `rotateKey`, `updateKeyConfig`, `deleteKey`, `encrypt`, `decrypt`, `rewrap`, `encryptBatch`, `decryptBatch`, `generateDataKey`, `hmac`, `sign`, `verify`, `hash`, `randomBytes` | [Transit](functions/transit.md) |
| Database + leases | `client.database(mount?)`, `client.leases` | `configureConnection`, `readConnection`, `deleteConnection`, `createRole`, `readRole`, `deleteRole`, `getCredentials` → `Lease`; `LeaseManager`: `renew`, `revoke`, `revokePrefix`, `lookup`, `manage` (auto-renew, `onExpire`) | [Database](functions/database.md) |
| PKI | `client.pki(mount?)` | `issueCertificate`, `signCsr`, `revokeCertificate`, `readCaChain`, `readCertificate`, `listCertificates`, `tidy`, `tidyStatus` | [PKI](functions/pki.md) |
| System + admin | `client.sys` | `health`, `sealStatus`, `leader`, `version`, `writePolicy`, `readPolicy`, `listPolicies`, `deletePolicy`, `listMounts`, `enableSecretsEngine`, `disableSecretsEngine`, `listAuthMethods`, `enableAuthMethod`, `disableAuthMethod`, `createAppRole`, `listAppRoles`, `deleteAppRole`, `readRoleId`, `generateSecretId` | [System](functions/system.md) |
| Capabilities + namespaces | `client.sys`, `client.withNamespace(ns)` | `capabilitiesSelf`, `capabilities` → `Capabilities` (`allows`), `withNamespace` (Vault Enterprise) | [Capabilities and namespaces](functions/namespaces.md) |
| Response wrapping | `client.wrapping` | `wrap`, `unwrap`, `lookupWrapping` | [Wrapping](functions/wrapping.md) |
| Testing | testing module | `init`, `unseal`, `seal`, `initStatus`, `waitForActive` | [Testing helpers](functions/testing.md) |

Every function is called against a real `hashicorp/vault:2.2.2` in the Docker suite of each
language, except the parts listed in [Compatibility](compatibility.md).

## Service configuration

| Setting | Default | Environment variables (precedence order) |
| - | - | - |
| `url` | `http://127.0.0.1:8200` | `GROW_HASHICORP_VAULT_URL`, `VAULT_ADDR` |
| `token` | none | `GROW_HASHICORP_VAULT_TOKEN`, `VAULT_TOKEN` |
| `namespace` (`X-Vault-Namespace`, Vault Enterprise) | none (root) | `GROW_HASHICORP_VAULT_NAMESPACE`, `VAULT_NAMESPACE` |
| `tls.caCertPath` | none | `GROW_HASHICORP_VAULT_CA_CERT`, `VAULT_CACERT` |
| `tls.clientCertPath` / `clientKeyPath` | none | `GROW_HASHICORP_VAULT_CLIENT_CERT` / `_KEY`, `VAULT_CLIENT_CERT` / `VAULT_CLIENT_KEY` |
| `tls.insecureSkipVerify` | `false` | `GROW_HASHICORP_VAULT_INSECURE_SKIP_VERIFY`, `VAULT_SKIP_VERIFY` |
| `kvMount` | `secret` | `GROW_HASHICORP_VAULT_KV_MOUNT` |
| `kvVersion` | auto-detect per mount | `GROW_HASHICORP_VAULT_KV_VERSION` (`1`, `2`; `0` = auto) |
| `secretsPath` (base path of `client.secrets()`) | `""` (mount root) | `GROW_HASHICORP_VAULT_SECRETS_PATH` |
| `valueField` (data field of a `client.secrets()` value) | `value` | — |

The common settings (timeouts, retries, proxy, hooks, logger) are described in
[Configuration](configuration.md). Explicit values win over `GROW_HASHICORP_VAULT_*`, which wins over the
vendor variables (`VAULT_*`; OpenBao's `BAO_*` names are not read). Leave `token` unset when the
client logs in with an auth method.
