# Compatibility

## Runtimes

| Language | Supported | Tested in CI |
| - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 |
| Go | Go ≥ 1.26 | 1.26, 1.27 |
| Python | ≥ 3.10 | 3.10, 3.13, 3.14 |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 |

## HashiCorp Vault versions

The integration suite runs against `hashicorp/vault:2.2.2` (the tag of the Grow Codes stack
catalog), Vault Community Edition, in real server mode (not dev mode) with `file` storage and a
1-of-1 Shamir seal, plus a second, never-initialised server for the `testing` lifecycle helpers.
Community Edition has no auto-unseal, so a restarted server comes back sealed; the Docker bootstrap
unseals it again (tests can call `testing.unseal` instead). Other Vault versions with the same HTTP
API are expected to work; parsers ignore unknown fields and treat optional fields as optional.

Only the `GROW_HASHICORP_VAULT_*` variables and the standard Vault variables (`VAULT_ADDR`,
`VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`, `VAULT_CLIENT_CERT`/`VAULT_CLIENT_KEY`,
`VAULT_SKIP_VERIFY`) are read. OpenBao's `BAO_*` names are ignored by this package.

### Vault Enterprise features

| Feature | SDK support | Tested |
| - | - | - |
| Namespaces (`X-Vault-Namespace`) | `namespace` config / `VAULT_NAMESPACE` and `client.withNamespace(ns)` views | unit tests (header on every request, own token per view, close semantics). Vault Community Edition silently ignores the header and serves the root namespace, so the Docker suite only shows that a view works against the root namespace; a wrong namespace is **not** detected on Community Edition. |
| Performance standby nodes | `health()` status `perfstandby`, `sys.leader()` `performanceStandby` / `performanceStandbyLastRemoteWal` | unit tests with recorded bodies |
| Eventual consistency (HTTP 412 "required index state not present") | `UNAVAILABLE`, retryable | unit tests |

## Differences from the OpenBao SDK

This package has the same API as the [Grow Codes OpenBao SDK](https://github.com/grow-codes-packages/openbao)
(same modules, names, defaults and error mapping) plus the Vault-only additions. Behaviour that
differs because the servers differ (verified side by side against `openbao/openbao:2.7.2`):

| Area | HashiCorp Vault (this package) | OpenBao package |
| - | - | - |
| Environment | `GROW_HASHICORP_VAULT_*`, then `VAULT_*` | `GROW_OPENBAO_*`, then `BAO_*`, then `VAULT_*` |
| Vault-only API | `sys.capabilitiesSelf` / `sys.capabilities` → `Capabilities` with `allows(path, capability)`; `client.withNamespace(ns)` | — (OpenBao namespaces work through the `namespace` setting) |
| Namespaces | Enterprise only; Community Edition ignores the header | available in OpenBao; an unknown namespace is an error |
| Bad / expired token | 403 `permission denied` + `invalid token` → `AUTHENTICATION` | plain 403 `permission denied` → `AUTHENTICATION` |
| `sealStatus()` | `buildDate` | `commitDate` |
| `leader()` | `performanceStandby`, `performanceStandbyLastRemoteWal`; `haEnabled` is `false` with `file` storage | Raft indexes; `haEnabled` is `true` with Raft |
| Storage / seal in the fixture | `file` storage, Shamir seal (re-unsealed after a restart) | single-node Raft, static auto-unseal |
| Token format | `hvs.` service tokens | `s.` tokens |
| List pagination (`after` / `limit`) | not offered (Vault has none) | offered on KV and transit lists |
| Malformed request JSON | 500 (the SDK always sends valid JSON) | 400 |

## Service behaviour the SDK normalises

| HashiCorp Vault behaviour | What the SDK does (all languages) |
| - | - |
| 403 for both a bad token and a policy denial; they differ only in the body | A message naming an invalid or missing token (Vault: `permission denied` + `invalid token`), the plain `["permission denied"]` body or no error text → `AUTHENTICATION`; the wrapped `1 error occurred: * permission denied` form (policy denial) → `PERMISSION_DENIED` |
| Login endpoints answer 400 (`invalid role or secret ID`, `invalid username or password`, expired JWT), 401 or 403 for rejected credentials | `AUTHENTICATION` for every login method |
| Login endpoints answer 500 when the auth backend fails (e.g. the Kubernetes API is unreachable) | `UNAVAILABLE`; logins are never retried |
| One-shot endpoints (logins, unwrap, database credentials, secret-id generation, token create, PKI issue/sign, data keys, init, unseal) | never retried after a 5xx or an uncertain send, whatever the HTTP method |
| `400 path is already in use` when enabling an engine or auth method | `VALIDATION` |
| 400 `check-and-set parameter did not match` | `CONFLICT` |
| 405 (e.g. `PATCH` on a KV v1 mount) | `UNSUPPORTED` |
| 412 (Vault Enterprise: the node has not caught up yet), 501 (server not initialised), 503 (sealed) | `UNAVAILABLE` (retryable) |
| KV `DELETE` answers 204 for missing paths | `SecretsProvider.delete` reads first and raises `NOT_FOUND` |
| KV v2 404 with `data.metadata` for a deleted or destroyed version | `NOT_FOUND`; a key whose current version is deleted counts as missing in `get`, `exists`, `metadata`, `list` and `delete` |
| Transit batch: HTTP 400 with per-item results when one item fails | requests send `partial_failure_response_code: 207`, so per-item errors are returned, not thrown. A server that ignores the parameter answers 400 + `batch_results`: Rust, Go, Python and Java return those per-item results; TypeScript raises `VALIDATION` (its generated transport does not expose 4xx bodies) |
| `transit/verify` answers 200 `valid: false` for a bad signature | `verify` returns `false` |
| `pki/ca_chain` is raw PEM; `pki/tidy` is asynchronous (202) | `readCaChain` returns the PEM text; `tidy` returns the started status, `tidyStatus` polls |
| `sys/health` uses 429/472/473/501/503 for node states | `health()` asks for 200 in every state and maps the body to `active`, `standby`, `perfstandby`, `sealed` or `uninitialized`; any error is `unreachable`; `healthy` is true only for `active` |
| A newly enabled KV v2 mount answers 400 `Upgrading from non-versioned to versioned data` for a moment | callers that enable their own mounts should retry (the Docker suites do) |
| `Retry-After` on 429 only when `sys/quotas/config.enable_rate_limit_response_headers=true` | honoured when present, full-jitter backoff otherwise |

## Functions the Docker suite cannot serve

Every public function is called against the real service in the Docker suite. These parts cannot
be served by the single-node fixture; they are covered by unit tests with recorded responses:

| Function | Languages | Reason |
| - | - | - |
| `KubernetesAuth` successful login | all | The fixture has no Kubernetes API for the TokenReview call (Kubernetes auth points at an unreachable host). The Docker suite verifies the request; Vault answers 500 → `UNAVAILABLE`. The success path is unit-tested. |
| Effect of `withNamespace` / `namespace` | all | Namespaces are Vault Enterprise only; Community Edition ignores `X-Vault-Namespace`. The Docker suite shows that a view works against the root namespace; the header, token ownership and close semantics are unit-tested. |
| 412 and 429 answers, `performanceStandby` fields | all | Enterprise features or quotas not configured in the fixture; unit tests use recorded or documented bodies. |
| `health()` states `standby` / `perfstandby` | all | Single node with `file` storage (no HA). Unit tests use recorded bodies; `sealed` and `uninitialized` run in Docker (restart and the init server). |
| `TokenRenewer` / `LeaseManager.manage` timing edge cases (refresh-ahead, max-TTL capping, `onExpire` exactly once) | all | Fake clocks in unit tests; real renewals and a real 30 s lease expiry run in Docker too. |
| Retries on 5xx and network errors, `Retry-After` as an HTTP date, TLS/mTLS | all | Deterministic HTTP fixtures in the core unit tests (a real 429 with `Retry-After` was recorded). |

## Skipped conformance scenarios

| Scenario | Reason |
| - | - |
| — | none: the `core` and `secrets` scenarios run on KV v2 (`secret/`) and on KV v1 (`kv1/`) |

## Parity decisions

These rules are the same in all five packages (decided for the OpenBao pilot and applied here
unchanged, plus the Vault-only rules at the end):

- **Errors**: see the table above. Login 400/401/403 → `AUTHENTICATION` (TypeScript, Rust, Go,
  Python and Java identical).
- **SecretsProvider over KV**: one secret = one KV path stored as `{"value": "<string>"}` (field
  configurable with `valueField`); bytes that are not valid UTF-8 (TypeScript, Python, Rust: every
  byte input) are stored base64-encoded with `"encoding": "base64"`; objects are JSON-encoded into
  `value`. A path without the value field is returned as the JSON encoding of the whole map.
  Versions are the KV v2 version numbers as strings (`""` on KV v1). `list` returns names sorted,
  skips sub-folders, and on KV v2 reads metadata per key with a concurrency of 8.
- **Versions on KV v1**: `SecretsProvider.get(name, {version})` → `VALIDATION`; `KvV1.read` with a
  version and every v2-only operation (`patch`, `deleteVersions`, `undelete`, `destroy`, metadata
  calls, `cas`) → `UNSUPPORTED` without a request. A version must be a positive integer
  (`VALIDATION` otherwise).
- **Metadata `extra`** (KV v2): `maxVersions`, `casRequired` (`"true"`/`"false"`),
  `deleteVersionAfter` (whole seconds with an `s` suffix, e.g. `"0s"`, `"2592000s"`) and
  `oldestVersion`; `SetOptions.description` is stored as the custom metadata key `description`.
- **health()**: `details` holds `version`, `initialized`, `sealed`, `standby` and `clusterName`
  (when set); on errors `error` (and `httpStatus`). `sys.health()` returns the typed node state
  (`state`, `initialized`, `sealed`, `standby`, `performanceStandby`, `version`, `clusterName`,
  `clusterId`, `serverTime`).
- **Environment**: `GROW_HASHICORP_VAULT_KV_MOUNT`, `GROW_HASHICORP_VAULT_KV_VERSION` (`1`, `2`; `0` = auto-detect;
  anything else → `CONFIG`) and `GROW_HASHICORP_VAULT_SECRETS_PATH` set the defaults of `client.secrets()`
  and `client.kv()` in every language. `~/.vault-token` is not read.
- **`withNamespace(ns)`**: surrounding whitespace and slashes are removed; `""` (or `"/"`) is the
  root namespace; a namespace that still contains whitespace → `CONFIG` at once (also for the
  `namespace` setting); a closed client → `VALIDATION`. The view shares the connection pool, starts
  with the parent's current token and then owns its token, KV version cache, renewers, leases and
  watchers: logins and `setToken` on the view or the parent do not affect the other. Closing the
  view leaves the parent open; closing the parent closes its views.
- **Capabilities**: `capabilitiesSelf(paths)` / `capabilities(token, paths)` take one path or a
  list (surrounding slashes removed, at least one path) and return a map from each requested path
  to its capabilities. `allows(path, capability)`: `deny` anywhere → `false`, `root` → `true`, a
  path that was not requested → `false`. `capabilities` with another token needs `update` on
  `sys/capabilities` (`PERMISSION_DENIED` otherwise).
- **Lease manager**: `client.leases` / `leases()` in every language (Rust keeps
  `lease_manager()` as an alias).

## Language differences

The API is the same in every language; only the conventions differ:

| Topic | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Durations | `…Ms` numbers | `Duration` | `time.Duration` | float seconds `…_s` (or `timedelta`) | `Duration` |
| Async | `Promise` + `AbortSignal` | `async` (tokio) + `blocking` feature | sync with `ctx` | `VaultClient` + `AsyncVaultClient` | sync + `…Async` |
| Module accessors | `client.auth`, `client.sys`, `client.wrapping`, `client.leases` (properties); `client.kv()`, `client.transit()`, … | `client.auth()`, `client.leases()`, `client.kv().await?` (detects the KV version on access), `client.transit()`, … | `client.Auth()`, `client.Leases()`, `client.KV(ctx, mount)` (detects on access), `client.Transit(mount)`, … | like TypeScript (`client.auth`, `client.leases`, `client.kv()`) | `client.auth()`, `client.leases()`, `client.kv()`, … |
| Provider options | `client.secrets({mount, path, valueField})` | `client.secrets_with(SecretsProviderOptions{..})` | `client.SecretsWith(SecretsProviderOptions{...})` | `client.secrets(mount, path=, value_field=)` | `client.secrets(SecretsOptions.builder()…build())` |
| Server lifecycle helpers | `@grow-codes/hashicorp-vault/testing`: `init`, `unseal`, `seal`, `initStatus`, `waitForActive` | `grow_hashicorp_vault::testing::{init, unseal, unseal_reset, seal, init_status, wait_for_active}` (feature `testing`) | package `testkit`: `Init`, `Unseal`, `Seal`, `InitStatus`, `WaitForActive` | `grow_hashicorp_vault.testing.lifecycle`: `init`, `unseal`, `seal`, `init_status`, `wait_for_active` (+ `a…` async forms) | `codes.grow.packages.vault.testing.VaultTesting`: `init`, `initRecovery`, `unseal`, `resetUnseal`, `seal`, `initStatus`, `waitForActive` |
| `withNamespace` | returns the view (throws) | `Result<VaultClient>` | `(*Client, error)` | returns the view (raises) | returns the view (throws) |
| `Capabilities` | record + non-enumerable `allows`; names in `Capability` | `Capabilities` (derefs to a `BTreeMap`), names in `capability::*` | `Capabilities` map type, `Capability*` constants | `Capabilities` (`dict` subclass), `CAPABILITY_*` | `Capabilities` class (`asMap()`), constants `Capabilities.READ`, … |
| Raw request escape hatch | `client.request(method, path, opts)` | — | — | `client.request(method, path, …)` | `client.request(method, path, body)` |
| `loadEnv` target | `process.env` | `std::env` | `os.Setenv` | `os.environ` | system properties (Java cannot change the environment) |

Rust exposes `Auth::login_with` and Go `Auth.LoginWith` as a building block for custom auth
methods; the other languages implement the `AuthMethod` interface instead.
