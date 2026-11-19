# Testing helpers

Two kinds of test support ship in the testing module of each package:

- **In-memory fakes and the conformance runner** (shared by every Grow Codes package), see
  [Secrets → Testing](../secrets.md#testing).
- **Server lifecycle helpers** for test fixtures and bootstrap scripts: initialise, unseal and
  seal a server and wait until it is active. They are deliberately not part of the main client
  API.

| Function | What it does |
| - | - |
| `initStatus(client)` | `GET sys/init` → initialised or not |
| `init(client, {secretShares = 1, secretThreshold = 1, recoveryShares?, recoveryThreshold?})` | `PUT sys/init`; returns the unseal (or recovery) keys and the root token, all redacted; an initialised server → `VALIDATION`; never retried |
| `unseal(client, key)` | enters one key share (hex or base64), returns the seal status; an invalid key → `VALIDATION`. Reset the progress with `{reset: true}` (TypeScript, Python), `unseal_reset` (Rust) or `resetUnseal` (Java). |
| `seal(client)` | `PUT sys/seal` with the client token (root or sudo) |
| `waitForActive(client, timeout = 30 s)` | polls `sys.health()` until the node is `active`; `TIMEOUT` otherwise |

Where they live: TypeScript `@grow-codes/hashicorp-vault/testing`; Rust `grow_hashicorp_vault::testing` (feature
`testing`); Go package `github.com/grow-codes-packages/hashicorp-vault/go/testkit`; Python
`grow_hashicorp_vault.testing.lifecycle` (`a…` forms for `AsyncVaultClient`); Java
`codes.grow.packages.vault.testing.VaultTesting` (plus `initRecovery` for auto-unseal seals).

=== "TypeScript"

    ```ts
    import { init, initStatus, unseal, waitForActive } from "@grow-codes/hashicorp-vault/testing";

    const client = new VaultClient({ url: "http://hashicorp-vault-init:8200" });
    if (!(await initStatus(client))) {
      const res = await init(client, { secretShares: 1, secretThreshold: 1 });
      await unseal(client, res.keys[0]!);
      client.setToken(res.rootToken);
    }
    await waitForActive(client, { timeoutMs: 30_000 });
    ```

=== "Rust"

    ```rust
    use grow_hashicorp_vault::testing::{self, InitOptions};

    if !testing::init_status(&client).await? {
        let res = testing::init(&client, &InitOptions::default()).await?;
        testing::unseal(&client, res.keys[0].expose_secret()).await?;
        client.set_token(Some(res.root_token.clone()));
    }
    testing::wait_for_active(&client, Duration::from_secs(30)).await?;
    ```

=== "Go"

    ```go
    import "github.com/grow-codes-packages/hashicorp-vault/go/testkit"

    if ok, err := testkit.InitStatus(ctx, client, nil); err == nil && !ok {
        res, err := testkit.Init(ctx, client, &testkit.InitOptions{SecretShares: 1, SecretThreshold: 1})
        if err != nil {
            return err
        }
        if _, err := testkit.Unseal(ctx, client, res.Keys[0].Reveal(), nil); err != nil {
            return err
        }
        client.SetToken(res.RootToken.Reveal())
    }
    _, err := testkit.WaitForActive(ctx, client, 30*time.Second)
    ```

=== "Python"

    ```python
    from grow_hashicorp_vault.testing import lifecycle

    if not lifecycle.init_status(client):
        res = lifecycle.init(client, secret_shares=1, secret_threshold=1)
        lifecycle.unseal(client, res.keys[0])
        client.set_token(res.root_token)
    lifecycle.wait_for_active(client, timeout_s=30)
    ```

=== "Java"

    ```java
    if (!VaultTesting.initStatus(client)) {
      InitResult res = VaultTesting.init(client, 1, 1);
      VaultTesting.unseal(client, res.keys().get(0));
      client.setToken(res.rootToken());
    }
    VaultTesting.waitForActive(client, Duration.ofSeconds(30));
    ```
