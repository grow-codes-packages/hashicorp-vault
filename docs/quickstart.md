# Quickstart

Connect to HashiCorp Vault, check that it is healthy, make an authenticated call and close the client.
The client reads `GROW_HASHICORP_VAULT_URL` and `GROW_HASHICORP_VAULT_TOKEN` (and the vendor variables
listed in [Configuration](configuration.md)), or takes the values in code.

```sh
export GROW_HASHICORP_VAULT_URL=http://127.0.0.1:8200
export GROW_HASHICORP_VAULT_TOKEN=...   # never commit real tokens
```

=== "TypeScript"

    ```ts
    import { VaultClient } from "@grow-codes/hashicorp-vault";

    const client = VaultClient.fromEnv();
    try {
      const health = await client.health();
      console.log("healthy:", health.healthy, health.status);
      console.log("ping:", await client.ping(), "ms");
      console.log("server version:", await client.serverVersion());
    } finally {
      await client.close();
    }
    ```

=== "Rust"

    ```rust
    use grow_hashicorp_vault::VaultClient;

    #[tokio::main]
    async fn main() -> grow_hashicorp_vault::Result<()> {
        let client = VaultClient::from_env()?;
        let health = client.health().await?;
        println!("healthy: {} {}", health.healthy, health.status);
        println!("ping: {:?}", client.ping().await?);
        println!("server version: {}", client.server_version().await?);
        client.close().await;
        Ok(())
    }
    ```

=== "Go"

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
        fmt.Println("healthy:", health.Healthy, health.Status)

        latency, err := client.Ping(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("ping:", latency)

        version, err := client.ServerVersion(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("server version:", version)
    }
    ```

=== "Python"

    ```python
    from grow_hashicorp_vault import VaultClient

    with VaultClient.from_env() as client:
        health = client.health()
        print("healthy:", health.healthy, health.status)
        print("ping:", client.ping(), "ms")
        print("server version:", client.server_version())
    ```

    Async code uses `AsyncVaultClient` with the same methods:

    ```python
    import asyncio
    from grow_hashicorp_vault import AsyncVaultClient

    async def main() -> None:
        async with AsyncVaultClient.from_env() as client:
            print(await client.health())

    asyncio.run(main())
    ```

=== "Java"

    ```java
    import codes.grow.packages.vault.VaultClient;
    import codes.grow.packages.vault.core.HealthStatus;

    public final class Quickstart {
      public static void main(String[] args) {
        try (VaultClient client = VaultClient.fromEnv()) {
          HealthStatus health = client.health();
          System.out.println("healthy: " + health.healthy() + " " + health.status());
          System.out.println("ping: " + client.ping().toMillis() + " ms");
          System.out.println("server version: " + client.serverVersion());
        }
      }
    }
    ```

## Store and read a secret

The `SecretsProvider` keeps one value per KV path (mount `secret`, KV v1/v2 detected
automatically); `client.kv()` gives the raw KV engine.

=== "TypeScript"

    ```ts
    const secrets = client.secrets();
    await secrets.set("app/db-password", "s3cret");
    const value = await secrets.require("app/db-password");
    console.log(String(value), value.reveal().length); // SecretValue([REDACTED]) 6
    ```

=== "Rust"

    ```rust
    use grow_hashicorp_vault::secrets::SecretsProvider;

    let secrets = client.secrets();
    secrets.set("app/db-password", "s3cret".into(), None).await?;
    let value = secrets.require("app/db-password", None).await?;
    println!("{value}"); // SecretValue([REDACTED])
    ```

=== "Go"

    ```go
    secrets := client.Secrets()
    if _, err := secrets.Set(ctx, "app/db-password", "s3cret", nil); err != nil {
        return err
    }
    value, err := secrets.Require(ctx, "app/db-password", nil)
    fmt.Println(value) // SecretValue([REDACTED])
    ```

=== "Python"

    ```python
    secrets = client.secrets()
    secrets.set("app/db-password", "s3cret")
    value = secrets.require("app/db-password")
    print(value, len(value.reveal()))  # SecretValue([REDACTED]) 6
    ```

=== "Java"

    ```java
    VaultSecretsProvider secrets = client.secrets();
    secrets.set("app/db-password", "s3cret");
    SecretValue value = secrets.require("app/db-password");
    System.out.println(value); // SecretValue([REDACTED])
    ```

## Next steps

- [Configuration](configuration.md): timeouts, retries, TLS, proxy, environment variables.
- [Functions](functions.md): the HashiCorp Vault API of this SDK (auth, KV, transit, database
  credentials, PKI, system, wrapping).
- [Error handling](errors.md): error codes and retries.
