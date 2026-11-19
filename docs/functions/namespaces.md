# Capabilities and namespaces

Two Vault-only additions on top of the API shared with the OpenBao SDK: capability checks, so a
caller can test a policy before acting, and namespace views for Vault Enterprise.

| Function | What it does |
| - | - |
| `sys.capabilitiesSelf(paths)` | `POST sys/capabilities-self`: the capabilities of the client token on each path. `paths` is one path or a list (surrounding slashes are removed; at least one path, else `VALIDATION`). |
| `sys.capabilities(token, paths)` | `POST sys/capabilities`: the capabilities of another token. The caller needs `update` on `sys/capabilities` (`PERMISSION_DENIED` otherwise). |
| `Capabilities` | map from each requested path to its capabilities (`create`, `read`, `update`, `patch`, `delete`, `list`, `sudo`, `root` or `deny`) |
| `Capabilities.allows(path, capability)` | `deny` → `false`; `root` → `true`; a path that was not requested → `false`; surrounding slashes of `path` are ignored |
| `client.withNamespace(ns)` | a client view that sends `X-Vault-Namespace: <ns>` on every request |

## Check a policy before acting

=== "TypeScript"

    ```ts
    import { Capability } from "@grow-codes/hashicorp-vault";

    const path = "secret/data/app/db";
    const caps = await client.sys.capabilitiesSelf([path, "sys/mounts"]);
    if (caps.allows(path, Capability.Read)) {
      const { data } = await client.kv().read("app/db");
    }
    console.log(caps[path]); // ["read", "update"]

    // Another token (needs update on sys/capabilities):
    const other = await client.sys.capabilities(appToken, path);
    ```

=== "Rust"

    ```rust
    use grow_hashicorp_vault::capability;

    let path = "secret/data/app/db";
    let caps = client.sys().capabilities_self([path, "sys/mounts"]).await?;
    if caps.allows(path, capability::READ) {
        let secret = client.kv_v2().read("app/db", None).await?;
    }
    println!("{:?}", caps.of(path)); // ["read", "update"]

    // Another token (needs update on sys/capabilities):
    let other = client.sys().capabilities(app_token, [path]).await?;
    ```

=== "Go"

    ```go
    path := "secret/data/app/db"
    caps, err := client.Sys().CapabilitiesSelf(ctx, path, "sys/mounts")
    if err != nil {
        return err
    }
    if caps.Allows(path, vault.CapabilityRead) {
        secret, err := client.KVv2("secret").Read(ctx, "app/db", nil)
        // ...
    }
    fmt.Println(caps[path]) // [read update]

    // Another token (needs update on sys/capabilities):
    other, err := client.Sys().Capabilities(ctx, appToken, path)
    ```

=== "Python"

    ```python
    import grow_hashicorp_vault as sdk

    path = "secret/data/app/db"
    caps = client.sys.capabilities_self([path, "sys/mounts"])
    if caps.allows(path, sdk.CAPABILITY_READ):
        secret = client.kv().read("app/db")
    print(caps[path])  # ['read', 'update']

    # Another token (needs update on sys/capabilities):
    other = client.sys.capabilities(app_token, path)
    ```

=== "Java"

    ```java
    String path = "secret/data/app/db";
    Capabilities caps = client.sys().capabilitiesSelf(path, "sys/mounts");
    if (caps.allows(path, Capabilities.READ)) {
      KvSecret secret = client.kv().read("app/db");
    }
    System.out.println(caps.get(path)); // [read, update]

    // Another token (needs update on sys/capabilities):
    Capabilities other = client.sys().capabilities(appToken, path);
    ```

## Namespace views (Vault Enterprise)

`withNamespace(ns)` returns a view of the client whose requests carry `X-Vault-Namespace: <ns>`.

- Surrounding whitespace and slashes are removed; `""` (or `"/"`) selects the root namespace (no
  header). A namespace that still contains whitespace is a `CONFIG` error at once; calling it on a
  closed client is a `VALIDATION` error.
- The view shares the connection pool. It starts with the parent's current token and then owns its
  token: a login or `setToken` on the view does not change the parent, and the other way round. KV
  version detection, token renewers, managed leases and secret watchers are per view.
- The parent is unchanged. Closing the view stops only its own background work; closing the parent
  also closes every view.
- A view can make further views (`team.withNamespace("team-a/child")` replaces the namespace).

!!! warning "Vault Enterprise only"
    Vault Community Edition silently ignores `X-Vault-Namespace` and serves the root namespace, so a
    view reads and writes the root namespace there and a wrong namespace is not detected. The
    `namespace` setting (`GROW_HASHICORP_VAULT_NAMESPACE`, `VAULT_NAMESPACE`) applies the same header
    to the whole client.

=== "TypeScript"

    ```ts
    const team = client.withNamespace("team-a");
    await team.auth.login(new AppRoleAuth(roleId, secretId)); // only the view's token changes
    const { data } = await team.kv().read("app/db");          // X-Vault-Namespace: team-a
    await team.close();                                       // the parent stays open
    ```

=== "Rust"

    ```rust
    let team = client.with_namespace("team-a")?;
    team.auth().login(AppRoleAuth::new(role_id, secret_id)).await?;
    let secret = team.kv_v2().read("app/db", None).await?;
    team.close().await;
    ```

=== "Go"

    ```go
    team, err := client.WithNamespace("team-a")
    if err != nil {
        return err // CONFIG for a namespace with whitespace
    }
    defer team.Close()
    _, err = team.Auth().Login(ctx, vault.NewAppRoleAuth(roleID, secretID))
    secret, err := team.KVv2("secret").Read(ctx, "app/db", nil)
    ```

=== "Python"

    ```python
    team = client.with_namespace("team-a")
    team.auth.login(sdk.AppRoleAuth(role_id, secret_id))
    secret = team.kv().read("app/db")
    team.close()
    ```

=== "Java"

    ```java
    try (VaultClient team = client.withNamespace("team-a")) {
      team.auth().login(new AppRoleAuth(roleId, secretId));
      KvSecret secret = team.kv().read("app/db");
    }
    ```
