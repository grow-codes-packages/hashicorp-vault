"""A tour of the HashiCorp Vault modules: KV, SecretsProvider, token capabilities, transit,
response wrapping, AppRole, namespaces, dynamic database credentials with a LeaseManager, and PKI.

Needs a token with admin rights (e.g. a dev server root token):

    export GROW_HASHICORP_VAULT_URL=http://127.0.0.1:8200 GROW_HASHICORP_VAULT_TOKEN=...
    python examples/python/vault_tour.py

Optional sections run only when their engine exists: ``VAULT_TEST_DB_ROLE`` (database role on
mount ``database``) and ``VAULT_TEST_PKI_ROLE`` + ``VAULT_TEST_PKI_DOMAIN`` (role on mount ``pki``).
"""

from __future__ import annotations

import os

import grow_hashicorp_vault as sdk


def kv_and_provider(client: sdk.VaultClient) -> None:
    kv = client.kv()  # mount "secret", KV version auto-detected
    meta = kv.write("examples/app", {"user": "app", "password": "s3cret"})
    print("kv version written:", meta.version if meta else "(kv v1)")
    print("kv keys:", sorted(kv.read("examples/app").data))  # values stay out of logs
    secrets = client.secrets(path="examples")
    secrets.set("api-key", "k-123", tags={"owner": "examples"})
    print("api-key exists:", secrets.exists("api-key"), secrets.get("api-key"))  # redacted
    secrets.delete("api-key", permanent=True)
    kv.delete_metadata("examples/app")


def capabilities_and_namespace(client: sdk.VaultClient) -> None:
    caps = client.sys.capabilities_self(["secret/data/examples/app", "sys/mounts"])
    print("may read secret/data/examples/app:", caps.allows("secret/data/examples/app", "read"))
    # Vault Enterprise only: OSS ignores the header and serves the root namespace.
    team = client.with_namespace("team-a")
    print("namespace view:", team.namespace, "healthy:", team.health().healthy)
    team.close()


def transit(client: sdk.VaultClient) -> None:
    t = client.transit()
    t.create_key("examples-key")  # idempotent
    ct = t.encrypt("examples-key", "hello transit")
    print("ciphertext:", ct.ciphertext[:16], "…")
    print("decrypted:", t.decrypt("examples-key", ct.ciphertext).decode())
    sig_key = t.create_key("examples-sign", "ed25519")
    sig = t.sign(sig_key.name, "message")
    print("signature valid:", t.verify(sig_key.name, "message", signature=sig.signature))
    print("sha2-256:", t.hash("message"))


def wrapping(client: sdk.VaultClient) -> None:
    info = client.wrapping.wrap({"one-time": "value"}, ttl_s=60)
    print("wrapping token:", info.token, "ttl", info.ttl_s)  # Secret prints [REDACTED]
    print("unwrapped keys:", sorted(client.wrapping.unwrap(info.token).data or {}))


def approle(client: sdk.VaultClient) -> None:
    if "examples-approle/" not in client.sys.list_auth_methods():
        client.sys.enable_auth_method("examples-approle", "approle")
    client.sys.create_app_role("app", mount="examples-approle", token_policies=["default"])
    role_id = client.sys.read_role_id("app", mount="examples-approle")
    secret = client.sys.generate_secret_id("app", mount="examples-approle")
    with sdk.VaultClient(sdk.VaultConfig(url=client.config.url)) as app:
        info = app.auth.login(sdk.AppRoleAuth(role_id, secret.secret_id, mount="examples-approle"))
        print("approle policies:", info.policies, "ttl", info.lease_duration_s)
        print("ping:", round(app.ping(), 1), "ms")
    client.sys.disable_auth_method("examples-approle")


def database(client: sdk.VaultClient) -> None:
    role = os.environ.get("VAULT_TEST_DB_ROLE")
    if not role:
        return
    lease = client.database().get_credentials(role)
    print("db user:", lease.data.username, "password:", lease.data.password)  # redacted
    handle = client.leases.manage(lease, on_expire=lambda: print("credentials expired"))
    print("lease managed until:", handle.expires_at)
    handle.stop()
    client.leases.revoke(lease.lease_id)


def pki(client: sdk.VaultClient) -> None:
    role, domain = (
        os.environ.get("VAULT_TEST_PKI_ROLE"),
        os.environ.get("VAULT_TEST_PKI_DOMAIN"),
    )
    if not role or not domain:
        return
    cert = client.pki().issue_certificate(role, f"app.{domain}", ttl_s=3600)
    print("certificate serial:", cert.serial_number)
    client.pki().revoke_certificate(cert.serial_number)


def main() -> None:
    with sdk.VaultClient.from_env() as client:
        print("server:", client.server_version(), client.health().status)
        kv_and_provider(client)
        capabilities_and_namespace(client)
        transit(client)
        wrapping(client)
        approle(client)
        database(client)
        pki(client)


if __name__ == "__main__":
    main()
