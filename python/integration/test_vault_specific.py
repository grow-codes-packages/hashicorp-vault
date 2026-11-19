"""Vault-only surface against the real server: token capabilities and ``with_namespace`` views."""

from __future__ import annotations

import asyncio

import pytest

import grow_hashicorp_vault as sdk


def _scoped_token(client: sdk.VaultClient, env: dict[str, str]) -> sdk.Secret:
    with sdk.VaultClient(client.config) as c:
        info = c.auth.login(
            sdk.AppRoleAuth(env["VAULT_TEST_APPROLE_ROLE_ID"], env["VAULT_TEST_APPROLE_SECRET_ID"])
        )
        return info.client_token


def test_capabilities_self_and_of_another_token(
    client: sdk.VaultClient, env: dict[str, str], run_id: str
) -> None:
    allowed = f"secret/data/app/{run_id}/x"
    denied = f"secret/data/denied/{run_id}"
    root = client.sys.capabilities_self("sys/mounts")
    assert root == {"sys/mounts": ["root"]} and root.allows("sys/mounts", sdk.CAPABILITY_SUDO)
    scoped = _scoped_token(client, env)
    caps = client.sys.capabilities(scoped, [allowed, denied])
    assert set(caps[allowed]) == {"create", "read", "update", "patch", "delete"}
    assert caps[denied] == ["deny"]
    assert caps.allows(allowed, "read") and not caps.allows(denied, "read")
    with sdk.VaultClient(client.config) as c:
        c.set_token(scoped)
        mine = c.sys.capabilities_self([allowed, denied])
        assert mine == caps
        assert c.sys.capabilities_self("transit/encrypt/sdk-aes").allows(
            "transit/encrypt/sdk-aes", "update"
        )
        # The scoped policy has no update on sys/capabilities: a policy denial.
        with pytest.raises(sdk.PermissionDeniedError):
            c.sys.capabilities(scoped, "sys/mounts")


def test_with_namespace_view_round_trip(client: sdk.VaultClient, run_id: str) -> None:
    """Vault OSS ignores the namespace header (Enterprise only): the view reads and writes the
    root namespace, shares the pool and starts with the parent's token."""
    view = client.with_namespace("team-a")
    assert view.namespace == "team-a" and client.namespace is None
    assert view.token == client.token
    path = f"py/{run_id}/ns"
    view.kv().write(path, {"v": "from-view"})
    assert client.kv().read(path).data == {"v": "from-view"}
    assert client.with_namespace("").kv_v2().read(path).data == {"v": "from-view"}
    view.set_token("hvs.not-a-valid-token")
    with pytest.raises(sdk.AuthenticationError):
        view.ping()
    assert client.ping() >= 0  # parent token unchanged
    view.close()
    assert view.closed and not client.closed
    client.kv_v2().delete_metadata(path)


def test_async_capabilities_and_namespace(env: dict[str, str], run_id: str) -> None:
    async def run() -> None:
        async with sdk.AsyncVaultClient.from_env(env) as c:
            caps = await c.sys.capabilities_self(["sys/mounts", f"secret/data/py/{run_id}"])
            assert caps.allows("sys/mounts", "read")
            token = c.token
            assert token is not None
            other = await c.sys.capabilities(token, "sys/mounts")
            assert other == {"sys/mounts": ["root"]}
            view = c.with_namespace("team-b")
            await view.kv().write(f"py/{run_id}/ans", {"a": "1"})
            assert (await c.kv().read(f"py/{run_id}/ans")).data == {"a": "1"}
            await c.kv_v2().delete_metadata(f"py/{run_id}/ans")
        assert view.closed  # closing the parent closes its views

    asyncio.run(run())
