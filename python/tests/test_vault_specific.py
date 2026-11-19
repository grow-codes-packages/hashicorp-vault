"""Vault-only surface: token capabilities, ``with_namespace`` views, Vault error mapping and
Vault status fields (recorded fixtures from ``hashicorp/vault:2.2.2``)."""

from __future__ import annotations

import httpx
import pytest

import grow_hashicorp_vault as sdk
from vmock import TOKEN, Reply, Router, aclient, client, config, err


def test_capabilities_self_plural_single_and_root() -> None:
    r = Router()
    r.on(
        "POST",
        "sys/capabilities-self",
        "capabilities_self.plural",
        "capabilities_self.single",
        "capabilities_self.root",
    )
    allowed, denied = "secret/data/app/RUN/x", "secret/data/denied/RUN"
    with client(r) as c:
        caps = c.sys.capabilities_self([allowed, f"/{denied}/"])
        assert r.last().json == {"paths": [allowed, denied]}
        assert isinstance(caps, sdk.Capabilities) and isinstance(caps, dict)
        assert caps[allowed] == ["create", "delete", "patch", "read", "update"]
        assert caps[denied] == ["deny"]
        assert caps.allows(allowed, sdk.CAPABILITY_READ)
        assert caps.allows(f"/{allowed}", "update")
        assert not caps.allows(allowed, sdk.CAPABILITY_SUDO)
        assert not caps.allows(denied, "read")
        assert not caps.allows("not/requested", "read")
        # One path as a plain string (``{"paths": [path]}``).
        single = c.sys.capabilities_self("transit/encrypt/sdk-aes")
        assert r.last().json == {"paths": ["transit/encrypt/sdk-aes"]}
        assert single == {"transit/encrypt/sdk-aes": ["update"]}
        root = c.sys.capabilities_self("sys/mounts")
        assert root.allows("sys/mounts", "sudo") and root.allows("sys/mounts", "anything")
        assert r.last().headers["x-vault-token"] == TOKEN
        for bad in ([], [""], "  "):
            with pytest.raises(sdk.ValidationError):
                c.sys.capabilities_self(bad)


def test_capabilities_single_path_falls_back_to_capabilities_key() -> None:
    body = {"data": {"capabilities": ["read", "list"]}}
    r = Router().on("POST", "sys/capabilities-self", Reply(200, body))
    with client(r) as c:
        caps = c.sys.capabilities_self("kv1/x")
    assert caps == {"kv1/x": ["read", "list"]}
    # A legacy body without ``data`` is read from the top level.
    r2 = Router().on("POST", "sys/capabilities-self", Reply(200, {"a": ["read"], "b": "x"}))
    with client(r2) as c2:
        caps2 = c2.sys.capabilities_self(["a", "b"])
    assert caps2 == {"a": ["read"], "b": []}
    r3 = Router().on("POST", "sys/capabilities-self", Reply(204, None))
    with client(r3) as c3, pytest.raises(sdk.UnavailableError, match="empty response body"):
        c3.sys.capabilities_self("a")


def test_capabilities_of_another_token() -> None:
    r = Router().on("POST", "sys/capabilities", "capabilities.token", "capabilities.forbidden")
    other = "hvs.other-token-value"
    with client(r) as c:
        caps = c.sys.capabilities(sdk.Secret(other), ["secret/data/app/RUN/x", "sys/mounts"])
        assert r.last().json == {"token": other, "paths": ["secret/data/app/RUN/x", "sys/mounts"]}
        assert caps.allows("secret/data/app/RUN/x", "patch")
        assert not caps.allows("sys/mounts", "read")
        # A caller without update on sys/capabilities: policy denial, not an auth failure.
        with pytest.raises(sdk.PermissionDeniedError) as info:
            c.sys.capabilities(other, "sys/mounts")
        assert other not in str(info.value)
        with pytest.raises(sdk.ValidationError):
            c.sys.capabilities("", "sys/mounts")
        with pytest.raises(sdk.ValidationError):
            c.sys.capabilities(other, [])


async def test_async_capabilities() -> None:
    r = Router()
    r.on("POST", "sys/capabilities-self", "capabilities_self.single")
    r.on("POST", "sys/capabilities", "capabilities.token")
    async with aclient(r) as c:
        caps = await c.sys.capabilities_self("transit/encrypt/sdk-aes")
        assert caps.allows("transit/encrypt/sdk-aes", "update")
        other = await c.sys.capabilities("hvs.x-token", ["sys/mounts"])
        assert other == {"sys/mounts": ["deny"]}


def test_with_namespace_view() -> None:
    r = Router().on("GET", "secret/data/app/RUN/login", "namespace.header_kv")
    with client(r, kv_version=2) as c:
        team = c.with_namespace("/team-a/")
        assert team.namespace == "team-a" and team.config.namespace == "team-a"
        assert c.namespace is None
        assert team.kv().read("app/RUN/login").data == {"value": "login-ok"}
        seen = r.last()
        assert seen.headers["x-vault-namespace"] == "team-a"
        assert seen.headers["x-vault-token"] == TOKEN  # starts with the parent's token
        c.kv().read("app/RUN/login")
        assert "x-vault-namespace" not in r.last().headers  # parent unchanged
        # Own token afterwards: changes do not cross between parent and view.
        team.set_token("hvs.view-token")
        c.kv().read("app/RUN/login")
        assert r.last().headers["x-vault-token"] == TOKEN
        team.kv().read("app/RUN/login")
        assert r.last().headers["x-vault-token"] == "hvs.view-token"
        c.set_token("hvs.parent-new")
        team.kv().read("app/RUN/login")
        assert r.last().headers["x-vault-token"] == "hvs.view-token"
        # Own KV caches; shared connection pool.
        assert team.kv() is not c.kv() and team.kv() is team.kv()
        assert team._transport is c._transport
        # "" = root namespace (no header); nested views.
        root = team.with_namespace("")
        assert root.namespace is None
        root.kv().read("app/RUN/login")
        assert "x-vault-namespace" not in r.last().headers
        nested = c.with_namespace("team-a/child")
        nested.kv().read("app/RUN/login")
        assert r.last().headers["x-vault-namespace"] == "team-a/child"
        assert "hvs.view-token" in c._known_secrets()
        with pytest.raises(sdk.ConfigError):
            c.with_namespace("bad ns")
        with pytest.raises(sdk.ValidationError):
            c.with_namespace(None)  # type: ignore[arg-type]
        # Closing a view leaves the parent (and the pool) usable.
        nested.close()
        nested.close()
        assert nested.closed and not c.closed
        c.kv().read("app/RUN/login")
    # Closing the parent closes every view (and views of views).
    assert c.closed and team.closed and root.closed
    with pytest.raises(sdk.ValidationError, match="closed"):
        c.with_namespace("x")


async def test_async_with_namespace_view() -> None:
    r = Router().on("GET", "secret/data/a", "kv2.read")
    async with aclient(r, kv_version=2) as c:
        view = c.with_namespace("ns1")
        await view.kv().read("a")
        assert r.last().headers["x-vault-namespace"] == "ns1"
        assert r.last().headers["x-vault-token"] == TOKEN
        await c.kv().read("a")
        assert "x-vault-namespace" not in r.last().headers
        child = view.with_namespace("ns1/child")
        await child.aclose()
        assert child.closed and not view.closed
        await view.kv().read("a")
    assert c.closed and view.closed
    with pytest.raises(sdk.ValidationError):
        c.with_namespace("again")


def test_namespace_from_config_and_env() -> None:
    cfg = sdk.VaultConfig.from_env({"VAULT_NAMESPACE": "env-ns", "VAULT_ADDR": "http://x:1"})
    assert cfg.namespace == "env-ns"
    r = Router().on("GET", "sys/namespaces", "namespace.list")
    with sdk.VaultClient(config(namespace="cfg-ns"), http_transport=httpx.MockTransport(r)) as c:
        # Vault OSS answers sys/namespaces with 404 "enterprise-only feature".
        with pytest.raises(sdk.NotFoundError, match="enterprise-only"):
            c.request("GET", "sys/namespaces", list=True)
        assert r.last().headers["x-vault-namespace"] == "cfg-ns"
        assert c.with_namespace("").namespace is None


def test_vault_403_split() -> None:
    r = Router()
    r.on("GET", "auth/token/lookup-self", "ping.bad_token", "ping.no_token", "ping.lookup_self")
    r.on("GET", "secret/data/denied/x", "approle.denied_read")
    with client(r, kv_version=2) as c:
        # "2 errors occurred: permission denied, invalid token" → authentication.
        with pytest.raises(sdk.AuthenticationError):
            c.ping()
        # No token: plain "permission denied" → authentication.
        with pytest.raises(sdk.AuthenticationError):
            c.ping()
        assert c.ping() >= 0
        # Policy denial: "1 error occurred: permission denied" → permission denied.
        with pytest.raises(sdk.PermissionDeniedError):
            c.kv().read("denied/x")


def test_412_is_retryable_unavailable() -> None:
    r = Router().on("GET", "secret/data/a", err(412, "required index state not present"))
    with client(r, kv_version=2) as c, pytest.raises(sdk.UnavailableError) as info:
        c.kv().read("a")
    assert info.value.retryable and info.value.http_status == 412


def test_seal_status_build_date_and_unknown_fields() -> None:
    r = Router().on("GET", "sys/seal-status", "seal_status", Reply(200, {"sealed": True}))
    with client(r) as c:
        s = c.sys.seal_status()
        assert s.build_date and s.storage_type == "file" and s.type == "shamir"
        sealed = c.sys.seal_status()
        assert sealed.sealed and sealed.build_date == "" and sealed.version == ""
