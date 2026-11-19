"""Database + leases, PKI, system backend and response wrapping (recorded fixtures)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import grow_hashicorp_vault as sdk
from vmock import NO_CONTENT, Reply, Router, aclient, client, err, ok


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def wait(self, delay: float) -> bool:
        self.now += delay
        return False


def renew_reply(ttl: int, warnings: list[str] | None = None, renewable: bool = True) -> Reply:
    return ok(
        None,
        lease_id="database/creds/r/abc",
        lease_duration=ttl,
        renewable=renewable,
        warnings=warnings,
    )


# --------------------------------------------------------------------------- database


def test_database_credentials_and_admin() -> None:
    r = Router()
    r.on("GET", "database/creds/ro", "database.get_credentials", ok({"nope": 1}))
    r.on("GET", "database/creds/unknown", "database.get_credentials_missing_role")
    r.on(
        "POST",
        "database/config/pg",
        "database.configure_connection",
        "database.configure_connection_bad",
    )
    r.on("GET", "database/config/pg", "database.read_connection")
    r.on("DELETE", "database/config/pg", "database.create_role")
    r.on("POST", "database/roles/ro", "database.create_role")
    r.on("GET", "database/roles/ro", "database.read_role")
    r.on("DELETE", "database/roles/ro", "database.create_role")
    with client(r) as c:
        db = c.database()
        lease = db.get_credentials("ro")
        assert lease.lease_id.startswith("database/creds/") and lease.renewable
        assert lease.data.username and lease.lease_duration_s > 0
        assert lease.data.password.reveal() == "REDACTED"
        assert "password=Secret('[REDACTED]')" in repr(lease)
        with pytest.raises(sdk.UnavailableError, match="no credentials"):
            db.get_credentials("ro")
        with pytest.raises(sdk.ValidationError):
            db.get_credentials("unknown")
        db.configure_connection(
            "pg",
            plugin_name="postgresql-database-plugin",
            connection_url="postgresql://{{username}}:{{password}}@db:5432/x",
            username="admin",
            password=sdk.Secret("admin-password"),
            allowed_roles=["ro"],
            verify_connection=True,
            extra={"max_open_connections": 4},
        )
        assert r.last().json == {
            "max_open_connections": 4,
            "plugin_name": "postgresql-database-plugin",
            "connection_url": "postgresql://{{username}}:{{password}}@db:5432/x",
            "username": "admin",
            "password": "admin-password",
            "allowed_roles": ["ro"],
            "verify_connection": True,
        }
        with pytest.raises(sdk.ValidationError) as info:
            db.configure_connection("pg", plugin_name="p", connection_url="u", password="pw-secret")
        assert "pw-secret" not in str(info.value)
        conn = db.read_connection("pg")
        assert conn.plugin_name == "postgresql-database-plugin" and conn.allowed_roles
        assert "connection_url" in conn.connection_details
        db.delete_connection("pg")
        db.create_role(
            "ro",
            db_name="pg",
            creation_statements=["CREATE ROLE x"],
            revocation_statements=["DROP ROLE x"],
            renew_statements=[],
            rollback_statements=None,
            default_ttl_s=3600,
            max_ttl_s=7200,
        )
        assert r.last().json == {
            "db_name": "pg",
            "creation_statements": ["CREATE ROLE x"],
            "revocation_statements": ["DROP ROLE x"],
            "renew_statements": [],
            "default_ttl": "3600s",
            "max_ttl": "7200s",
        }
        role = db.read_role("ro")
        assert role.db_name and role.default_ttl_s > 0 and role.creation_statements
        db.delete_role("ro")
    creds = [s for s in r.seen if s.path == "/v1/database/creds/ro"]
    assert len(creds) == 2


def test_get_credentials_is_never_retried() -> None:
    r = Router().on("GET", "database/creds/ro", err(500, "boom"), "database.get_credentials")
    with client(r) as c, pytest.raises(sdk.UnavailableError):
        c.database().get_credentials("ro")
    assert len(r.seen) == 1


# --------------------------------------------------------------------------- leases


def test_lease_operations() -> None:
    r = Router()
    r.on(
        "PUT",
        "sys/leases/renew",
        "lease.renew",
        "lease.renew_over_max",
        "lease.renew_invalid",
    )
    r.on("PUT", "sys/leases/revoke", "lease.revoke")
    r.on("PUT", "sys/leases/revoke-prefix/database/creds/ro", "lease.revoke")
    r.on("PUT", "sys/leases/lookup", "lease.lookup", "lease.lookup_revoked")
    with client(r) as c:
        lm = c.leases
        renewed = lm.renew("database/creds/ro/abc", 600)
        assert r.last().json == {"lease_id": "database/creds/ro/abc", "increment": "600s"}
        assert renewed.lease_duration_s > 0 and renewed.renewable
        capped = lm.renew("database/creds/ro/abc")
        assert r.last().json == {"lease_id": "database/creds/ro/abc"}
        assert capped.warnings
        with pytest.raises(sdk.ValidationError):
            lm.renew("database/creds/ro/abc")
        lm.revoke("database/creds/ro/abc")
        lm.revoke_prefix("database/creds/ro")
        info = lm.lookup("database/creds/ro/abc")
        # Vault's lease lookup carries no ``path`` (OpenBao adds one).
        assert info.id and info.path == "" and info.ttl_s > 0 and info.expire_time is not None
        with pytest.raises(sdk.ValidationError):
            lm.lookup("database/creds/ro/abc")
        with pytest.raises(sdk.ValidationError):
            lm.revoke("")


def lease(ttl: float = 30, renewable: bool = True) -> sdk.Lease[Any]:
    return sdk.Lease("database/creds/r/abc", ttl, renewable, {}, [])


def test_manage_renews_detects_cap_and_expires_once() -> None:
    clock = FakeClock()
    r = Router()
    cap = ['TTL of "100h" exceeded the effective max_ttl']
    r.on("PUT", "sys/leases/renew", renew_reply(30), renew_reply(12, cap))
    renewals: list[sdk.LeaseRenewal] = []
    expired: list[int] = []
    with client(r) as c:
        handle = c.leases.manage(
            lease(),
            increment_s=30,
            on_renew=renewals.append,
            on_expire=lambda: expired.append(1),
            clock=clock,
            wait=clock.wait,
            background=False,
        )
        assert [x.lease_duration_s for x in renewals] == [30, 12]
        assert expired == [1] and handle.expired and not handle.running
        assert handle.lease_id == "database/creds/r/abc" and handle.lease.renewable
        assert c.leases.active_leases == 0
        handle.stop()
        with pytest.raises(sdk.ValidationError):
            c.leases.manage(sdk.Lease("", 1, True, {}, []))


def test_manage_revoke_on_stop_and_stop_all() -> None:
    r = Router()
    r.on("PUT", "sys/leases/revoke", NO_CONTENT, err(400, "lease not found"))
    errors: list[BaseException] = []
    with client(r) as c:
        h1 = c.leases.manage(lease(3600), revoke_on_stop=True)
        h2 = c.leases.manage(lease(3600), revoke_on_stop=True, on_error=errors.append)
        h3 = c.leases.manage(lease(3600, renewable=False), revoke_on_stop=True)
        assert c.leases.active_leases == 3 and h1.expires_at is not None
        h1.stop()
        h1.stop()
        c.leases.stop_all()
        assert c.leases.active_leases == 0
        assert not h2.running and not h3.running
    revokes = [s for s in r.seen if s.path == "/v1/sys/leases/revoke"]
    assert len(revokes) == 3
    assert len(errors) <= 1


async def test_async_leases_and_database() -> None:
    r = Router()
    r.on("GET", "database/creds/ro", "database.get_credentials")
    r.on("PUT", "sys/leases/lookup", "lease.lookup")
    r.on("PUT", "sys/leases/renew", renew_reply(5, renewable=False))
    r.on("PUT", "sys/leases/revoke", NO_CONTENT, err(500, "x"))
    now = [0.0]

    async def sleep(delay: float) -> None:
        now[0] += delay

    expired = asyncio.Event()
    errors: list[BaseException] = []
    async with aclient(r, retry=sdk.RetryPolicy(max_retries=0)) as c:
        got = await c.database().get_credentials("ro")
        assert (await c.leases.lookup(got.lease_id)).renewable
        h = c.leases.manage(lease(30), clock=lambda: now[0], sleep=sleep, on_expire=expired.set)
        await asyncio.wait_for(expired.wait(), 5)
        assert h.expired and not h.running and h.expires_at is not None
        assert c.leases.active_leases == 0
        await h.stop()
        h2 = c.leases.manage(lease(3600), revoke_on_stop=True)
        await h2.stop()
        await h2.stop()
        h3 = c.leases.manage(lease(3600), revoke_on_stop=True, on_error=errors.append)
        assert c.leases.active_leases == 1
        await c.leases.stop_all()
        assert not h3.running and len(errors) == 1
        with pytest.raises(sdk.ValidationError):
            c.leases.manage(sdk.Lease("", 1, True, {}, []))


# --------------------------------------------------------------------------- pki


def test_pki() -> None:
    r = Router()
    r.on(
        "POST",
        "pki/issue/sdk-test",
        "pki.issue",
        "pki.issue_denied",
        ok({}),
    )
    r.on("POST", "pki/sign/sdk-test", "pki.sign_csr", "pki.issue_denied")
    r.on("POST", "pki/revoke", "pki.revoke_certificate", "pki.revoke_missing")
    r.on("GET", "pki/ca_chain", "pki.read_ca_chain_pem")
    r.on(
        "GET",
        "pki/cert/aa%3Abb",
        "pki.read_certificate",
        "pki.read_revoked",
        "pki.read_certificate_missing",
        ok({"certificate": ""}),
    )
    r.on("GET", "pki/certs/", "pki.list_certificates")
    with client(r) as c:
        pki = c.pki()
        cert = pki.issue_certificate(
            "sdk-test",
            "a.example.test",
            alt_names=["b.example.test"],
            ip_sans=["10.0.0.1"],
            uri_sans=[],
            ttl_s=3600,
            format="pem",
            private_key_format="pkcs8",
            exclude_cn_from_sans=False,
        )
        assert cert.certificate.startswith("-----BEGIN CERTIFICATE")
        assert cert.serial_number and cert.ca_chain and cert.issuing_ca
        assert cert.private_key_type and cert.expiration is not None
        assert r.last().json == {
            "common_name": "a.example.test",
            "alt_names": "b.example.test",
            "ip_sans": "10.0.0.1",
            "ttl": "3600s",
            "format": "pem",
            "private_key_format": "pkcs8",
            "exclude_cn_from_sans": False,
        }
        with pytest.raises(sdk.ValidationError):
            pki.issue_certificate("sdk-test", "evil.example.com")
        with pytest.raises(sdk.UnavailableError, match="no certificate"):
            pki.issue_certificate("sdk-test", "a.example.test")
        signed = pki.sign_csr(
            "sdk-test",
            "-----BEGIN CERTIFICATE REQUEST-----",
            common_name="x",
            alt_names=["y"],
            ttl_s=60,
        )
        assert signed.certificate and not isinstance(signed, sdk.IssuedCertificate)
        with pytest.raises(sdk.ValidationError):
            pki.sign_csr("sdk-test", "bad")
        rev = pki.revoke_certificate("aa:bb")
        assert rev.state == "revoked" and rev.revocation_time is not None
        with pytest.raises(sdk.ValidationError):
            pki.revoke_certificate("ff:ff")
        assert pki.read_ca_chain().startswith("-----BEGIN CERTIFICATE")
        info = pki.read_certificate("aa:bb")
        assert info.certificate and not info.revoked
        assert pki.read_certificate("aa:bb").revoked
        with pytest.raises(sdk.NotFoundError):
            pki.read_certificate("aa:bb")
        with pytest.raises(sdk.UnavailableError):
            pki.read_certificate("aa:bb")
        assert pki.list_certificates()
        assert c.pki("other").list_certificates() == []


def test_pki_tidy_polls_until_finished() -> None:
    running = ok({"state": "Running", "error": ""})
    failed = ok({"state": "Error", "error": "boom", "cert_store_deleted_count": 2})
    r = Router()
    r.on("POST", "pki/tidy", "pki.tidy")
    r.on("GET", "pki/tidy-status", running, running, "pki.tidy_status", running, failed)
    with client(r) as c:
        pki = c.pki()
        status = pki.tidy(safety_buffer_s=1, interval_s=0.001)
        assert status.state == "Finished" and status.error is None
        assert status.time_started is not None
        assert r.last("POST").json == {
            "tidy_cert_store": True,
            "tidy_revoked_certs": True,
            "safety_buffer": "1s",
        }
        assert pki.tidy(wait=False).state == "Running"
        last = pki.tidy(interval_s=0.001)
        assert last.state == "Error" and last.error == "boom" and last.cert_store_deleted_count == 2
    r = Router().on("POST", "pki/tidy", "pki.tidy").on("GET", "pki/tidy-status", running)
    with client(r) as c, pytest.raises(sdk.TimeoutError):
        c.pki().tidy(timeout_s=0.02, interval_s=0.005)


async def test_async_pki_tidy() -> None:
    r = Router().on("POST", "pki/tidy", "pki.tidy")
    r.on("GET", "pki/tidy-status", ok({"state": "Running"}), "pki.tidy_status")
    async with aclient(r) as c:
        assert (await c.pki().tidy(interval_s=0.001)).state == "Finished"
        assert (await c.pki().tidy_status()).state == "Finished"


# --------------------------------------------------------------------------- sys


def test_sys_status_endpoints() -> None:
    r = Router()
    r.on("GET", "sys/health", "health")
    r.on("GET", "sys/seal-status", "seal_status")
    r.on(
        "GET",
        "sys/leader",
        "leader",
        Reply(
            200,
            {
                "ha_enabled": True,
                "is_self": False,
                "active_time": "2026-11-18T20:25:40Z",
                "leader_address": "https://vault-0:8200",
                "leader_cluster_address": "https://vault-0:8201",
                "performance_standby": True,
                "performance_standby_last_remote_wal": 42,
            },
        ),
        Reply(204, None),
    )
    with client(r) as c:
        h = c.sys.health()
        assert h.state == "active" and h.version == "2.2.2" and h.server_time is not None
        s = c.sys.seal_status()
        assert not s.sealed and s.initialized and s.storage_type == "file"
        assert s.build_date.startswith("20") and s.version == "2.2.2"
        lead = c.sys.leader()
        # File storage: no HA (recorded from the real server).
        assert not lead.ha_enabled and not lead.is_self and lead.leader_address == ""
        assert lead.active_time is None and not lead.performance_standby
        assert lead.performance_standby_last_remote_wal == 0
        ent = c.sys.leader()  # Vault Enterprise performance standby fields
        assert ent.ha_enabled and ent.performance_standby
        assert ent.performance_standby_last_remote_wal == 42 and ent.active_time is not None
        assert c.sys.version() == "2.2.2"
        with pytest.raises(sdk.UnavailableError, match="empty response body"):
            c.sys.leader()
    assert "x-vault-token" not in r.last("GET", "sys/seal-status").headers


def test_sys_policies() -> None:
    r = Router()
    r.on("PUT", "sys/policies/acl/p1", "policy.write", "policy.write_invalid")
    r.on("GET", "sys/policies/acl/p1", "policy.read", "policy.read_missing")
    r.on("GET", "sys/policies/acl", "policy.list")
    r.on("DELETE", "sys/policies/acl/p1", "policy.delete")
    with client(r) as c:
        c.sys.write_policy("p1", 'path "x" { capabilities = ["read"] }')
        assert r.last().json == {"policy": 'path "x" { capabilities = ["read"] }'}
        with pytest.raises(sdk.ValidationError):
            c.sys.write_policy("p1", "bad")
        with pytest.raises(sdk.ValidationError):
            c.sys.write_policy("p1", "")
        policy = c.sys.read_policy("p1")
        assert policy.name and policy.policy
        with pytest.raises(sdk.NotFoundError):
            c.sys.read_policy("p1")
        assert "default" in c.sys.list_policies()
        assert r.last().query == {"list": "true"}
        c.sys.delete_policy("p1")


def test_sys_mounts_and_auth_methods() -> None:
    r = Router()
    r.on("GET", "sys/mounts", "mounts.list", "approle.denied_read")
    r.on(
        "POST",
        "sys/mounts/kv-x",
        "mounts.enable",
        "mounts.enable_conflict",
    )
    r.on("DELETE", "sys/mounts/kv-x", "mounts.disable")
    r.on("GET", "sys/auth", "auth.list")
    r.on("POST", "sys/auth/ar", "auth.enable")
    r.on("DELETE", "sys/auth/ar", "auth.disable")
    with client(r) as c:
        mounts = c.sys.list_mounts()
        assert mounts["secret/"].type == "kv" and mounts["secret/"].options["version"] == "2"
        assert all(isinstance(m, sdk.MountInfo) for m in mounts.values())
        with pytest.raises(sdk.PermissionDeniedError):
            c.sys.list_mounts()
        c.sys.enable_secrets_engine(
            "/kv-x/",
            "kv",
            description="d",
            options={"version": "2"},
            default_lease_ttl_s=60,
            max_lease_ttl_s=120,
            local=False,
            seal_wrap=False,
        )
        assert r.last().json == {
            "type": "kv",
            "description": "d",
            "options": {"version": "2"},
            "config": {"default_lease_ttl": "60s", "max_lease_ttl": "120s"},
            "local": False,
            "seal_wrap": False,
        }
        with pytest.raises(sdk.ValidationError):
            c.sys.enable_secrets_engine("kv-x", "kv")
        assert r.last().json == {"type": "kv"}
        c.sys.disable_secrets_engine("kv-x")
        assert c.sys.list_auth_methods()["approle/"].type == "approle"
        c.sys.enable_auth_method("ar", "approle", description="d", max_lease_ttl_s=60, local=True)
        assert r.last().json == {
            "type": "approle",
            "description": "d",
            "config": {"max_lease_ttl": "60s"},
            "local": True,
        }
        c.sys.disable_auth_method("ar")
        with pytest.raises(sdk.ValidationError):
            c.sys.enable_auth_method("/", "approle")


def test_sys_approle_admin() -> None:
    r = Router()
    r.on("POST", "auth/approle/role/r1", "approle.create_role")
    r.on("GET", "auth/approle/role", "approle.list_roles")
    r.on(
        "GET",
        "auth/approle/role/r1/role-id",
        "approle.read_role_id",
        "policy.read_missing",
        ok({}),
    )
    r.on("POST", "auth/approle/role/r1/secret-id", "approle.generate_secret_id", ok({}))
    r.on("DELETE", "auth/approle/role/r1", NO_CONTENT)
    with client(r) as c:
        c.sys.create_app_role(
            "r1",
            token_policies=["p"],
            token_ttl_s=60,
            token_max_ttl_s=120,
            secret_id_ttl_s=0,
            secret_id_num_uses=1,
            bind_secret_id=True,
            token_type="service",
        )
        assert r.last().json == {
            "token_policies": ["p"],
            "token_ttl": "60s",
            "token_max_ttl": "120s",
            "secret_id_ttl": "0s",
            "secret_id_num_uses": 1,
            "bind_secret_id": True,
            "token_type": "service",
        }
        assert c.sys.list_app_roles()
        assert c.sys.list_app_roles(mount="other") == []
        assert c.sys.read_role_id("r1")
        with pytest.raises(sdk.NotFoundError):
            c.sys.read_role_id("r1")
        with pytest.raises(sdk.UnavailableError, match="no role_id"):
            c.sys.read_role_id("r1")
        sid = c.sys.generate_secret_id(
            "r1", metadata={"a": "b"}, cidr_list=["10.0.0.0/8"], ttl_s=60, num_uses=2
        )
        assert r.last().json == {
            "metadata": '{"a": "b"}',
            "cidr_list": ["10.0.0.0/8"],
            "ttl": "60s",
            "num_uses": 2,
        }
        assert sid.secret_id.reveal() and str(sid.secret_id) == "[REDACTED]"
        with pytest.raises(sdk.UnavailableError, match="no secret_id"):
            c.sys.generate_secret_id("r1")
        c.sys.delete_app_role("r1")


async def test_async_sys_and_wrapping() -> None:
    r = Router()
    r.on("GET", "sys/health", "health")
    r.on("POST", "sys/wrapping/wrap", "wrapping.wrap")
    async with aclient(r) as c:
        assert (await c.sys.health()).state == "active"
        assert (await c.wrapping.wrap({"a": "b"}, 60)).token


# --------------------------------------------------------------------------- wrapping


def test_wrapping() -> None:
    r = Router()
    r.on("POST", "sys/wrapping/wrap", "wrapping.wrap", "policy.write_invalid", ok({}))
    r.on("POST", "sys/wrapping/lookup", "wrapping.lookup", "wrapping.unwrap_again")
    r.on(
        "POST",
        "sys/wrapping/unwrap",
        "wrapping.unwrap",
        "wrapping.unwrap_again",
        ok(None, auth={"client_token": "s.wrapped-login"}),
    )
    with client(r) as c:
        info = c.wrapping.wrap({"k": "v"}, 300)
        assert r.last().headers["x-vault-wrap-ttl"] == "300s"
        assert r.last().json == {"k": "v"}
        assert info.ttl_s == 300 and info.creation_path and info.creation_time is not None
        assert str(info.token) == "[REDACTED]"
        with pytest.raises(sdk.ValidationError):
            c.wrapping.wrap({}, 0)
        with pytest.raises(sdk.UnavailableError, match="no wrap_info"):
            c.wrapping.wrap({}, 1)
        look = c.wrapping.lookup_wrapping(info.token)
        assert "x-vault-token" not in r.last().headers
        assert r.last().json == {"token": info.token.reveal()}
        assert look.creation_path and look.creation_ttl_s > 0
        with pytest.raises(sdk.ValidationError):
            c.wrapping.lookup_wrapping("used")
        out = c.wrapping.unwrap("wrap-token-1")
        assert r.last().headers["x-vault-token"] == "wrap-token-1"
        assert out.data is not None and out.auth is None
        with pytest.raises(sdk.ValidationError):
            c.wrapping.unwrap(sdk.Secret("wrap-token-2"))
        login = c.wrapping.unwrap("wrap-token-3")
        assert login.data is None and login.auth is not None
        with pytest.raises(sdk.ValidationError):
            c.wrapping.unwrap("")
    unwraps = [s for s in r.seen if s.path == "/v1/sys/wrapping/unwrap"]
    assert len(unwraps) == 3  # never retried
