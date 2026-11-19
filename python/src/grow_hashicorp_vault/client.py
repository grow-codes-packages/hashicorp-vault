"""Vault clients (sync and async), service-owned.

>>> client = VaultClient.from_env()                    # doctest: +SKIP
>>> client.kv().write("app/db", {"password": "s3cret"})  # doctest: +SKIP
>>> client.kv().read("app/db").data                      # doctest: +SKIP
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import threading
import time
from collections.abc import Iterator, Mapping
from types import TracebackType
from typing import Any, Literal

import httpx

from ._api import (
    AsyncRunner,
    Call,
    Op,
    Session,
    SyncRunner,
    cancel_scope,
    decode_envelope,
    encode_path,
    map_vault_error,
    seconds,
    strings,
    text,
    trim_slashes,
    unexpected,
)
from ._core import (
    AsyncHttpTransport,
    CancelledError,
    CancelToken,
    ConfigError,
    HealthStatus,
    HttpTransport,
    ResourceRegistry,
    Secret,
    ServiceError,
    ValidationError,
    error_from_status,
    to_seconds,
)
from .auth import AsyncAuth, Auth
from .config import VaultConfig
from .database import AsyncDatabase, Database
from .kv import AsyncKvMount, AsyncKvV1, AsyncKvV2, KvMount, KvV1, KvV2
from .leases import AsyncLeaseManager, LeaseManager
from .pki import AsyncPki, Pki
from .provider import AsyncVaultSecretsProvider, VaultSecretsProvider
from .system import HEALTH_QUERY, AsyncSys, HealthResponse, Sys, to_health, version_op
from .transit import AsyncTransit, Transit
from .wrapping import AsyncWrapping, WrapInfo, Wrapping, wrap_info

__all__ = ["VaultClient", "AsyncVaultClient", "RawResponse"]

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


@dataclasses.dataclass(frozen=True)
class RawResponse:
    """Result of :meth:`VaultClient.request`: the decoded Vault envelope."""

    #: HTTP status (204 = no content).
    status: int
    data: dict[str, Any] | None = dataclasses.field(repr=False)
    lease_id: str
    lease_duration_s: float
    renewable: bool
    warnings: list[str]
    #: Set when the response was wrapped (``wrap_ttl_s``).
    wrap_info: WrapInfo | None = None


def _health_status(h: HealthResponse) -> HealthStatus:
    details = {
        "version": h.version,
        "initialized": str(h.initialized).lower(),
        "sealed": str(h.sealed).lower(),
        "standby": str(h.standby).lower(),
    }
    if h.cluster_name:
        details["clusterName"] = h.cluster_name
    return HealthStatus(healthy=h.state == "active", status=h.state, details=details)


def _health_error(err: ServiceError) -> HealthStatus:
    if isinstance(err, (CancelledError, ConfigError)):
        raise err
    # Any error is ``unreachable`` (DECISIONS §10: the status is a node state or unreachable).
    word = "unreachable"
    details = {"error": err.message}
    if err.http_status is not None:
        details["httpStatus"] = str(err.http_status)
    return HealthStatus(healthy=False, status=word, details=details)


def _health_op() -> Op[HealthResponse]:
    # Every node state answers 200 thanks to HEALTH_QUERY; a proxy or server that ignores the
    # query still sends the health body with 429/473/501/503, which is parsed the same way.
    resp = yield Call(
        "GET",
        "sys/health",
        "health",
        params=HEALTH_QUERY,
        token=None,
        max_retries=0,
        raise_for_status=False,
    )
    try:
        body = decode_envelope(resp, "health")
    except ServiceError:
        body = {}
    if resp.ok or "initialized" in body:
        if not body:
            raise unexpected("health", "empty response body")
        return to_health(body)
    raise map_vault_error(
        error_from_status(resp.status, "health", content=resp.content, headers=resp.headers)
    )


def _ping_op() -> Op[None]:
    # lookup-self is allowed for every valid token: 400/401/403 mean bad credentials.
    yield Call("GET", "auth/token/lookup-self", "ping", login=True)


def _raw_op(
    method: Method,
    path: str,
    params: Mapping[str, Any] | None,
    json: Any,
    headers: Mapping[str, str] | None,
    list_: bool,
    wrap_ttl_s: float | _dt.timedelta | None,
    idempotent: bool | None,
) -> Op[RawResponse]:
    call = Call(
        method,
        encode_path(path),
        f"{method} {trim_slashes(path)}",
        params=params,
        json=json,
        headers=headers,
        list=list_,
        wrap_ttl=None if wrap_ttl_s is None else to_seconds(wrap_ttl_s),
        idempotent=idempotent,
    )
    resp = yield call
    env = decode_envelope(resp, call.operation)
    found = env.get("data")
    return RawResponse(
        status=resp.status,
        data=found if isinstance(found, dict) else None,
        lease_id=text(env.get("lease_id")),
        lease_duration_s=seconds(env.get("lease_duration")),
        renewable=env.get("renewable") is True,
        warnings=strings(env.get("warnings")),
        wrap_info=wrap_info(env.get("wrap_info")),
    )


def _view_config(config: VaultConfig, namespace: str) -> VaultConfig:
    if not isinstance(namespace, str):
        raise ValidationError("withNamespace: namespace must be a string")
    ns = trim_slashes(namespace.strip())
    if any(ch.isspace() for ch in ns):
        raise ConfigError("withNamespace: namespace must not contain whitespace")
    return dataclasses.replace(config, namespace=ns or None)


class _ClientBase:
    config: VaultConfig
    _session: Session

    def _setup(self, config: VaultConfig | None) -> None:
        if config is None:
            config = VaultConfig.from_env()
        self.config = config.validate()
        self._session = Session(config.token, config.namespace)
        self._resources = ResourceRegistry()
        self._closed = False
        self._is_view = False
        self._parent: _ClientBase | None = None
        self._views: list[_ClientBase] = []

    def _setup_view(self, parent: _ClientBase, namespace: str) -> None:
        if parent._closed:
            raise ValidationError("withNamespace: the client is closed")
        self.config = _view_config(parent.config, namespace)
        # The view starts with the parent's current token; afterwards logins and token changes
        # of the view and of the parent are independent (DECISIONS.md #5).
        self._session = Session(parent._session.token, self.config.namespace)
        self._resources = ResourceRegistry()
        self._closed = False
        self._is_view = True
        self._parent = parent
        self._views = []
        parent._views.append(self)

    def _known_secrets(self) -> list[str]:
        out = self._session.known_secrets(self.config.known_secrets())
        for view in list(self._views):
            out.extend(view._known_secrets())
        return out

    def _detach(self) -> None:
        parent = self._parent
        if parent is not None:
            with contextlib.suppress(ValueError):
                parent._views.remove(self)

    @property
    def namespace(self) -> str | None:
        """The namespace sent as ``X-Vault-Namespace`` (``None`` = root namespace)."""
        return self.config.namespace

    @property
    def token(self) -> Secret | None:
        """The current client token (from the config, a login or :meth:`set_token`)."""
        return self._session.token

    def set_token(self, token: str | Secret | None) -> None:
        """Replace the client token (``None`` removes it)."""
        self._session.token = Secret(token) if token else None
        if token:
            self._session.remember(token)

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` was called."""
        return self._closed

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources (watchers) stopped by :meth:`close`."""
        return self._resources

    def _mount(self, mount: str | None) -> str:
        return trim_slashes(mount if mount is not None else self.config.kv_mount)


class VaultClient(_ClientBase):
    """Synchronous Vault client. Thread-safe; use as a context manager or call
    :meth:`close`.

    Service modules: :attr:`auth`, :attr:`sys`, :attr:`wrapping`, :attr:`leases`,
    :meth:`kv`, :meth:`kv_v1`, :meth:`kv_v2`, :meth:`transit`, :meth:`database`, :meth:`pki`
    and :meth:`secrets` (the ``SecretsProvider``). Cancel calls from another thread with
    ``with client.cancellable(token): ...`` or the ``cancel=`` argument of the core methods.
    """

    def __init__(
        self,
        config: VaultConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._setup(config)
        self._transport = HttpTransport(
            self.config, known_secrets=self._known_secrets, http_transport=http_transport
        )
        self._init_modules()

    def _init_modules(self) -> None:
        self._runner = SyncRunner(self._transport, self._session)
        self._kv_mounts: dict[str, KvMount] = {}
        self._lock = threading.Lock()
        self.auth = Auth(self._runner)
        """Logins, token self-service and token renewal."""
        self.sys = Sys(self._runner)
        """System backend (health, seal status, capabilities, policies, mounts, auth methods,
        AppRole)."""
        self.wrapping = Wrapping(self._runner)
        """Response wrapping."""
        self.leases = LeaseManager(self._runner)
        """Lease renew/revoke/lookup and automatic lease renewal."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> VaultClient:
        """Build a client from ``GROW_HASHICORP_VAULT_*`` and ``VAULT_*`` variables."""
        return cls(VaultConfig.from_env(env, **overrides))

    def with_namespace(self, namespace: str) -> VaultClient:
        """A view of this client whose requests carry ``X-Vault-Namespace: <namespace>``.

        ``""`` selects the root namespace (no header); surrounding slashes are removed. The view
        shares the connection pool and starts with this client's current token; logins, token
        changes, KV version detection, renewers and watchers of the view do not affect this
        client, which stays unchanged. Closing the view stops its own background work; closing
        this client also closes every view.

        **Vault Enterprise only.** Vault OSS silently ignores the header and serves the root
        namespace, so on OSS a view reads and writes the root namespace and a wrong namespace is
        not detected.

        >>> team = client.with_namespace("team-a")  # doctest: +SKIP
        >>> team.kv().read("app/db")                # doctest: +SKIP
        """
        view = VaultClient.__new__(VaultClient)
        with self._lock:
            view._setup_view(self, namespace)
        view._transport = self._transport
        view._init_modules()
        view._runner.sleep = self._runner.sleep
        return view

    @contextlib.contextmanager
    def cancellable(self, token: CancelToken) -> Iterator[CancelToken]:
        """Apply ``token`` to every call made by this thread inside the ``with`` block."""
        with cancel_scope(token) as t:
            yield t

    def kv(self, mount: str | None = None) -> KvMount:
        """KV mount with auto-detected version (default ``config.kv_mount``); cached per mount."""
        key = self._mount(mount)
        with self._lock:
            found = self._kv_mounts.get(key)
            if found is None:
                found = KvMount(self._runner, key, self.config.kv_version)
                self._kv_mounts[key] = found
        return found

    def kv_v1(self, mount: str | None = None) -> KvV1:
        """KV version 1 mount (no detection)."""
        return KvV1(self._runner, self._mount(mount))

    def kv_v2(self, mount: str | None = None) -> KvV2:
        """KV version 2 mount (no detection)."""
        return KvV2(self._runner, self._mount(mount))

    def transit(self, mount: str = "transit") -> Transit:
        """Transit engine (default mount ``transit``)."""
        return Transit(self._runner, mount)

    def database(self, mount: str = "database") -> Database:
        """Database engine (default mount ``database``)."""
        return Database(self._runner, mount)

    def pki(self, mount: str = "pki") -> Pki:
        """PKI engine (default mount ``pki``)."""
        return Pki(self._runner, mount)

    def secrets(
        self, mount: str | None = None, *, path: str | None = None, value_field: str | None = None
    ) -> VaultSecretsProvider:
        """:class:`SecretsProvider` over a KV mount (default ``config.kv_mount``) and base path
        (default ``config.secrets_path``); ``close()`` stops its watchers."""
        return VaultSecretsProvider(
            self.kv(mount),
            path=self.config.secrets_path if path is None else path,
            value_field=self.config.value_field if value_field is None else value_field,
            owner=self._resources,
        )

    def request(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        list: bool = False,  # noqa: A002 - mirrors the LIST operation
        wrap_ttl_s: float | _dt.timedelta | None = None,
        idempotent: bool | None = None,
    ) -> RawResponse:
        """Call any Vault API path (``/v1/<path>``) with the client token, namespace,
        retries and error mapping (for endpoints this SDK has no method for)."""
        return self._runner.run(
            _raw_op(method, path, params, json, headers, list, wrap_ttl_s, idempotent)
        )

    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """Unauthenticated health (``GET /v1/sys/health``); never raises for an unhealthy or
        unreachable server.

        ``healthy`` is true only for an active, unsealed node; ``status`` is ``active``,
        ``standby``, ``perfstandby``, ``sealed`` or ``uninitialized`` (``unreachable`` on any
        error). ``details`` holds ``version``, ``initialized``, ``sealed``, ``standby`` and
        ``clusterName`` (when set); on errors ``error`` (and ``httpStatus``). Raises only
        :class:`CancelledError` and :class:`ConfigError`.
        """
        try:
            with self._maybe_cancel(cancel):
                return _health_status(self._runner.run(_health_op()))
        except ServiceError as err:
            return _health_error(err)

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip (``GET auth/token/lookup-self``); latency in ms.

        A missing, invalid or revoked token raises :class:`AuthenticationError`.
        """
        started = time.monotonic()
        with self._maybe_cancel(cancel):
            self._runner.run(_ping_op())
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """Server version from ``sys/health`` (e.g. ``2.2.2``)."""
        with self._maybe_cancel(cancel):
            return self._runner.run(version_op())

    @contextlib.contextmanager
    def _maybe_cancel(self, cancel: CancelToken | None) -> Iterator[None]:
        if cancel is None:
            yield
            return
        with cancel_scope(cancel):
            yield

    def close(self) -> None:
        """Stop token renewers, managed leases and secret watchers (also of every
        :meth:`with_namespace` view), then release connections (idempotent). Closing a view
        leaves the shared connection pool open."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            views = list(self._views)
        for view in views:
            view.close()  # type: ignore[attr-defined]
        self.auth.stop_renewers()
        self.leases.stop_all()
        self._resources.stop_all()
        if self._is_view:
            self._detach()
        else:
            self._transport.close()

    def __enter__(self) -> VaultClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"VaultClient(config={self.config!r})"


class AsyncVaultClient(_ClientBase):
    """Asynchronous Vault client (same modules and methods, awaitable); use ``async with``
    or call :meth:`aclose`.

    Cancel a call by cancelling its task: the SDK raises :class:`CancelledError`, which is also
    an :class:`asyncio.CancelledError`.
    """

    def __init__(
        self,
        config: VaultConfig | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._setup(config)
        self._transport = AsyncHttpTransport(
            self.config, known_secrets=self._known_secrets, http_transport=http_transport
        )
        self._init_modules()

    def _init_modules(self) -> None:
        self._runner = AsyncRunner(self._transport, self._session)
        self._kv_mounts: dict[str, AsyncKvMount] = {}
        self.auth = AsyncAuth(self._runner)
        """Logins, token self-service and token renewal."""
        self.sys = AsyncSys(self._runner)
        """System backend."""
        self.wrapping = AsyncWrapping(self._runner)
        """Response wrapping."""
        self.leases = AsyncLeaseManager(self._runner)
        """Lease operations and automatic renewal."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> AsyncVaultClient:
        """Build a client from ``GROW_HASHICORP_VAULT_*`` and ``VAULT_*`` variables."""
        return cls(VaultConfig.from_env(env, **overrides))

    def with_namespace(self, namespace: str) -> AsyncVaultClient:
        """See :meth:`VaultClient.with_namespace` (Vault Enterprise only; OSS ignores it)."""
        view = AsyncVaultClient.__new__(AsyncVaultClient)
        view._setup_view(self, namespace)
        view._transport = self._transport
        view._init_modules()
        return view

    def kv(self, mount: str | None = None) -> AsyncKvMount:
        """See :meth:`VaultClient.kv`."""
        key = self._mount(mount)
        found = self._kv_mounts.get(key)
        if found is None:
            found = AsyncKvMount(self._runner, key, self.config.kv_version)
            self._kv_mounts[key] = found
        return found

    def kv_v1(self, mount: str | None = None) -> AsyncKvV1:
        """KV version 1 mount (no detection)."""
        return AsyncKvV1(self._runner, self._mount(mount))

    def kv_v2(self, mount: str | None = None) -> AsyncKvV2:
        """KV version 2 mount (no detection)."""
        return AsyncKvV2(self._runner, self._mount(mount))

    def transit(self, mount: str = "transit") -> AsyncTransit:
        """Transit engine (default mount ``transit``)."""
        return AsyncTransit(self._runner, mount)

    def database(self, mount: str = "database") -> AsyncDatabase:
        """Database engine (default mount ``database``)."""
        return AsyncDatabase(self._runner, mount)

    def pki(self, mount: str = "pki") -> AsyncPki:
        """PKI engine (default mount ``pki``)."""
        return AsyncPki(self._runner, mount)

    def secrets(
        self, mount: str | None = None, *, path: str | None = None, value_field: str | None = None
    ) -> AsyncVaultSecretsProvider:
        """See :meth:`VaultClient.secrets`."""
        return AsyncVaultSecretsProvider(
            self.kv(mount),
            path=self.config.secrets_path if path is None else path,
            value_field=self.config.value_field if value_field is None else value_field,
            owner=self._resources,
        )

    async def request(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        list: bool = False,  # noqa: A002 - mirrors the LIST operation
        wrap_ttl_s: float | _dt.timedelta | None = None,
        idempotent: bool | None = None,
    ) -> RawResponse:
        """See :meth:`VaultClient.request`."""
        return await self._runner.run(
            _raw_op(method, path, params, json, headers, list, wrap_ttl_s, idempotent)
        )

    async def health(self) -> HealthStatus:
        """See :meth:`VaultClient.health`."""
        try:
            return _health_status(await self._runner.run(_health_op()))
        except ServiceError as err:
            return _health_error(err)

    async def ping(self) -> float:
        """See :meth:`VaultClient.ping`."""
        started = time.monotonic()
        await self._runner.run(_ping_op())
        return (time.monotonic() - started) * 1000.0

    async def server_version(self) -> str:
        """See :meth:`VaultClient.server_version`."""
        return await self._runner.run(version_op())

    async def aclose(self) -> None:
        """Stop renewers, managed leases and watchers (also of every :meth:`with_namespace`
        view), then close connections (idempotent; a view leaves the shared pool open)."""
        if self._closed:
            return
        self._closed = True
        for view in list(self._views):
            await view.aclose()  # type: ignore[attr-defined]
        self.auth.stop_renewers()
        await self.leases.stop_all()
        self._resources.stop_all()
        if self._is_view:
            self._detach()
        else:
            await self._transport.aclose()

    close = aclose

    async def __aenter__(self) -> AsyncVaultClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncVaultClient(config={self.config!r})"
