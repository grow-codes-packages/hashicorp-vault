"""Factories the integration suite and the conformance runner use (owned by this repository)."""

from __future__ import annotations

from collections.abc import Mapping

import grow_hashicorp_vault as sdk

URL_VAR = "GROW_HASHICORP_VAULT_URL"

#: Capabilities of the deployment under test for the core scenarios ("version" = serverVersion).
CORE_CAPABILITIES: set[str] = {"version"}


def core_client(env: Mapping[str, str]) -> sdk.VaultClient:
    """A client configured from the test environment (URL, root token from /bootstrap/env)."""
    return sdk.VaultClient.from_env(env)


def async_core_client(env: Mapping[str, str]) -> sdk.AsyncVaultClient:
    return sdk.AsyncVaultClient.from_env(env)


#: Capabilities for the secrets scenarios: write, delete, versions (KV v2 mount `secret`).
SECRETS_CAPABILITIES: set[str] = {"write", "delete", "versions"}


def secrets_provider(client: sdk.VaultClient) -> sdk.SecretsProvider | None:
    """The KV v2 backed secrets provider on top of ``client``."""
    return client.secrets()
