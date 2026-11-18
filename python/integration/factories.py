"""Factories the integration suite and the conformance runner use (owned by this repository).

sdk-kit generates this file once. Replace the bodies when the service needs more setup (extra
credentials from /bootstrap/env, namespaces, a provider built on the client …) and keep the
capability sets honest: every capability left out skips scenarios, and each skip must be
explained in docs/compatibility.md.
"""

from __future__ import annotations

from collections.abc import Mapping

import grow_hashicorp_vault as sdk

URL_VAR = "GROW_HASHICORP_VAULT_URL"

#: Capabilities of the deployment under test for the core scenarios ("version" = serverVersion).
CORE_CAPABILITIES: set[str] = {"version"}


def core_client(env: Mapping[str, str]) -> sdk.VaultClient:
    """A client configured from the test environment (URL, token, … from /bootstrap/env)."""
    return sdk.VaultClient.from_env(env)


def async_core_client(env: Mapping[str, str]) -> sdk.AsyncVaultClient:
    return sdk.AsyncVaultClient.from_env(env)


#: Capabilities for the secrets scenarios: write, delete, versions.
SECRETS_CAPABILITIES: set[str] = {"write", "delete", "versions"}


def secrets_provider(client: sdk.VaultClient) -> sdk.SecretsProvider | None:
    """The service's secrets provider on top of ``client``; ``None`` skips the secrets suite.

    Replace with the real provider, e.g. ``return client.kv``.
    """
    return None
