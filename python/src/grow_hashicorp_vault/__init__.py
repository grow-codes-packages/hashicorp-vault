"""Grow Codes SDK for HashiCorp Vault.

>>> from grow_hashicorp_vault import VaultClient, VaultConfig
>>> client = VaultClient.from_env()  # doctest: +SKIP
"""

from . import _core
from ._core import *  # noqa: F403
from ._version import __version__
from .client import AsyncVaultClient, VaultClient
from .config import DEFAULT_URL, VaultConfig

__all__ = [
    "__version__",
    "VaultClient",
    "AsyncVaultClient",
    "VaultConfig",
    "DEFAULT_URL",
]
__all__ += _core.__all__

from . import _secrets  # noqa: E402
from ._secrets import *  # noqa: E402, F403

__all__ += _secrets.__all__
