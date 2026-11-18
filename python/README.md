# grow-hashicorp-vault (Python)

Python SDK for [HashiCorp Vault](https://grow-codes-packages.github.io/hashicorp-vault/) by Grow Codes.
Unofficial and community maintained; "HashiCorp Vault" is a trademark of HashiCorp, Inc. (an IBM company).

```bash
pip install grow-hashicorp-vault
```

```python
from grow_hashicorp_vault import VaultClient, VaultConfig

# Reads GROW_HASHICORP_VAULT_URL, GROW_HASHICORP_VAULT_TOKEN, ... from the environment.
with VaultClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_hashicorp_vault import AsyncVaultClient

async def main() -> None:
    async with AsyncVaultClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_hashicorp_vault`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_hashicorp_vault.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/hashicorp-vault/ ·
Source: https://github.com/grow-codes-packages/hashicorp-vault · Licence: Apache-2.0
