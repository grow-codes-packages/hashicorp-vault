# Python examples

Install the package, point it at a running HashiCorp Vault and run an example:

```bash
pip install grow-hashicorp-vault
export GROW_HASHICORP_VAULT_URL=http://127.0.0.1:8200
export GROW_HASHICORP_VAULT_TOKEN=...   # when the service needs one
python examples/python/basic.py
```

| File | Shows |
| - | - |
| `basic.py` | sync client: health, ping, server version, error handling |
| `vault_tour.py` | KV, `client.secrets()`, `sys.capabilities_self`, `with_namespace`, transit, wrapping, AppRole login, database credentials + `LeaseManager`, PKI |
| `async_basic.py` | async client, cancellation by task |
| `hooks_and_logging.py` | request hooks, the `grow_hashicorp_vault` logger, retries and timeouts |
| `secrets_cache.py` | cached secret reads, typed getters, `load_env`, `watch` (in-memory provider) |
