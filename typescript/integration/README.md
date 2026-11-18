# TypeScript integration tests

A consumer project: it installs the packed `@grow-codes/hashicorp-vault` tarball (never the source tree)
and runs the integration and conformance tests with `node --test` against a real HashiCorp Vault.

```sh
cd typescript && make pack            # writes dist/grow-codes-hashicorp-vault-<version>.tgz
cd integration && npm run install-package
GROW_HASHICORP_VAULT_URL=http://127.0.0.1:<port> GROW_HASHICORP_VAULT_TOKEN=... npm test
```

In CI and locally with Docker this runs inside `docker/Dockerfile.typescript`
(`make test-docker LANGS=typescript` from the repository root), which reads `/bootstrap/env`.
