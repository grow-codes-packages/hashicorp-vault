#!/bin/sh
# Vault SDK fixture bootstrap (idempotent). Run as the compose `bootstrap` service.
#  1. init (1 share / threshold 1, Shamir) once; keep the material in /bootstrap/.init (0600)
#  2. unseal (every run: a restarted server comes back sealed - Vault has no static seal)
#  3. configure engines/auth/policies (each step skips when already present)
#  4. write /bootstrap/env (KEY=value, 0644) for the test containers
set -eu
. /scripts/lib.sh

: "${VAULT_ADDR:?}"
INIT_FILE=/bootstrap/.init
ENV_FILE=/bootstrap/env
INIT_URL=${VAULT_INIT_URL:-http://hashicorp-vault-init:8200}

code=$(wait_health "$VAULT_ADDR" 200 429 472 473 501 503)
log "server reachable (health $code)"

if [ "$code" = 501 ]; then
  [ -f "$INIT_FILE" ] && die "server is uninitialised but $INIT_FILE exists (data volume lost?)"
  log "initialising (1 key share)"
  out=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
  key=$(printf '%s' "$out" | tr -d '\n ' | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p')
  root=$(printf '%s' "$out" | tr -d '\n ' | json_str root_token)
  [ -n "$key" ] && [ -n "$root" ] || die "could not parse init output"
  umask 077
  printf 'UNSEAL_KEY=%s\nROOT_TOKEN=%s\n' "$key" "$root" > "$INIT_FILE"
  umask 022
fi
[ -f "$INIT_FILE" ] || die "server is initialised but $INIT_FILE is missing"
. "$INIT_FILE"

if [ "$(http_status "$VAULT_ADDR/v1/sys/health")" = 503 ]; then
  log "unsealing"
  vault operator unseal "$UNSEAL_KEY" >/dev/null
fi
wait_health "$VAULT_ADDR" 200 >/dev/null
log "active and unsealed"

export VAULT_TOKEN="$ROOT_TOKEN"
. /scripts/configure.sh

# Separate uninitialised server for testing.init()/unseal(): only check it is still uninitialised.
init_code=$(http_status "$INIT_URL/v1/sys/health")
log "init-test server health $init_code (501 = uninitialised, expected on a fresh stack)"

tmp=$ENV_FILE.tmp
{
  echo "GROW_HASHICORP_VAULT_URL=$VAULT_ADDR"
  echo "VAULT_ADDR=$VAULT_ADDR"
  echo "VAULT_TOKEN=$ROOT_TOKEN"
  echo "GROW_HASHICORP_VAULT_TOKEN=$ROOT_TOKEN"
  echo "VAULT_TEST_ROOT_TOKEN=$ROOT_TOKEN"
  echo "VAULT_TEST_UNSEAL_KEY=$UNSEAL_KEY"
  echo "VAULT_TEST_INIT_URL=$INIT_URL"
  echo "VAULT_TEST_VERSION=2.2.2"
  echo "VAULT_TEST_KV2_MOUNT=secret"
  echo "VAULT_TEST_KV1_MOUNT=kv1"
  echo "VAULT_TEST_TRANSIT_MOUNT=transit"
  echo "VAULT_TEST_TRANSIT_AES_KEY=sdk-aes"
  echo "VAULT_TEST_TRANSIT_SIGN_KEY=sdk-sign"
  echo "VAULT_TEST_DB_MOUNT=database"
  echo "VAULT_TEST_DB_CONNECTION=sdk-postgres"
  echo "VAULT_TEST_DB_ROLE=sdk-readonly"
  echo "VAULT_TEST_PG_HOST=$PG_HOST"
  echo "VAULT_TEST_PG_PORT=$PG_PORT"
  echo "VAULT_TEST_PG_DB=$PG_DB"
  echo "VAULT_TEST_PG_ADMIN_USER=$PG_ADMIN_USER"
  echo "VAULT_TEST_PG_ADMIN_PASSWORD=$PG_ADMIN_PASSWORD"
  echo "VAULT_TEST_PKI_MOUNT=pki"
  echo "VAULT_TEST_PKI_ROLE=sdk-test"
  echo "VAULT_TEST_PKI_DOMAIN=sdk.test"
  echo "VAULT_TEST_CSR_FILE=/bootstrap/test-csr.pem"
  echo "VAULT_TEST_POLICY=sdk-app"
  echo "VAULT_TEST_ALLOWED_KV2_PREFIX=app/"
  echo "VAULT_TEST_DENIED_KV2_PREFIX=denied/"
  echo "VAULT_TEST_APPROLE_MOUNT=approle"
  echo "VAULT_TEST_APPROLE_ROLE=sdk-app"
  echo "VAULT_TEST_APPROLE_ROLE_ID=$APPROLE_ROLE_ID"
  echo "VAULT_TEST_APPROLE_SECRET_ID=$APPROLE_SECRET_ID"
  echo "VAULT_TEST_USERPASS_MOUNT=userpass"
  echo "VAULT_TEST_USERPASS_USER=sdk-user"
  echo "VAULT_TEST_USERPASS_PASSWORD=$USERPASS_PASSWORD"
  echo "VAULT_TEST_JWT_MOUNT=jwt"
  echo "VAULT_TEST_JWT_ROLE=sdk-jwt"
  echo "VAULT_TEST_JWT=$JWT_TOKEN"
  echo "VAULT_TEST_OIDC_TOKEN_ROLE=sdk"
  echo "VAULT_TEST_KUBERNETES_MOUNT=kubernetes"
} > "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$ENV_FILE"
cp /scripts/test-csr.pem /bootstrap/test-csr.pem && chmod 0644 /bootstrap/test-csr.pem
log "wrote $ENV_FILE ($(wc -l < "$ENV_FILE") lines)"
