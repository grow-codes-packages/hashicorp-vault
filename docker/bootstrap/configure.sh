# Sourced by bootstrap.sh with VAULT_TOKEN=root. Every step is idempotent.
CREDS_FILE=/bootstrap/.creds
if [ -f "$CREDS_FILE" ]; then . "$CREDS_FILE"; fi

# --- secrets engines -------------------------------------------------------
mount_exists secret || vault secrets enable -path=secret -version=2 kv >/dev/null
mount_exists kv1 || vault secrets enable -path=kv1 -version=1 kv >/dev/null

mount_exists transit || vault secrets enable transit >/dev/null
vault read transit/keys/sdk-aes >/dev/null 2>&1 || vault write -f transit/keys/sdk-aes type=aes256-gcm96 >/dev/null
vault read transit/keys/sdk-sign >/dev/null 2>&1 || vault write -f transit/keys/sdk-sign type=ed25519 >/dev/null

mount_exists database || vault secrets enable database >/dev/null
vault write database/config/sdk-postgres \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=disable" \
  username="$PG_ADMIN_USER" password="$PG_ADMIN_PASSWORD" \
  allowed_roles="*" verify_connection=true >/dev/null
vault write database/roles/sdk-readonly db_name=sdk-postgres \
  creation_statements=@/scripts/pg-creation.sql default_ttl=10m max_ttl=1h >/dev/null

if ! mount_exists pki; then
  vault secrets enable pki >/dev/null
  vault secrets tune -max-lease-ttl=87600h pki >/dev/null
  vault write pki/root/generate/internal common_name="Grow SDK Test Root CA" key_type=ec ttl=87600h >/dev/null 2>&1
  vault write pki/config/urls issuing_certificates="${VAULT_ADDR}/v1/pki/ca" crl_distribution_points="${VAULT_ADDR}/v1/pki/crl" >/dev/null
fi
vault write pki/roles/sdk-test allowed_domains=sdk.test allow_subdomains=true allow_bare_domains=true \
  key_type=ec max_ttl=72h >/dev/null

# --- policies --------------------------------------------------------------
vault policy write sdk-app /scripts/policy-sdk-app.hcl >/dev/null
vault policy write sdk-oidc /scripts/policy-sdk-oidc.hcl >/dev/null

# --- auth methods ----------------------------------------------------------
auth_exists approle || vault auth enable approle >/dev/null
vault write auth/approle/role/sdk-app token_policies=sdk-app token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
APPROLE_ROLE_ID=$(vault read -field=role_id auth/approle/role/sdk-app/role-id)
if [ -z "${APPROLE_SECRET_ID:-}" ]; then
  APPROLE_SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/sdk-app/secret-id)
fi

auth_exists userpass || vault auth enable userpass >/dev/null
[ -n "${USERPASS_PASSWORD:-}" ] || USERPASS_PASSWORD=$(rand_secret)
vault write auth/userpass/users/sdk-user password="$USERPASS_PASSWORD" \
  token_policies="sdk-app,sdk-oidc" token_ttl=1h >/dev/null

# JWT auth trusts Vault's own identity-token issuer (no external IdP, no openssl needed).
vault read identity/oidc/key/sdk-key >/dev/null 2>&1 || \
  vault write identity/oidc/key/sdk-key algorithm=RS256 allowed_client_ids="*" \
    rotation_period=24h verification_ttl=24h >/dev/null
vault write identity/oidc/role/sdk key=sdk-key ttl=24h >/dev/null
OIDC_CLIENT_ID=$(vault read -field=client_id identity/oidc/role/sdk)
auth_exists jwt || vault auth enable jwt >/dev/null
vault write auth/jwt/config jwks_url="${VAULT_ADDR}/v1/identity/oidc/.well-known/keys" >/dev/null
vault write auth/jwt/role/sdk-jwt role_type=jwt bound_audiences="$OIDC_CLIENT_ID" user_claim=sub \
  token_policies=sdk-app token_ttl=1h >/dev/null
user_token=$(vault write -field=token auth/userpass/login/sdk-user password="$USERPASS_PASSWORD")
JWT_TOKEN=$(VAULT_TOKEN="$user_token" vault read -field=token identity/oidc/token/sdk)
VAULT_TOKEN="$user_token" vault token revoke -self >/dev/null

# Kubernetes auth: mounted + configured against an unreachable API so the SDK request shape can be
# exercised; a real login needs a Kubernetes TokenReview API (not part of this fixture).
auth_exists kubernetes || vault auth enable kubernetes >/dev/null
# (OpenBao insists on kubernetes_ca_cert with disable_local_ca_jwt; any PEM CA works - use the test root.)
vault read -field=certificate pki/cert/ca > /tmp/k8s-ca.pem
vault write auth/kubernetes/config kubernetes_host="https://kubernetes.invalid:6443" \
  kubernetes_ca_cert=@/tmp/k8s-ca.pem disable_local_ca_jwt=true >/dev/null
vault write auth/kubernetes/role/sdk-k8s bound_service_account_names=sdk \
  bound_service_account_namespaces=default token_policies=sdk-app >/dev/null

umask 077
printf 'APPROLE_SECRET_ID=%s\nUSERPASS_PASSWORD=%s\n' "$APPROLE_SECRET_ID" "$USERPASS_PASSWORD" > "$CREDS_FILE"
umask 022
log "configured: kv v1/v2, transit, database, pki, policies, approle/userpass/jwt/kubernetes"
