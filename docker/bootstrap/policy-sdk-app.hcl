# Scoped identity used by AppRole / Userpass / JWT logins in the SDK tests.
path "secret/data/app/*"      { capabilities = ["create", "read", "update", "patch", "delete"] }
path "secret/metadata/app/*"  { capabilities = ["read", "list", "delete"] }
path "secret/metadata/app"    { capabilities = ["list"] }
path "kv1/app/*"              { capabilities = ["create", "read", "update", "delete", "list"] }
path "transit/encrypt/sdk-aes" { capabilities = ["update"] }
path "transit/decrypt/sdk-aes" { capabilities = ["update"] }
path "database/creds/sdk-readonly" { capabilities = ["read"] }
path "pki/issue/sdk-test"     { capabilities = ["update"] }
# secret/data/denied/* is intentionally not granted (typed PermissionDeniedError tests).
