# HashiCorp Vault server-mode config for the SDK Docker fixture (test only).
# Persistent file storage + Shamir seal: the bootstrap container initialises and unseals it.
# Vault 2.2.2 still ships the "file" backend (OpenBao removed it in 2.7.0 and needs raft).
storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://hashicorp-vault:8200"
disable_mlock = true
ui            = false
log_level     = "info"
