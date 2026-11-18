// Package vault is the Grow Codes SDK for HashiCorp Vault.
//
// Create a client from the environment (GROW_HASHICORP_VAULT_URL,
// GROW_HASHICORP_VAULT_TOKEN, ...) or from a Config literal:
//
//	client, err := vault.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, vault.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// HashiCorp Vault is a trademark of HashiCorp, Inc. (an IBM company). This package is not affiliated
// with or endorsed by HashiCorp, Inc. (an IBM company).
package vault
