// Package vault is the Grow Codes SDK for HashiCorp Vault.
//
// Create a client from the environment (GROW_HASHICORP_VAULT_URL / VAULT_ADDR,
// GROW_HASHICORP_VAULT_TOKEN / VAULT_TOKEN, ...) or from a Config literal:
//
//	client, err := vault.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every method takes a context.Context first. Service modules hang off the client:
//
//	client.Auth()            logins (TokenAuth, AppRoleAuth, KubernetesAuth, JWTAuth,
//	                         UserpassAuth), LookupSelf, RenewSelf, RevokeSelf,
//	                         CreateToken, StartTokenRenewer
//	client.KV(ctx, mount)    KV engine with auto-detected version (KVv1 / KVv2)
//	client.Secrets()         SecretsProvider over KV (get/set/list/delete/metadata,
//	                         typed getters, LoadEnv, Watch; wrap in NewSecretCache)
//	client.Transit(mount)    encryption as a service
//	client.Database(mount)   dynamic database credentials (Lease)
//	client.LeaseManager()    renew / revoke / auto-renew leases with OnExpire
//	client.PKI(mount)        issue / sign / revoke certificates
//	client.Sys()             seal status, leader, policies, mounts, auth methods,
//	                         AppRole admin, Capabilities / CapabilitiesSelf
//	client.Wrapping()        response wrapping
//	client.WithNamespace(ns) a view of the client in a Vault Enterprise namespace
//
// Init, Unseal and Seal for test fixtures live in the testkit subpackage.
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, vault.ErrNotFound)). Vault answers 403 both for a
// missing/invalid token (ErrAuthentication) and for a policy denial
// (ErrPermissionDenied); failed logins are ErrAuthentication and a
// check-and-set mismatch is ErrConflict. Credentials are wrapped in Secret and
// never appear in errors, hooks or logs.
//
// Namespaces (Config.Namespace, Client.WithNamespace) are a Vault Enterprise
// feature: Vault OSS silently ignores the X-Vault-Namespace header and serves
// the root namespace, so a misconfigured namespace reads the root namespace there.
//
// HashiCorp Vault is a trademark of HashiCorp, Inc. (an IBM company). This package is not affiliated
// with or endorsed by HashiCorp, Inc. (an IBM company).
package vault
