package integration

import (
	"context"
	"strings"
	"testing"

	vault "github.com/grow-codes-packages/hashicorp-vault/go"
	"github.com/grow-codes-packages/hashicorp-vault/go/testkit"
)

// capabilities the deployment under test offers (see conformance "requires").
// Vault KV v2 supports writes, deletes, versions and exposes its version.
var capabilities = []string{"version", "write", "delete", "versions"}

// categories runs "core" plus this service's categories.
func categories() []string {
	return append([]string{"core"}, strings.Split("secrets", ",")...)
}

// factories builds the conformance targets: the client for "core" and the KV
// v2 SecretsProvider (mount "secret") for "secrets".
func factories(t *testing.T) testkit.Factories {
	t.Helper()
	return testkit.Factories{
		"core": testkit.CoreFactory(func(context.Context) (testkit.CoreTarget, error) {
			return vault.NewClientFromEnv()
		}),
		"secrets": testkit.SecretsFactory(func(context.Context) (vault.SecretsProvider, error) {
			c, err := vault.NewClientFromEnv()
			if err != nil {
				return nil, err
			}
			return &closingProvider{KVSecretsProvider: c.Secrets(), client: c}, nil
		}),
	}
}

// closingProvider closes its client when the scenario ends.
type closingProvider struct {
	*vault.KVSecretsProvider
	client *vault.Client
}

func (p *closingProvider) Close() error { return p.client.Close() }
