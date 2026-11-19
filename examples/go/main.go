// Command example shows the HashiCorp Vault Go SDK against a real server:
// health, an authenticated ping, a capability check, the SecretsProvider over
// KV v2, a KV v2 round trip, transit encryption, response wrapping and a
// namespace view (Vault Enterprise; ignored by Vault OSS).
//
//	GROW_HASHICORP_VAULT_URL=http://127.0.0.1:8200 GROW_HASHICORP_VAULT_TOKEN=... go run .
//
// The token needs write access to secret/ (KV v2) and transit/ (the example
// creates the transit key "example-go" if it is missing).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	vault "github.com/grow-codes-packages/hashicorp-vault/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := vault.ConfigFromEnv()
	if err != nil {
		return err // CONFIG error naming the variable, never its value
	}
	cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg.Hooks = &vault.Hooks{
		OnError: func(info vault.ErrorInfo) {
			if info.WillRetry {
				fmt.Fprintf(os.Stderr, "retrying %s %s (attempt %d)\n", info.Method, info.URL, info.Attempt)
			}
		},
	}
	fmt.Println("config:", cfg) // the token prints as [REDACTED]

	client, err := vault.NewClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("health: healthy=%t status=%s\n", health.Healthy, health.Status)

	latency, err := client.Ping(ctx)
	switch {
	case errors.Is(err, vault.ErrAuthentication):
		return fmt.Errorf("check GROW_HASHICORP_VAULT_TOKEN: %w", err)
	case err != nil:
		return err
	}
	version, err := client.ServerVersion(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("ping: %s, server version %s\n", latency, version)

	// Feature detection: check the policy before acting.
	caps, err := client.Sys().CapabilitiesSelf(ctx, "secret/data/examples/go/db-password", "transit/encrypt/example-go")
	if err != nil {
		return err
	}
	if !caps.Allows("secret/data/examples/go/db-password", vault.CapabilityCreate) {
		return errors.New("the token may not write secret/data/examples/go/*")
	}
	fmt.Println("capabilities:", caps)

	// SecretsProvider over KV v2 (mount "secret", version auto-detected).
	secrets := client.Secrets()
	v, err := secrets.Set(ctx, "examples/go/db-password", "s3cr3t", &vault.SetOptions{Tags: map[string]string{"app": "example"}})
	if err != nil {
		return err
	}
	value, err := secrets.Require(ctx, "examples/go/db-password", nil)
	if err != nil {
		return err
	}
	text, _ := value.Reveal()
	fmt.Printf("secret version %s read back (%d chars), printed as %s\n", v, len(text), value)

	// Native KV v2 with check-and-set.
	kv := client.KVv2("secret")
	md, err := kv.Write(ctx, "examples/go/config", map[string]any{"port": 5432}, nil)
	if err != nil {
		return err
	}
	if _, err := kv.Write(ctx, "examples/go/config", map[string]any{"port": 5433}, &vault.KVWriteOptions{CAS: vault.Ptr(md.Version)}); err != nil {
		return err
	}
	if _, err := kv.Write(ctx, "examples/go/config", map[string]any{"port": 1}, &vault.KVWriteOptions{CAS: vault.Ptr(md.Version)}); errors.Is(err, vault.ErrConflict) {
		fmt.Println("stale check-and-set write rejected as CONFLICT")
	}

	// Transit: encryption as a service.
	transit := client.Transit("transit")
	if _, err := transit.CreateKey(ctx, "example-go", "aes256-gcm96", nil); err != nil {
		return err
	}
	ct, err := transit.Encrypt(ctx, "example-go", []byte("hello"), nil)
	if err != nil {
		return err
	}
	pt, err := transit.Decrypt(ctx, "example-go", ct.Ciphertext, nil)
	if err != nil {
		return err
	}
	fmt.Printf("transit: %s -> %q\n", ct.Ciphertext[:12]+"...", pt)

	// Response wrapping: hand a secret over with a single-use token.
	wrapped, err := client.Wrapping().Wrap(ctx, map[string]any{"api_key": "abc"}, time.Minute)
	if err != nil {
		return err
	}
	unwrapped, err := client.Wrapping().Unwrap(ctx, wrapped.Token.Reveal())
	if err != nil {
		return err
	}
	fmt.Printf("unwrapped %d field(s) with a token printed as %s\n", len(unwrapped.Data), wrapped.Token)

	// Namespace view (Vault Enterprise). Vault OSS ignores the header and
	// serves the root namespace, so this reads the same secret there.
	team, err := client.WithNamespace("team-a")
	if err != nil {
		return err
	}
	if _, found, err := team.Secrets().GetString(ctx, "examples/go/db-password", nil); err == nil {
		fmt.Printf("namespace %q view: secret found=%t\n", team.Namespace(), found)
	}
	_ = team.Close()

	// Clean up.
	if err := secrets.Delete(ctx, "examples/go/db-password", &vault.DeleteOptions{Permanent: true}); err != nil {
		return err
	}
	return kv.DeleteMetadata(ctx, "examples/go/config")
}
