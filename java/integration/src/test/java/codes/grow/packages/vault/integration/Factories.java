package codes.grow.packages.vault.integration;

import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.VaultSecretsProvider;
import codes.grow.packages.vault.SecretsOptions;
import codes.grow.packages.vault.core.EnvReader;
import codes.grow.packages.vault.testing.ConformanceRunner;

/**
 * Conformance targets of this service (owned by the service repository).
 *
 * <p>{@code core} is the client; {@code secrets} is the KV v2 {@code SecretsProvider} on mount
 * {@code secret}. Every capability is supported (write, versions, delete, version).
 */
final class Factories {
  /** Capabilities the deployment under test offers (see the scenario {@code requires}). */
  static final String[] CAPABILITIES = {"version", "write", "versions", "delete"};

  private Factories() {}

  static void register(ConformanceRunner.Builder runner, EnvReader env) {
    runner.target("core", scenario -> VaultClient.builder().fromEnv(env).build());
    runner.target(
        "secrets",
        scenario -> {
          VaultClient client = VaultClient.builder().fromEnv(env).build();
          VaultSecretsProvider provider =
              client.secrets(SecretsOptions.builder().mount("secret").build());
          return provider;
        });
  }
}
