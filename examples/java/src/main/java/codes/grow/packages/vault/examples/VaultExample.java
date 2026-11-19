package codes.grow.packages.vault.examples;

import codes.grow.packages.vault.Capabilities;
import codes.grow.packages.vault.Ciphertext;
import codes.grow.packages.vault.DatabaseCredentials;
import codes.grow.packages.vault.IssuedCertificate;
import codes.grow.packages.vault.KvSecret;
import codes.grow.packages.vault.Lease;
import codes.grow.packages.vault.ManagedLease;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.VaultSecretsProvider;
import codes.grow.packages.vault.RenewalOptions;
import codes.grow.packages.vault.SecretsOptions;
import codes.grow.packages.vault.UnwrapResult;
import codes.grow.packages.vault.WrapInfo;
import codes.grow.packages.vault.core.VaultException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * A tour of the HashiCorp Vault modules against a real server (for example the Docker fixture of
 * this repository): capabilities, KV v2, the {@code SecretsProvider}, transit, dynamic database
 * credentials with a managed lease, PKI, response wrapping and a namespace view.
 *
 * <p>Needs {@code GROW_HASHICORP_VAULT_URL} (or {@code VAULT_ADDR}) and a token with access to the
 * {@code secret}, {@code transit}, {@code database} and {@code pki} mounts ({@code
 * GROW_HASHICORP_VAULT_TOKEN} or {@code VAULT_TOKEN}). Optional: {@code EXAMPLE_TRANSIT_KEY} (default {@code sdk-aes}), {@code
 * EXAMPLE_DB_ROLE} (default {@code sdk-readonly}), {@code EXAMPLE_PKI_ROLE} (default {@code
 * sdk-test}) and {@code EXAMPLE_PKI_DOMAIN} (default {@code example.test}).
 */
public final class VaultExample {
  private VaultExample() {}

  private static String env(String name, String fallback) {
    String v = System.getenv(name);
    return v == null || v.isEmpty() ? fallback : v;
  }

  /**
   * Runs the example.
   *
   * @param args unused
   */
  public static void main(String[] args) {
    try (VaultClient client = VaultClient.fromEnv()) {
      System.out.println("server " + client.serverVersion() + ", " + client.health().status());

      // Feature detection: check the policy before acting
      Capabilities caps = client.sys().capabilitiesSelf("secret/data/examples/app/db");
      System.out.println(
          "may write: " + caps.allows("secret/data/examples/app/db", Capabilities.UPDATE));

      // KV v2 (version auto-detected per mount)
      client.kv().write("examples/app/db", Map.of("user", "app", "password", "s3cret"));
      KvSecret secret = client.kv().read("examples/app/db");
      System.out.println("kv version " + secret.metadata().map(m -> m.version()).orElse(0));

      // SecretsProvider: one value per path, typed getters, metadata
      VaultSecretsProvider secrets =
          client.secrets(SecretsOptions.builder().path("examples/provider").build());
      String version = secrets.set("api-key", "k-123");
      System.out.println("api-key v" + version + " -> " + secrets.require("api-key"));

      // Transit: encryption as a service
      String key = env("EXAMPLE_TRANSIT_KEY", "sdk-aes");
      Ciphertext ct = client.transit().encrypt(key, "hello");
      byte[] plain = client.transit().decrypt(key, ct.ciphertext());
      System.out.println("transit round trip: " + new String(plain, StandardCharsets.UTF_8));

      // Dynamic database credentials, renewed in the background until the max TTL
      Lease<DatabaseCredentials> lease =
          client.database().getCredentials(env("EXAMPLE_DB_ROLE", "sdk-readonly"));
      ManagedLease managed =
          client
              .leases()
              .manage(
                  lease,
                  RenewalOptions.builder()
                      .revokeOnStop(true)
                      .onExpire(() -> System.out.println("credentials expired"))
                      .build());
      System.out.println("db user " + lease.data().username() + " (" + lease.leaseDuration() + ")");
      managed.close(); // stops renewing and revokes the credentials

      // PKI
      IssuedCertificate cert =
          client
              .pki()
              .issueCertificate(
                  env("EXAMPLE_PKI_ROLE", "sdk-test"),
                  "app." + env("EXAMPLE_PKI_DOMAIN", "example.test"));
      System.out.println("certificate serial " + cert.serialNumber());

      // Response wrapping: hand a secret over through a single-use token
      WrapInfo wrapped = client.wrapping().wrap(Map.of("password", "s3cret"), Duration.ofMinutes(1));
      UnwrapResult unwrapped = client.wrapping().unwrap(wrapped.token());
      System.out.println("unwrapped keys: " + unwrapped.data().map(Map::keySet).orElseThrow());

      // Namespaces (Vault Enterprise; Vault OSS ignores the header and serves the root namespace)
      VaultClient team = client.withNamespace("team-a");
      System.out.println("namespace view: " + team.namespace().orElse("root"));

      client.kv().deleteMetadata("examples/app/db");
      secrets.delete("api-key");
    } catch (VaultException e) {
      // messages are redacted: they never contain tokens or secret values
      System.out.println(e.code() + ": " + e.getMessage());
    }
  }
}
