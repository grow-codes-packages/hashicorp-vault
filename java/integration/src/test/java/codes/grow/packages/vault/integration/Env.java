package codes.grow.packages.vault.integration;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.core.EnvReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import java.util.function.BooleanSupplier;

/** Environment of the Docker suite: {@code /bootstrap/env} plus {@code GROW_HASHICORP_VAULT_URL}. */
final class Env {
  private static final SecureRandom RANDOM = new SecureRandom();

  private Env() {}

  static Map<String, String> load() {
    try {
      Map<String, String> env = ConformanceTest.environment();
      String urlVariable = EnvReader.DEFAULT_PREFIX + "URL";
      assumeTrue(env.containsKey(urlVariable), urlVariable + " is not set; use docker/compose.yml");
      return env;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static String get(Map<String, String> env, String name) {
    String v = env.get("VAULT_TEST_" + name);
    if (v == null) {
      throw new IllegalStateException("missing VAULT_TEST_" + name);
    }
    return v;
  }

  /**
   * Seeds {@code value=world} at {@code app/<run>/hello} on the KV v2 mount {@code secret} and the
   * KV v1 mount {@code kv1} (the scoped {@code sdk-app} policy may read {@code app/*}, not {@code
   * denied/*}) and returns the path.
   */
  static String seedAllowed(Map<String, String> env) {
    String path = "app/java-" + run() + "/hello";
    try (VaultClient root = root(env)) {
      root.kvV2(get(env, "KV2_MOUNT")).write(path, Map.of("value", "world"));
      root.kvV1(get(env, "KV1_MOUNT")).write(path, Map.of("value", "world"));
    }
    return path;
  }

  /** Root client from the bootstrap token. */
  static VaultClient root(Map<String, String> env) {
    return VaultClient.builder().fromEnv(EnvReader.of(env)).build();
  }

  /** A client of the same server without a token. */
  static VaultClient anonymous(Map<String, String> env) {
    return VaultClient.builder().url(env.get(EnvReader.DEFAULT_PREFIX + "URL")).build();
  }

  static String run() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 8; i++) {
      sb.append((char) ('a' + RANDOM.nextInt(26)));
    }
    return sb.toString();
  }

  static void eventually(Duration timeout, BooleanSupplier condition) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("condition not met within " + timeout);
      }
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError(e);
      }
    }
  }
}
