package codes.grow.packages.vault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.vault.HealthResponse;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.SealStatus;
import codes.grow.packages.vault.UnwrapResult;
import codes.grow.packages.vault.WrapInfo;
import codes.grow.packages.vault.WrappingLookup;
import codes.grow.packages.vault.core.HealthStatus;
import codes.grow.packages.vault.core.ValidationException;
import codes.grow.packages.vault.testing.VaultTesting;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class WrappingAndLifecycleTest {
  @Test
  void wrapping() {
    Map<String, String> env = Env.load();
    String secret = "wrapped-" + Env.run();
    try (VaultClient c = Env.root(env)) {
      WrapInfo w = c.wrapping().wrap(Map.of("secret", secret, "n", 1), Duration.ofSeconds(60));
      assertEquals(Duration.ofSeconds(60), w.ttl());
      assertEquals("sys/wrapping/wrap", w.creationPath());
      try (VaultClient anon = Env.anonymous(env)) {
        WrappingLookup l = anon.wrapping().lookupWrapping(w.token());
        assertEquals("sys/wrapping/wrap", l.creationPath());
        assertEquals(Duration.ofSeconds(60), l.creationTtl());
        UnwrapResult r = anon.wrapping().unwrap(w.token());
        assertEquals(secret, r.data().get().get("secret"));
        assertThrows(ValidationException.class, () -> anon.wrapping().unwrap(w.token()));
        assertThrows(ValidationException.class, () -> anon.wrapping().lookupWrapping(w.token()));
      }
    }
  }

  @Test
  void initUnsealSeal() {
    Map<String, String> env = Env.load();
    String url = Env.get(env, "INIT_URL");
    try (VaultClient c = VaultClient.builder().url(url).build()) {
      HealthStatus before = c.health();
      assertFalse(before.healthy());
      assertEquals("uninitialized", before.status());
      assertFalse(VaultTesting.initStatus(c));
      VaultTesting.InitResult init = VaultTesting.init(c, 1, 1);
      assertEquals(1, init.keys().size());
      assertTrue(VaultTesting.initStatus(c));
      assertThrows(ValidationException.class, () -> VaultTesting.init(c, 1, 1));
      SealStatus sealed = c.sys().sealStatus();
      assertTrue(sealed.sealed());
      assertEquals("shamir", sealed.type());
      assertEquals("sealed", c.health().status());
      assertThrows(
          ValidationException.class,
          () ->
              VaultTesting.unseal(
                  c, codes.grow.packages.vault.core.Secret.of("not-a-valid-key!")));
      SealStatus open = VaultTesting.unseal(c, init.keys().get(0));
      assertFalse(open.sealed());
      HealthResponse h = VaultTesting.waitForActive(c, Duration.ofSeconds(30));
      assertEquals("active", h.state());
      c.setToken(init.rootToken());
      assertTrue(c.ping().toNanos() > 0);
      VaultTesting.seal(c);
      assertTrue(c.sys().sealStatus().sealed());
      VaultTesting.resetUnseal(c);
      VaultTesting.unseal(c, init.keysBase64().get(0));
      assertEquals("active", VaultTesting.waitForActive(c, Duration.ofSeconds(30)).state());
    }
  }
}
