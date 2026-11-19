package codes.grow.packages.vault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.vault.AppRoleAuth;
import codes.grow.packages.vault.AuthInfo;
import codes.grow.packages.vault.Capabilities;
import codes.grow.packages.vault.CreateTokenOptions;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.core.NotFoundException;
import codes.grow.packages.vault.core.PermissionDeniedException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Vault-only surface: capabilities and namespace views. */
class VaultOnlyIntegrationTest {
  @Test
  void capabilitiesSelfAndOfAnotherToken() {
    Map<String, String> env = Env.load();
    String allowed = "secret/data/app/java-" + Env.run() + "/x";
    String denied = "secret/data/denied/java-" + Env.run();
    try (VaultClient root = Env.root(env)) {
      Capabilities rootCaps = root.sys().capabilitiesSelf("sys/mounts");
      assertEquals(List.of("root"), rootCaps.get("sys/mounts"));
      assertTrue(rootCaps.allows("sys/mounts", Capabilities.SUDO));

      AuthInfo app =
          root.auth()
              .createToken(CreateTokenOptions.builder().policies(Env.get(env, "POLICY")).build());
      try (VaultClient c = Env.anonymous(env)) {
        c.setToken(app.clientToken());
        Capabilities self = c.sys().capabilitiesSelf(List.of(allowed, denied));
        assertTrue(self.allows(allowed, Capabilities.READ));
        assertTrue(self.allows(allowed, Capabilities.PATCH));
        assertFalse(self.allows(allowed, Capabilities.SUDO));
        assertEquals(List.of("deny"), self.get(denied));
        assertFalse(self.allows(denied, Capabilities.READ));
        Capabilities single = c.sys().capabilitiesSelfAsync(List.of("transit/encrypt/sdk-aes")).join();
        assertEquals(List.of("update"), single.get("transit/encrypt/sdk-aes"));
        // a scoped token may not inspect other tokens
        assertThrows(
            PermissionDeniedException.class,
            () -> c.sys().capabilities(app.clientToken().reveal(), "sys/mounts"));
      }
      Capabilities other =
          root.sys().capabilities(app.clientToken().reveal(), allowed, "sys/mounts");
      assertTrue(other.allows(allowed, Capabilities.CREATE));
      assertEquals(List.of("deny"), other.get("sys/mounts"));
      assertTrue(
          root.sys()
              .capabilitiesAsync(app.clientToken().reveal(), List.of(allowed))
              .join()
              .allows(allowed, Capabilities.UPDATE));
    }
  }

  @Test
  void namespaceViewOnVaultOss() {
    Map<String, String> env = Env.load();
    String path = Env.seedAllowed(env);
    VaultClient root = Env.root(env);
    {
      VaultClient team = root.withNamespace("team-java");
      assertEquals("team-java", team.namespace().get());
      // Vault OSS ignores X-Vault-Namespace and serves the root namespace
      assertEquals("world", team.kvV2("secret").read(path).data().get("value"));
      assertTrue(team.health().healthy());
      // the namespace list is an Enterprise feature
      assertThrows(NotFoundException.class, () -> root.request("LIST", "sys/namespaces", null));

      // the view logs in on its own; the parent keeps the root token
      VaultClient app = root.withNamespace("");
      app.auth()
          .login(
              new AppRoleAuth(Env.get(env, "APPROLE_ROLE_ID"), Env.get(env, "APPROLE_SECRET_ID")));
      assertThrows(PermissionDeniedException.class, () -> app.sys().listMounts());
      assertFalse(root.sys().listMounts().isEmpty());
      app.close();
      assertTrue(app.isClosed());
      assertTrue(root.ping().toNanos() > 0);
      root.close();
      assertTrue(team.isClosed());
    }
  }
}
