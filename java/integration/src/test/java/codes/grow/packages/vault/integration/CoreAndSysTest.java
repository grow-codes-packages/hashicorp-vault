package codes.grow.packages.vault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.vault.AppRoleAuth;
import codes.grow.packages.vault.AppRoleOptions;
import codes.grow.packages.vault.AuthInfo;
import codes.grow.packages.vault.EnableOptions;
import codes.grow.packages.vault.HealthResponse;
import codes.grow.packages.vault.LeaderStatus;
import codes.grow.packages.vault.MountInfo;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.RawResponse;
import codes.grow.packages.vault.SealStatus;
import codes.grow.packages.vault.SecretIdInfo;
import codes.grow.packages.vault.SecretIdOptions;
import codes.grow.packages.vault.Sys;
import codes.grow.packages.vault.core.AuthenticationException;
import codes.grow.packages.vault.core.CancelledException;
import codes.grow.packages.vault.core.HealthStatus;
import codes.grow.packages.vault.core.NotFoundException;
import codes.grow.packages.vault.core.PermissionDeniedException;
import codes.grow.packages.vault.core.ValidationException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CoreAndSysTest {
  @Test
  void clientSurface() {
    Map<String, String> env = Env.load();
    VaultClient c = Env.root(env);
    HealthStatus h = c.health();
    assertTrue(h.healthy());
    assertEquals("active", h.status());
    assertEquals(Env.get(env, "VERSION"), h.details().get("version"));
    assertTrue(c.healthAsync().join().healthy());
    assertTrue(c.ping().toNanos() > 0);
    assertTrue(c.pingAsync().join().toNanos() > 0);
    assertEquals(Env.get(env, "VERSION"), c.serverVersion());
    assertEquals(Env.get(env, "VERSION"), c.serverVersionAsync().join());
    RawResponse raw = c.request("GET", "sys/mounts", null);
    assertEquals(200, raw.status());
    assertTrue(raw.data().get().has("secret/"));
    c.close();
    c.close();
    assertTrue(c.isClosed());
    assertThrows(CancelledException.class, c::ping);
    try (VaultClient anon = Env.anonymous(env)) {
      assertThrows(AuthenticationException.class, anon::ping);
      assertTrue(anon.health().healthy());
    }
    try (VaultClient bad =
        VaultClient.builder().url(env.get("GROW_HASHICORP_VAULT_URL")).token("not-a-real-token").build()) {
      assertThrows(AuthenticationException.class, bad::ping);
      // an ordinary call with a bad token: plain "permission denied" 403 -> AUTHENTICATION
      assertThrows(
          AuthenticationException.class, () -> bad.kvV2("secret").read("app/x/hello"));
    }
  }

  @Test
  void sysStatus() {
    Map<String, String> env = Env.load();
    try (VaultClient c = Env.root(env)) {
      Sys sys = c.sys();
      HealthResponse h = sys.health();
      assertEquals("active", h.state());
      assertTrue(h.initialized());
      SealStatus s = sys.sealStatus();
      assertFalse(s.sealed());
      assertEquals("file", s.storageType());
      assertFalse(s.buildDate().isEmpty());
      assertEquals(Env.get(env, "VERSION"), s.version());
      // file storage: no HA, no performance standby (Vault OSS)
      LeaderStatus l = sys.leader();
      assertFalse(l.haEnabled());
      assertFalse(l.isSelf());
      assertFalse(l.performanceStandby());
      assertEquals(0L, l.performanceStandbyLastRemoteWal());
      assertEquals(Env.get(env, "VERSION"), sys.version());
    }
  }

  @Test
  void policies() {
    Map<String, String> env = Env.load();
    String name = "sdk-java-" + Env.run();
    String hcl = "path \"secret/data/" + name + "/*\" { capabilities = [\"read\"] }";
    try (VaultClient c = Env.root(env)) {
      c.sys().writePolicy(name, hcl);
      assertEquals(hcl, c.sys().readPolicy(name).policy().trim());
      assertTrue(c.sys().listPolicies().contains(name));
      assertThrows(ValidationException.class, () -> c.sys().writePolicy(name, "not { hcl"));
      c.sys().deletePolicy(name);
      assertThrows(NotFoundException.class, () -> c.sys().readPolicy(name));
      assertFalse(c.sys().listPolicies().contains(name));
    }
  }

  @Test
  void mountsAndAppRoleAdmin() {
    Map<String, String> env = Env.load();
    String run = Env.run();
    String kvPath = "java-kv-" + run;
    String authPath = "java-ar-" + run;
    String policy = "java-pol-" + run;
    try (VaultClient c = Env.root(env)) {
      Sys sys = c.sys();
      Map<String, MountInfo> mounts = sys.listMounts();
      assertEquals("kv", mounts.get("secret/").type());
      assertEquals("2", mounts.get("secret/").options().get("version"));
      sys.enableSecretsEngine(
          kvPath, "kv", EnableOptions.builder().option("version", "2").description("java").build());
      assertEquals("java", sys.listMounts().get(kvPath + "/").description());
      assertThrows(ValidationException.class, () -> sys.enableSecretsEngine(kvPath, "kv"));
      sys.disableSecretsEngine(kvPath);
      assertFalse(sys.listMounts().containsKey(kvPath + "/"));

      sys.enableAuthMethod(authPath, "approle");
      assertEquals("approle", sys.listAuthMethods().get(authPath + "/").type());
      String allowed = Env.seedAllowed(env);
      sys.writePolicy(policy, "path \"secret/data/app/*\" { capabilities = [\"read\"] }");
      sys.createAppRole(
          "r1",
          AppRoleOptions.builder()
              .mount(authPath)
              .tokenPolicies(policy)
              .tokenTtl(Duration.ofMinutes(10))
              .secretIdNumUses(1)
              .build());
      assertEquals(List.of("r1"), sys.listAppRoles(authPath));
      String roleId = sys.readRoleId("r1", authPath);
      SecretIdInfo sid =
          sys.generateSecretId(
              "r1", SecretIdOptions.builder().mount(authPath).metadata("purpose", "sdk").build());
      assertEquals(1, sid.secretIdNumUses());
      try (VaultClient app = Env.anonymous(env)) {
        AuthInfo info =
            app.auth().login(new AppRoleAuth(roleId, sid.secretId(), authPath));
        assertTrue(info.policies().contains(policy));
        assertEquals("sdk", info.metadata().get("purpose"));
        assertEquals("world", app.kvV2("secret").read(allowed).data().get("value"));
        assertThrows(
            PermissionDeniedException.class, () -> app.kvV2("secret").read("denied/hello"));
        // single-use secret id
        assertThrows(
            AuthenticationException.class,
            () -> app.auth().login(new AppRoleAuth(roleId, sid.secretId(), authPath)));
      }
      assertThrows(NotFoundException.class, () -> sys.readRoleId("nope", authPath));
      sys.deleteAppRole("r1", authPath);
      assertTrue(sys.listAppRoles(authPath).isEmpty());
      sys.disableAuthMethod(authPath);
      assertFalse(sys.listAuthMethods().containsKey(authPath + "/"));
      sys.deletePolicy(policy);
    }
  }
}
