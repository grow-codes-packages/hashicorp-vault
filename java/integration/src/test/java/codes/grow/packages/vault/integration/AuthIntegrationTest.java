package codes.grow.packages.vault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.vault.AppRoleAuth;
import codes.grow.packages.vault.AuthInfo;
import codes.grow.packages.vault.CreateTokenOptions;
import codes.grow.packages.vault.JwtAuth;
import codes.grow.packages.vault.KubernetesAuth;
import codes.grow.packages.vault.LoginOptions;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.RenewalEvent;
import codes.grow.packages.vault.RenewalOptions;
import codes.grow.packages.vault.TokenAuth;
import codes.grow.packages.vault.TokenInfo;
import codes.grow.packages.vault.TokenRenewer;
import codes.grow.packages.vault.UserpassAuth;
import codes.grow.packages.vault.core.AuthenticationException;
import codes.grow.packages.vault.core.PermissionDeniedException;
import codes.grow.packages.vault.core.Secret;
import codes.grow.packages.vault.core.UnavailableException;
import codes.grow.packages.vault.core.ValidationException;
import codes.grow.packages.vault.core.VaultException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class AuthIntegrationTest {
  private static void assertLoginRejected(VaultException e) {
    assertTrue(
        e instanceof UnavailableException || e instanceof AuthenticationException,
        "unexpected " + e);
  }

  @Test
  void loginMethods() throws Exception {
    Map<String, String> env = Env.load();
    String allowed = Env.seedAllowed(env);
    try (VaultClient c = Env.anonymous(env)) {
      AuthInfo app =
          c.auth()
              .login(
                  new AppRoleAuth(
                      Env.get(env, "APPROLE_ROLE_ID"), Env.get(env, "APPROLE_SECRET_ID")));
      assertTrue(app.policies().contains("sdk-app"));
      assertEquals("sdk-app", app.metadata().get("role_name"));
      // KV version detection works for a restricted token inside the mount
      assertEquals("world", c.kv().read(allowed).data().get("value"));
      assertEquals("world", c.kv("kv1").read(allowed).data().get("value"));
      assertThrows(PermissionDeniedException.class, () -> c.kv().read("denied/hello"));
      assertThrows(
          AuthenticationException.class,
          () -> c.auth().login(new AppRoleAuth(Env.get(env, "APPROLE_ROLE_ID"), "wrong")));
    }
    try (VaultClient c = Env.anonymous(env)) {
      AuthInfo up =
          c.auth()
              .login(
                  new UserpassAuth(
                      Env.get(env, "USERPASS_USER"), Env.get(env, "USERPASS_PASSWORD")));
      assertEquals(Env.get(env, "USERPASS_USER"), up.metadata().get("username"));
      assertEquals("world", c.kvV2("secret").read(allowed).data().get("value"));
      assertThrows(
          AuthenticationException.class,
          () -> c.auth().login(new UserpassAuth(Env.get(env, "USERPASS_USER"), "nope")));
    }
    try (VaultClient c = Env.anonymous(env)) {
      AuthInfo jwt =
          c.auth()
              .login(
                  new JwtAuth(Env.get(env, "JWT_ROLE"), Env.get(env, "JWT")),
                  LoginOptions.builder().setToken(true).build());
      assertEquals(Env.get(env, "JWT_ROLE"), jwt.metadata().get("role"));
      assertEquals("world", c.kvV2("secret").read(allowed).data().get("value"));
      // a JWT that is not signed by the trusted issuer
      String forged = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
      assertThrows(
          AuthenticationException.class,
          () -> c.auth().login(new JwtAuth(Env.get(env, "JWT_ROLE"), forged)));
    }
    // Kubernetes: the fixture has no Kubernetes API, so Vault cannot review the token and rejects
    // the login (500 -> UNAVAILABLE, or 400/403 -> AUTHENTICATION; request shape only).
    String saJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpzZGsifQ.c2ln";
    Path sa = Files.createTempFile("sa", ".jwt");
    Files.writeString(sa, saJwt, StandardCharsets.UTF_8);
    try (VaultClient c = Env.anonymous(env)) {
      assertLoginRejected(
          assertThrows(
              VaultException.class,
              () -> c.auth().login(new KubernetesAuth("sdk-k8s", sa.toString()))));
      assertLoginRejected(
          assertThrows(
              VaultException.class,
              () ->
                  c.auth()
                      .login(
                          KubernetesAuth.withJwt(
                              "sdk-k8s", Secret.of(saJwt), Env.get(env, "KUBERNETES_MOUNT")))));
    } finally {
      Files.deleteIfExists(sa);
    }
  }

  @Test
  void tokenLifecycle() {
    Map<String, String> env = Env.load();
    try (VaultClient root = Env.root(env)) {
      AuthInfo child =
          root.auth()
              .createToken(
                  CreateTokenOptions.builder()
                      .policies("sdk-app")
                      .ttl(Duration.ofHours(1))
                      .renewable(true)
                      .displayName("sdk-java")
                      .meta("run", Env.run())
                      .build());
      assertTrue(child.renewable());
      try (VaultClient c = Env.anonymous(env)) {
        AuthInfo viaToken = c.auth().login(new TokenAuth(child.clientToken()));
        assertTrue(viaToken.policies().contains("sdk-app"));
        TokenInfo self = c.auth().lookupSelf();
        assertEquals("token-sdk-java", self.displayName());
        assertTrue(self.ttl().compareTo(Duration.ZERO) > 0);
        AuthInfo renewed = c.auth().renewSelf(Duration.ofMinutes(30));
        assertEquals(Duration.ofMinutes(30), renewed.leaseDuration());
        // a token without the root policy cannot create children
        assertThrows(
            PermissionDeniedException.class,
            () -> c.auth().createToken(CreateTokenOptions.builder().policies("root").build()));
        c.auth().revokeSelf();
        assertFalse(c.token().isPresent());
        c.setToken(child.clientToken().reveal());
        assertThrows(AuthenticationException.class, c::ping);
      }
      AuthInfo fixed =
          root.auth()
              .createToken(
                  CreateTokenOptions.builder().policies("sdk-app").renewable(false).build());
      try (VaultClient c = Env.anonymous(env)) {
        c.setToken(fixed.clientToken());
        assertThrows(ValidationException.class, () -> c.auth().renewSelf(Duration.ofMinutes(5)));
      }
    }
  }

  @Test
  void tokenRenewerRenewsInBackground() {
    Map<String, String> env = Env.load();
    try (VaultClient root = Env.root(env)) {
      AuthInfo shortToken =
          root.auth()
              .createToken(
                  CreateTokenOptions.builder()
                      .policies("sdk-app")
                      .ttl(Duration.ofSeconds(3))
                      .explicitMaxTtl(Duration.ofSeconds(30))
                      .renewable(true)
                      .build());
      VaultClient sc = Env.anonymous(env);
      {
        sc.setToken(shortToken.clientToken());
        List<RenewalEvent> renewals = new CopyOnWriteArrayList<>();
        TokenRenewer r =
            sc.auth()
                .startRenewer(
                    RenewalOptions.builder()
                        .increment(Duration.ofSeconds(3))
                        .minDelay(Duration.ofMillis(200))
                        .onRenew(renewals::add)
                        .build());
        assertTrue(r.running());
        Env.eventually(Duration.ofSeconds(15), () -> renewals.size() >= 2);
        assertTrue(r.expiresAt().isPresent());
        assertTrue(sc.ping().toNanos() > 0);
        sc.close();
        assertFalse(r.running());
      }
      // login with automatic renewal
      try (VaultClient c = Env.anonymous(env)) {
        AuthInfo info =
            c.auth()
                .login(
                    new UserpassAuth(
                        Env.get(env, "USERPASS_USER"), Env.get(env, "USERPASS_PASSWORD")),
                    LoginOptions.builder().autoRenew(RenewalOptions.defaults()).build());
        assertTrue(info.renewable());
        assertEquals(1, c.auth().activeRenewers());
      }
    }
  }
}
