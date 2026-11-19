package codes.grow.packages.vault;

import static codes.grow.packages.vault.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.vault.core.AuthenticationException;
import codes.grow.packages.vault.core.ConfigException;
import codes.grow.packages.vault.core.MockServer;
import codes.grow.packages.vault.core.NotFoundException;
import codes.grow.packages.vault.core.PermissionDeniedException;
import codes.grow.packages.vault.core.UnavailableException;
import codes.grow.packages.vault.core.ValidationException;
import codes.grow.packages.vault.core.VaultException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Vault-only surface: capabilities, namespaces, Vault status mapping. */
class VaultSpecificTest {
  private MockServer server;
  private VaultClient client;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = Fixtures.client(server).build();
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  private MockServer.Recorded req(int i) {
    return server.requests().get(i);
  }

  @Test
  void capabilitiesSelfPluralSingleAndRoot() {
    enqueue(server, "capabilities_self.plural");
    Capabilities caps =
        client.sys().capabilitiesSelf("secret/data/app/RUN/x", "/secret/data/denied/RUN/");
    assertThat(req(0).method()).isEqualTo("POST");
    assertThat(req(0).uri()).isEqualTo("/v1/sys/capabilities-self");
    assertThat(req(0).body())
        .isEqualTo("{\"paths\":[\"secret/data/app/RUN/x\",\"secret/data/denied/RUN\"]}");
    assertThat(caps.get("secret/data/app/RUN/x"))
        .containsExactly("create", "delete", "patch", "read", "update");
    assertThat(caps.allows("secret/data/app/RUN/x", Capabilities.UPDATE)).isTrue();
    assertThat(caps.allows("secret/data/app/RUN/x", Capabilities.SUDO)).isFalse();
    assertThat(caps.allows("secret/data/denied/RUN", Capabilities.READ)).isFalse();
    assertThat(caps.allows("not/requested", Capabilities.READ)).isFalse();
    assertThat(caps.get("not/requested")).isEmpty();
    assertThat(caps.asMap()).hasSize(2);
    assertThat(caps.toString()).contains("deny");

    enqueue(server, "capabilities_self.single");
    Capabilities single = client.sys().capabilitiesSelf(List.of("transit/encrypt/sdk-aes"));
    assertThat(single.get("transit/encrypt/sdk-aes")).containsExactly("update");

    enqueue(server, "capabilities_self.root");
    Capabilities root = client.sys().capabilitiesSelfAsync(List.of("sys/mounts")).join();
    assertThat(root.allows("sys/mounts", Capabilities.DELETE)).isTrue();
    assertThat(root.allows("sys/mounts", Capabilities.SUDO)).isTrue();

    // single path answered only with "capabilities" (data or top level)
    server.enqueue(200, "{\"data\":{\"capabilities\":[\"read\"]}}");
    assertThat(client.sys().capabilitiesSelf("a/b").get("a/b")).containsExactly("read");
    server.enqueue(200, "{\"capabilities\":[\"list\"]}");
    assertThat(client.sys().capabilitiesSelf("a/b").get("a/b")).containsExactly("list");
    // legacy top-level copy only
    server.enqueue(200, "{\"a/b\":[\"read\"],\"c\":[\"deny\"]}");
    Capabilities legacy = client.sys().capabilitiesSelf("a/b", "c");
    assertThat(legacy.get("a/b")).containsExactly("read");
    assertThat(legacy.get("c")).containsExactly("deny");
    // several paths never fall back to "capabilities"; an empty body gives empty lists
    server.enqueue(200, "{\"capabilities\":[\"read\"]}");
    assertThat(client.sys().capabilitiesSelf("a", "b").get("a")).isEmpty();
    server.enqueue(204, "");
    assertThat(client.sys().capabilitiesSelf("a").get("a")).isEmpty();
    server.enqueue(200, "{\"data\":null}");
    assertThat(client.sys().capabilitiesSelf("a").get("a")).isEmpty();
    assertThat(server.requests()).hasSize(9);

    assertThatThrownBy(() -> client.sys().capabilitiesSelf())
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.sys().capabilitiesSelf((String[]) null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.sys().capabilitiesSelf(java.util.Arrays.asList("/", null)))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.sys().capabilitiesSelf((List<String>) null))
        .isInstanceOf(ValidationException.class);
    assertThat(server.requests()).hasSize(9);
  }

  @Test
  void capabilitiesOfAnotherToken() {
    enqueue(server, "capabilities.token");
    Capabilities caps =
        client.sys().capabilities("other-token-5678", "secret/data/app/RUN/x", "sys/mounts");
    assertThat(req(0).uri()).isEqualTo("/v1/sys/capabilities");
    assertThat(req(0).body())
        .isEqualTo(
            "{\"token\":\"other-token-5678\",\"paths\":[\"secret/data/app/RUN/x\",\"sys/mounts\"]}");
    assertThat(caps.allows("secret/data/app/RUN/x", Capabilities.CREATE)).isTrue();
    assertThat(caps.allows("sys/mounts", Capabilities.READ)).isFalse();
    enqueue(server, "capabilities.forbidden");
    assertThatThrownBy(() -> client.sys().capabilities("t", List.of("sys/mounts")))
        .isInstanceOf(PermissionDeniedException.class);
    assertThatThrownBy(() -> client.sys().capabilities("", "a"))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.sys().capabilities("t", (String[]) null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.sys().capabilitiesAsync(null, List.of("a")).join())
        .hasCauseInstanceOf(ValidationException.class);
    assertThat(server.requests()).hasSize(2);
  }

  @Test
  void capabilitiesValueType() {
    Capabilities a = Capabilities.of(Map.of("p", List.of("read")));
    Capabilities b = Capabilities.of(Map.of("p", List.of("read")));
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b).isNotEqualTo("p");
    assertThat(a.allows("/p/", Capabilities.READ)).isTrue();
    assertThat(Capabilities.of(Map.of("p", List.of("deny", "read"))).allows("p", "read")).isFalse();
    assertThat(Capabilities.of(Map.of("p", List.of(Capabilities.ROOT))).allows("p", "x")).isTrue();
  }

  @Test
  void withNamespaceSendsHeaderAndKeepsParentUnchanged() {
    assertThat(client.namespace()).isEmpty();
    VaultClient team = client.withNamespace("/team-a/child/");
    assertThat(team.namespace()).contains("team-a/child");
    assertThat(team.config().namespace()).contains("team-a/child");
    assertThat(team.token().get().reveal()).isEqualTo("root-token-1234");

    enqueue(server, "namespace.header_kv");
    assertThat(team.kvV2("secret").read("app/RUN/login").data()).containsEntry("value", "login-ok");
    assertThat(req(0).header("X-Vault-Namespace")).isEqualTo("team-a/child");
    assertThat(req(0).header("X-Vault-Token")).isEqualTo("root-token-1234");

    enqueue(server, "health.namespace_header");
    assertThat(team.health().healthy()).isTrue();
    assertThat(req(1).header("X-Vault-Namespace")).isEqualTo("team-a/child");

    // the parent sends no namespace
    enqueue(server, "kv2.read");
    client.kvV2("secret").read("app/RUN/alpha");
    assertThat(req(2).header("X-Vault-Namespace")).isNull();

    // the view's token is its own
    team.setToken("team-token-9999");
    assertThat(client.token().get().reveal()).isEqualTo("root-token-1234");
    enqueue(server, "token.lookup_self");
    team.auth().lookupSelf();
    assertThat(req(3).header("X-Vault-Token")).isEqualTo("team-token-9999");

    // a login on the view replaces only the view's token
    server.enqueue(
        200,
        "{\"auth\":{\"client_token\":\"login-token-7777\",\"lease_duration\":60,"
            + "\"renewable\":false}}");
    team.auth().login(new UserpassAuth("u", "pw-1234"));
    assertThat(team.token().get().reveal()).isEqualTo("login-token-7777");
    assertThat(client.token().get().reveal()).isEqualTo("root-token-1234");

    // the view's token is redacted in error messages by the shared transport
    server.enqueue(400, "{\"errors\":[\"bad token login-token-7777\"]}");
    assertThatThrownBy(() -> team.sys().listPolicies())
        .isInstanceOf(VaultException.class)
        .message()
        .doesNotContain("login-token-7777");

    // "" is the root namespace: no header
    VaultClient root = team.withNamespace("");
    assertThat(root.namespace()).isEmpty();
    enqueue(server, "health");
    root.health();
    assertThat(req(6).header("X-Vault-Namespace")).isNull();
    assertThat(req(6).header("X-Vault-Token")).isNull();
    assertThat(root.token().get().reveal()).isEqualTo("login-token-7777");
    assertThat(team.toString()).contains("namespace=team-a/child");
  }

  @Test
  void configuredNamespaceIsSent() {
    try (VaultClient c = Fixtures.client(server).namespace("ns1").build()) {
      enqueue(server, "kv2.read");
      c.kvV2("secret").read("x");
      assertThat(req(0).header("X-Vault-Namespace")).isEqualTo("ns1");
      VaultClient other = c.withNamespace("ns2");
      enqueue(server, "kv2.read");
      other.kvV2("secret").read("x");
      assertThat(req(1).header("X-Vault-Namespace")).isEqualTo("ns2");
    }
  }

  @Test
  void withNamespaceValidationAndClose() {
    assertThatThrownBy(() -> client.withNamespace(null)).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.withNamespace("team a")).isInstanceOf(ConfigException.class);

    // closing a view leaves the parent (and the shared connection pool) working
    VaultClient view = client.withNamespace("team-a");
    view.close();
    view.close();
    assertThat(view.isClosed()).isTrue();
    enqueue(server, "health");
    assertThat(client.health().healthy()).isTrue();

    // closing the parent closes every open view
    VaultClient open = client.withNamespace("team-b");
    VaultClient nested = open.withNamespace("team-b/child");
    client.close();
    assertThat(open.isClosed()).isTrue();
    assertThat(nested.isClosed()).isTrue();
    assertThatThrownBy(() -> client.withNamespace("x")).isInstanceOf(ValidationException.class);
  }

  @Test
  void namespaceListIsEnterpriseOnly() {
    enqueue(server, "namespace.list");
    assertThatThrownBy(() -> client.request("LIST", "sys/namespaces", null))
        .isInstanceOf(NotFoundException.class)
        .hasMessageContaining("enterprise-only feature");
  }

  @Test
  void vaultStatusMapping() {
    // 412: Enterprise eventual consistency -> retryable UNAVAILABLE
    server.enqueue(412, "{\"errors\":[\"required index state not present\"]}");
    assertThatThrownBy(() -> client.sys().listPolicies())
        .isInstanceOfSatisfying(
            UnavailableException.class,
            e -> {
              assertThat(e.retryable()).isTrue();
              assertThat(e.httpStatus()).hasValue(412);
            });
    // 403 "invalid token" -> AUTHENTICATION; policy denial -> PERMISSION_DENIED
    enqueue(server, "ping.bad_token");
    assertThatThrownBy(() -> client.sys().listPolicies())
        .isInstanceOf(AuthenticationException.class);
    enqueue(server, "token.after_revoke");
    assertThatThrownBy(() -> client.auth().lookupSelf())
        .isInstanceOf(AuthenticationException.class);
    enqueue(server, "ping.no_token");
    assertThatThrownBy(() -> client.sys().listPolicies())
        .isInstanceOf(AuthenticationException.class);
    enqueue(server, "approle.denied_read");
    assertThatThrownBy(() -> client.kvV2("secret").read("denied/x"))
        .isInstanceOf(PermissionDeniedException.class);
    // Vault answers malformed JSON with 500 (a plain VaultException, UNKNOWN)
    enqueue(server, "error.bad_json");
    assertThatThrownBy(() -> client.request("POST", "sys/policies/acl/x", Map.of()))
        .isInstanceOf(VaultException.class)
        .hasMessageContaining("invalid character");
    // login answered with 400/403 -> AUTHENTICATION
    server.enqueue(403, "{\"errors\":[\"permission denied\"]}");
    assertThatThrownBy(() -> client.auth().login(new AppRoleAuth("r", "s")))
        .isInstanceOf(AuthenticationException.class);
  }
}
