package codes.grow.packages.vault;

import static codes.grow.packages.vault.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.vault.core.MockServer;
import codes.grow.packages.vault.core.Secret;
import codes.grow.packages.vault.core.UnavailableException;
import codes.grow.packages.vault.core.ValidationException;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class WrappingTest {
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

  @Test
  void wrapLookupUnwrap() {
    Wrapping w = client.wrapping();
    enqueue(server, "wrapping.wrap");
    WrapInfo info = w.wrap(Map.of("secret", "s"), Duration.ofSeconds(60));
    assertThat(info.ttl()).isEqualTo(Duration.ofSeconds(300));
    assertThat(info.creationPath()).isEqualTo("sys/wrapping/wrap");
    assertThat(info.creationTime()).isPresent();
    assertThat(info.accessor()).isPresent();
    assertThat(server.requests().get(0).header("X-Vault-Wrap-TTL")).isEqualTo("60s");
    server.enqueue(200, "{\"wrap_info\":null}");
    assertThatThrownBy(() -> w.wrap(Map.of(), Duration.ofSeconds(1)))
        .isInstanceOf(UnavailableException.class);
    enqueue(server, "synthetic.wrap_missing_ttl");
    assertThatThrownBy(() -> client.request("POST", "sys/wrapping/wrap", Map.of("a", 1)))
        .isInstanceOf(ValidationException.class);

    enqueue(server, "wrapping.lookup");
    WrappingLookup l = w.lookupWrapping("wrap-token-1234");
    assertThat(l.creationPath()).isEqualTo("sys/wrapping/wrap");
    assertThat(l.creationTtl()).isEqualTo(Duration.ofSeconds(300));
    assertThat(l.creationTime()).isPresent();
    assertThat(server.requests().get(3).header("X-Vault-Token")).isNull();
    assertThat(server.requests().get(3).body()).isEqualTo("{\"token\":\"wrap-token-1234\"}");
    enqueue(server, "wrapping.unwrap_again");
    assertThatThrownBy(() -> w.lookupWrapping(Secret.of("used-token")))
        .isInstanceOf(ValidationException.class);

    enqueue(server, "wrapping.unwrap");
    UnwrapResult r = w.unwrap("wrap-token-1234");
    assertThat(r.data().get()).containsEntry("foo", "bar").containsEntry("n", 1);
    assertThat(r.auth()).isEmpty();
    assertThat(r.leaseId()).isEmpty();
    assertThat(r.leaseDuration()).isZero();
    assertThat(r.renewable()).isFalse();
    assertThat(r.warnings()).isEmpty();
    assertThat(r.toString()).doesNotContain("bar");
    assertThat(server.requests().get(5).header("X-Vault-Token")).isEqualTo("wrap-token-1234");
    enqueue(server, "wrapping.unwrap_again");
    assertThatThrownBy(() -> w.unwrap("used")).isInstanceOf(ValidationException.class);
    server.enqueue(200, "{\"data\":null,\"auth\":{\"client_token\":\"t-1\",\"lease_duration\":5}}");
    UnwrapResult login = w.unwrap(Secret.of("x"));
    assertThat(login.data()).isEmpty();
    assertThat(login.auth()).isPresent();
    assertThat(login.toString()).contains("data=none");
    server.enqueue(204, "");
    assertThatThrownBy(() -> w.unwrap("x")).isInstanceOf(UnavailableException.class);
    assertThatThrownBy(() -> w.unwrap(" ")).isInstanceOf(ValidationException.class);
  }

  @Test
  void rawRequestWithWrapInfo() {
    enqueue(server, "wrapping.wrap_kv_read");
    RawResponse r = client.request("GET", "secret/data/sdk/allowed/hello", null);
    assertThat(r.status()).isEqualTo(200);
    assertThat(r.data()).isEmpty();
    assertThat(r.wrapInfo()).isPresent();
    assertThat(r.auth()).isEmpty();
    assertThat(r.toString()).contains("data=none");
    enqueue(server, "kv2.list");
    RawResponse list = client.request("list", "secret/metadata/sdk", null);
    assertThat(list.data().get().get("keys")).hasSize(4);
    assertThat(list.toString()).contains("[REDACTED]");
    assertThat(server.requests().get(1).uri()).isEqualTo("/v1/secret/metadata/sdk?list=true");
    server.enqueue(204, "");
    RawResponse empty = client.request("DELETE", "secret/data/x", null);
    assertThat(empty.status()).isEqualTo(204);
    assertThat(empty.data()).isEmpty();
    server.enqueue(
        200, "{\"auth\":{\"client_token\":\"t\"},\"lease_id\":\"l\",\"warnings\":[\"w\"]}");
    RawResponse auth = client.request("POST", "auth/x/login", Map.of());
    assertThat(auth.auth()).isPresent();
    assertThat(auth.leaseId()).isEqualTo("l");
    assertThat(auth.warnings()).containsExactly("w");
    assertThat(auth.leaseDuration()).isZero();
    assertThat(auth.renewable()).isFalse();
  }
}
