package codes.grow.packages.vault;

import static codes.grow.packages.vault.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.vault.core.AuthenticationException;
import codes.grow.packages.vault.core.ConflictException;
import codes.grow.packages.vault.core.MockServer;
import codes.grow.packages.vault.core.NotFoundException;
import codes.grow.packages.vault.core.PermissionDeniedException;
import codes.grow.packages.vault.core.UnavailableException;
import codes.grow.packages.vault.core.UnsupportedException;
import codes.grow.packages.vault.core.ValidationException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KvTest {
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
  void v2ReadWritePatchAndMetadata() {
    KvV2 kv = client.kvV2("secret/");
    assertThat(kv.mount()).isEqualTo("secret");
    assertThat(kv.version()).isEqualTo(2);
    assertThat(kv.toString()).isEqualTo("KvV2(secret)");
    enqueue(server, "kv2.read");
    KvSecret s = kv.read("sdk/test/alpha");
    assertThat(s.data()).containsEntry("value", "one").containsEntry("keep", "k");
    assertThat(s.metadata().get().version()).isEqualTo(1);
    assertThat(s.metadata().get().createdTime()).isPresent();
    assertThat(s.metadata().get().deleted()).isFalse();
    assertThat(s.toString()).doesNotContain("one").contains("[REDACTED]");
    assertThat(server.requests().get(0).uri()).isEqualTo("/v1/secret/data/sdk/test/alpha");
    assertThat(server.requests().get(0).header("X-Vault-Token")).isEqualTo("root-token-1234");

    enqueue(server, "kv2.read_version");
    kv.read("sdk/test/alpha", 1);
    assertThat(server.requests().get(1).uri()).endsWith("?version=1");

    enqueue(server, "kv2.seed");
    assertThat(kv.write("sdk/test/beta", Map.of("v", "b")).get().version()).isEqualTo(1);
    assertThat(server.requests().get(2).body()).isEqualTo("{\"data\":{\"v\":\"b\"}}");

    enqueue(server, "kv2.write_cas1");
    kv.write("sdk/test/beta", Map.of("v", "c"), 1);
    assertThat(server.requests().get(3).body()).contains("\"options\":{\"cas\":1}");

    enqueue(server, "kv2.write_cas0_conflict");
    assertThatThrownBy(() -> kv.write("sdk/test/beta", Map.of("a", "x"), 0))
        .isInstanceOf(ConflictException.class);

    enqueue(server, "kv2.patch");
    assertThat(kv.patch("sdk/test/alpha", Map.of("c", "3")).version()).isPositive();
    assertThat(server.requests().get(5).method()).isEqualTo("PATCH");
    assertThat(server.requests().get(5).header("Content-Type"))
        .isEqualTo("application/merge-patch+json");

    enqueue(server, "kv2.write_stale_cas");
    assertThatThrownBy(() -> kv.patch("sdk/test/alpha", Map.of("c", "3"), 9))
        .isInstanceOf(ConflictException.class);

    enqueue(server, "kv2.read_metadata_after");
    KvMetadata m = kv.readMetadata("sdk/test/alpha");
    assertThat(m.currentVersion()).isEqualTo(3);
    assertThat(m.maxVersions()).isEqualTo(5);
    assertThat(m.deleteVersionAfter()).isEqualTo(Duration.ofHours(1));
    assertThat(m.customMetadata()).containsEntry("owner", "sdk");
    assertThat(m.versions()).containsKeys(1, 2, 3);
    assertThat(m.createdTime()).isPresent();

    enqueue(server, "kv2.write_metadata");
    kv.writeMetadata(
        "sdk/test/alpha",
        KvMetadataOptions.builder()
            .maxVersions(5)
            .casRequired(false)
            .deleteVersionAfter(Duration.ofHours(720))
            .customMetadata(Map.of("owner", "sdk"))
            .build());
    assertThat(server.requests().get(8).body())
        .contains("\"max_versions\":5")
        .contains("\"delete_version_after\":\"2592000s\"")
        .contains("\"custom_metadata\":{\"owner\":\"sdk\"}");
  }

  @Test
  void v2DeleteVersionsAndList() {
    KvV2 kv = client.kvV2("secret");
    enqueue(server, "kv2.delete_latest");
    kv.delete("a/b");
    enqueue(server, "kv2.delete_versions");
    kv.deleteVersions("a/b", List.of(1));
    enqueue(server, "kv2.undelete");
    kv.undelete("a/b", List.of(3));
    enqueue(server, "kv2.destroy");
    kv.destroy("a/b", List.of(1));
    enqueue(server, "kv2.delete_metadata");
    kv.deleteMetadata("a/b");
    List<MockServer.Recorded> r = server.requests();
    assertThat(r.get(0).method()).isEqualTo("DELETE");
    assertThat(r.get(0).uri()).isEqualTo("/v1/secret/data/a/b");
    assertThat(r.get(1).uri()).isEqualTo("/v1/secret/delete/a/b");
    assertThat(r.get(1).body()).isEqualTo("{\"versions\":[1]}");
    assertThat(r.get(2).uri()).isEqualTo("/v1/secret/undelete/a/b");
    assertThat(r.get(3).method()).isEqualTo("PUT");
    assertThat(r.get(3).uri()).isEqualTo("/v1/secret/destroy/a/b");
    assertThat(r.get(4).uri()).isEqualTo("/v1/secret/metadata/a/b");
    assertThatThrownBy(() -> kv.deleteVersions("a/b", List.of()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> kv.destroy("a/b", List.of(0))).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> kv.undelete("a/b", null)).isInstanceOf(ValidationException.class);

    enqueue(server, "kv2.list");
    assertThat(kv.list("sdk/test")).containsExactly("alpha", "beta", "dir/", "login");
    assertThat(server.requests().get(5).uri()).isEqualTo("/v1/secret/metadata/sdk/test/?list=true");
    enqueue(server, "kv2.list");
    kv.list("sdk/test");
    assertThat(server.requests().get(6).uri()).doesNotContain("after=").doesNotContain("limit=");
    enqueue(server, "kv2.list_missing");
    assertThat(kv.list(null)).isEmpty();
    server.enqueue(403, "{\"errors\":[\"1 error occurred:\\n\\t* permission denied\\n\\n\"]}");
    assertThatThrownBy(() -> kv.list("x")).isInstanceOf(PermissionDeniedException.class);
  }

  @Test
  void v2ReadMissingAndDeleted() {
    KvV2 kv = client.kvV2("secret");
    enqueue(server, "kv2.read_missing");
    assertThatThrownBy(() -> kv.read("nope")).isInstanceOf(NotFoundException.class);
    enqueue(server, "kv2.read_deleted");
    assertThatThrownBy(() -> kv.read("gone")).isInstanceOf(NotFoundException.class);
    server.enqueue(200, "{\"data\":{\"data\":null,\"metadata\":{\"version\":2}}}");
    assertThatThrownBy(() -> kv.read("gone")).isInstanceOf(NotFoundException.class);
    server.enqueue(200, "{\"data\":{\"data\":{\"x\":1}}}");
    assertThat(kv.read("nometa").metadata()).isEmpty();
    server.enqueue(200, "{}");
    assertThatThrownBy(() -> kv.read("bad")).isInstanceOf(UnavailableException.class);
    assertThatThrownBy(() -> kv.read(" ")).isInstanceOf(ValidationException.class);
    enqueue(server, "approle.denied_read");
    assertThatThrownBy(() -> kv.read("sdk/denied/hello"))
        .isInstanceOf(PermissionDeniedException.class);
    enqueue(server, "ping.no_token");
    assertThatThrownBy(() -> kv.read("x")).isInstanceOf(AuthenticationException.class);
    server.enqueue(403, "{\"errors\":[]}");
    assertThatThrownBy(() -> kv.read("x")).isInstanceOf(AuthenticationException.class);
    server.enqueue(403, "{\"errors\":[\"invalid token\"]}");
    assertThatThrownBy(() -> kv.read("x")).isInstanceOf(AuthenticationException.class);
    enqueue(server, "kv2.patch_wrong_content_type");
    assertThatThrownBy(() -> kv.patch("x", Map.of("a", 1))).isInstanceOf(ValidationException.class);
    enqueue(server, "kv2.write_cas_required");
    assertThatThrownBy(() -> kv.write("x", Map.of("a", 1))).isInstanceOf(ValidationException.class);
  }

  @Test
  void v1Operations() {
    KvV1 kv = client.kvV1("kv1");
    assertThat(kv.version()).isEqualTo(1);
    assertThat(kv.mount()).isEqualTo("kv1");
    assertThat(kv.toString()).isEqualTo("KvV1(kv1)");
    enqueue(server, "kv1.read");
    KvSecret s = kv.read("sdk/test/alpha");
    assertThat(s.data()).containsEntry("value", "one").containsEntry("n", "1");
    assertThat(s.metadata()).isEmpty();
    enqueue(server, "kv1.write");
    assertThat(kv.write("sdk/with space", Map.of("a", "1"))).isEmpty();
    assertThat(server.requests().get(1).uri()).isEqualTo("/v1/kv1/sdk/with%20space");
    enqueue(server, "kv1.delete");
    kv.delete("sdk/test/alpha");
    enqueue(server, "kv1.list");
    assertThat(kv.list("sdk/test")).isNotEmpty();
    assertThat(server.requests().get(3).uri()).isEqualTo("/v1/kv1/sdk/test/?list=true");
    enqueue(server, "kv1.list_missing");
    assertThat(kv.list("missing")).isEmpty();
    enqueue(server, "kv1.read_missing");
    assertThatThrownBy(() -> kv.read("missing")).isInstanceOf(NotFoundException.class);

    assertThatThrownBy(() -> kv.read("a", 1)).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.write("a", Map.of(), 1)).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.patch("a", Map.of())).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.deleteVersions("a", List.of(1)))
        .isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.undelete("a", List.of(1))).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.destroy("a", List.of(1))).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.readMetadata("a")).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(
            () -> kv.writeMetadata("a", KvMetadataOptions.builder().maxVersions(1).build()))
        .isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.deleteMetadata("a")).isInstanceOf(UnsupportedException.class);
    assertThat(server.requests()).hasSize(6);
  }

  @Test
  void v1PatchOnServerIs405Unsupported() {
    enqueue(server, "kv1.patch_unsupported");
    assertThatThrownBy(() -> client.request("PATCH", "kv1/x", Map.of("a", "3")))
        .isInstanceOf(UnsupportedException.class);
  }

  @Test
  void mountDetectsVersionOnce() {
    KvMount kv = client.kv();
    assertThat(client.kv("secret/")).isSameAs(kv);
    assertThat(kv.mount()).isEqualTo("secret");
    assertThat(kv.toString()).isEqualTo("KvMount(secret)");
    enqueue(server, "kv.detect_v2");
    enqueue(server, "kv2.read");
    assertThat(kv.read("sdk/allowed/hello").data()).containsKey("value");
    assertThat(server.requests().get(0).uri())
        .isEqualTo("/v1/sys/internal/ui/mounts/secret/sdk/allowed/hello");
    assertThat(kv.version()).isEqualTo(2);
    assertThat(kv.engine()).isInstanceOf(KvV2.class);
    // every call delegates without a second detection
    enqueue(server, "kv2.seed");
    kv.write("a", Map.of("v", "b"));
    enqueue(server, "kv2.write_cas1");
    kv.write("a", Map.of("v", "b"), 1);
    enqueue(server, "kv2.patch");
    kv.patch("a", Map.of("v", "c"));
    enqueue(server, "kv2.patch");
    kv.patch("a", Map.of("v", "c"), 2);
    enqueue(server, "kv2.read_version");
    kv.read("a", 1);
    enqueue(server, "kv2.delete_latest");
    kv.delete("a");
    enqueue(server, "kv2.delete_versions");
    kv.deleteVersions("a", List.of(1));
    enqueue(server, "kv2.undelete");
    kv.undelete("a", List.of(1));
    enqueue(server, "kv2.destroy");
    kv.destroy("a", List.of(1));
    enqueue(server, "kv2.list");
    kv.list("");
    enqueue(server, "kv2.list");
    kv.listAsync("").join();
    enqueue(server, "kv2.read_metadata");
    kv.readMetadata("a");
    enqueue(server, "kv2.write_metadata");
    kv.writeMetadata("a", KvMetadataOptions.builder().casRequired(true).build());
    enqueue(server, "kv2.delete_metadata");
    kv.deleteMetadata("a");
    assertThat(server.requests()).hasSize(16);
    assertThat(
            server.requests().stream().filter(r -> r.uri().contains("internal/ui/mounts")).count())
        .isEqualTo(1);
  }

  @Test
  void mountDetection() {
    enqueue(server, "kv.detect_v1");
    assertThat(client.kv("kv1").version()).isEqualTo(1);
    // no options -> version 1
    server.enqueue(200, "{\"data\":{\"type\":\"kv\",\"options\":null}}");
    assertThat(client.kv("old").version()).isEqualTo(1);
    server.enqueue(200, "{\"data\":{\"type\":\"transit\"}}");
    assertThatThrownBy(() -> client.kv("transit").version())
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("not a KV mount");
    server.enqueue(200, "{\"data\":{\"type\":\"kv\",\"options\":{\"version\":\"3\"}}}");
    assertThatThrownBy(() -> client.kv("weird").version()).isInstanceOf(UnavailableException.class);
    // a failed detection is retried on the next call
    enqueue(server, "kv.detect_restricted_denied");
    KvMount m = client.kv("secret");
    assertThatThrownBy(m::version).isInstanceOf(PermissionDeniedException.class);
    enqueue(server, "kv.detect_v2");
    assertThat(m.version()).isEqualTo(2);
  }

  @Test
  void fixedVersionSkipsDetection() {
    try (VaultClient c = Fixtures.client(server).kvVersion(1).kvMount("kv1").build()) {
      enqueue(server, "kv1.read");
      assertThat(c.kv().read("a").data()).containsKey("value");
      assertThat(c.kv().version()).isEqualTo(1);
      assertThat(server.requests()).hasSize(1);
    }
  }
}
