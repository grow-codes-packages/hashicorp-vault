package codes.grow.packages.vault.testing;

import codes.grow.packages.vault.HealthResponse;
import codes.grow.packages.vault.SealStatus;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.core.HttpTransport;
import codes.grow.packages.vault.core.Poll;
import codes.grow.packages.vault.core.Secret;
import codes.grow.packages.vault.core.TransportRequest;
import codes.grow.packages.vault.core.UnavailableException;
import codes.grow.packages.vault.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Vault server lifecycle helpers for tests and bootstrap scripts: {@code init}, {@code unseal},
 * {@code seal} and waiting for an active node. Not for production code.
 *
 * <pre>{@code
 * try (VaultClient c = VaultClient.builder().url("http://hashicorp-vault-init:8200").build()) {
 *   VaultTesting.InitResult init = VaultTesting.init(c, 1, 1);
 *   VaultTesting.unseal(c, init.keys().get(0));
 *   VaultTesting.waitForActive(c, Duration.ofSeconds(30));
 * }
 * }</pre>
 */
public final class VaultTesting {
  private VaultTesting() {}

  /**
   * Result of {@link #init}. Every key is a redacting {@link Secret}.
   *
   * @param keys unseal keys (hex); empty with an auto-unseal seal
   * @param keysBase64 unseal keys (base64)
   * @param recoveryKeys recovery keys (hex), auto-unseal seals only
   * @param recoveryKeysBase64 recovery keys (base64)
   * @param rootToken initial root token
   */
  public record InitResult(
      List<Secret> keys,
      List<Secret> keysBase64,
      List<Secret> recoveryKeys,
      List<Secret> recoveryKeysBase64,
      Secret rootToken) {
    /**
     * Creates the record; lists are copied.
     *
     * @param keys keys
     * @param keysBase64 keys base64
     * @param recoveryKeys recovery keys
     * @param recoveryKeysBase64 recovery keys base64
     * @param rootToken root token
     */
    public InitResult {
      keys = List.copyOf(keys);
      keysBase64 = List.copyOf(keysBase64);
      recoveryKeys = List.copyOf(recoveryKeys);
      recoveryKeysBase64 = List.copyOf(recoveryKeysBase64);
    }
  }

  private static CompletableFuture<JsonNode> call(
      VaultClient client, String method, String path, String op, Object json, boolean token) {
    TransportRequest.Builder b =
        TransportRequest.builder(method, "/v1/" + path).operation(op).idempotent(false);
    client.config().namespace().ifPresent(ns -> b.header("X-Vault-Namespace", ns));
    if (token) {
      client.token().ifPresent(t -> b.header("X-Vault-Token", t.reveal()));
    }
    if (json != null) {
      b.json(json);
    }
    if (method.equals("GET")) {
      b.idempotent(true);
    }
    return client
        .transport()
        .sendAsync(b.build())
        .thenApply(r -> r.body().length == 0 ? null : r.jsonNode());
  }

  private static JsonNode object(JsonNode body, String op) {
    if (body == null || !body.isObject()) {
      throw new UnavailableException(op + ": unexpected response (empty response body)");
    }
    return body;
  }

  private static List<Secret> secrets(JsonNode arr) {
    List<Secret> out = new ArrayList<>();
    if (arr != null && arr.isArray()) {
      for (JsonNode n : arr) {
        if (n.isTextual() && !n.asText().isEmpty()) {
          out.add(Secret.of(n.asText()));
        }
      }
    }
    return out;
  }

  /**
   * Whether the server is initialised: {@code GET sys/init}.
   *
   * @param client client of the server
   * @return true when initialised
   */
  public static boolean initStatus(VaultClient client) {
    return HttpTransport.await(
        call(client, "GET", "sys/init", "testing.initStatus", null, false)
            .thenApply(b -> object(b, "testing.initStatus").path("initialized").asBoolean(false)),
        "testing.initStatus");
  }

  /**
   * Initialises a new Shamir-sealed server ({@code PUT sys/init}). An initialised server raises
   * {@code ValidationException} ("already initialized"). Never retried.
   *
   * @param client client of the server
   * @param secretShares unseal key shares
   * @param secretThreshold shares needed to unseal
   * @return the keys and root token
   */
  public static InitResult init(VaultClient client, int secretShares, int secretThreshold) {
    return init(client, Map.of("secret_shares", secretShares, "secret_threshold", secretThreshold));
  }

  /**
   * Initialises a server with an auto-unseal (KMS / transit) seal using recovery shares.
   *
   * @param client client of the server
   * @param recoveryShares recovery key shares
   * @param recoveryThreshold recovery threshold
   * @return the recovery keys and root token
   */
  public static InitResult initRecovery(
      VaultClient client, int recoveryShares, int recoveryThreshold) {
    return init(
        client, Map.of("recovery_shares", recoveryShares, "recovery_threshold", recoveryThreshold));
  }

  private static InitResult init(VaultClient client, Map<String, Object> body) {
    return HttpTransport.await(
        call(client, "PUT", "sys/init", "testing.init", body, false)
            .thenApply(
                raw -> {
                  JsonNode b = object(raw, "testing.init");
                  if (!b.path("root_token").isTextual()) {
                    throw new UnavailableException(
                        "testing.init: unexpected response (no root_token)");
                  }
                  return new InitResult(
                      secrets(b.get("keys")),
                      secrets(b.get("keys_base64")),
                      secrets(b.get("recovery_keys")),
                      secrets(b.get("recovery_keys_base64")),
                      Secret.of(b.get("root_token").asText()));
                }),
        "testing.init");
  }

  /**
   * Enters one unseal key (hex or base64): {@code PUT sys/unseal}.
   *
   * @param client client of the server
   * @param key unseal key
   * @return the seal status after the key
   */
  public static SealStatus unseal(VaultClient client, Secret key) {
    if (key == null || key.reveal().trim().isEmpty()) {
      throw new ValidationException("testing.unseal: key must not be empty");
    }
    return unseal(client, Map.of("key", key.reveal()));
  }

  /**
   * Discards the unseal keys entered so far ({@code PUT sys/unseal {"reset": true}}).
   *
   * @param client client of the server
   * @return the seal status
   */
  public static SealStatus resetUnseal(VaultClient client) {
    return unseal(client, Map.of("reset", true));
  }

  private static SealStatus unseal(VaultClient client, Map<String, Object> body) {
    return HttpTransport.await(
        call(client, "PUT", "sys/unseal", "testing.unseal", body, false)
            .thenApply(b -> SealStatus.from(object(b, "testing.unseal"))),
        "testing.unseal");
  }

  /**
   * Seals the server ({@code PUT sys/seal}, needs a root or sudo token on the client).
   *
   * @param client client of the server
   */
  public static void seal(VaultClient client) {
    HttpTransport.await(
        call(client, "PUT", "sys/seal", "testing.seal", null, true), "testing.seal");
  }

  /**
   * Polls {@code sys/health} every 250 ms until the node is active (initialised, unsealed and
   * leader).
   *
   * @param client client of the server
   * @param timeout maximum wait
   * @return the health of the active node
   * @throws codes.grow.packages.vault.core.TimeoutException when it does not become active in time
   */
  public static HealthResponse waitForActive(VaultClient client, Duration timeout) {
    return Poll.until(
        "testing.waitForActive",
        timeout,
        Duration.ofMillis(250),
        () -> {
          HealthResponse h = client.sys().health();
          return h.state().equals("active") ? Optional.of(h) : Optional.empty();
        });
  }
}
