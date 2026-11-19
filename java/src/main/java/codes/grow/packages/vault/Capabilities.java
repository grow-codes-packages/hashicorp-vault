package codes.grow.packages.vault;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The capabilities a token has on each requested path ({@code sys/capabilities-self} or {@code
 * sys/capabilities}), for example {@code ["create", "read", "update"]}, {@code ["deny"]} or {@code
 * ["root"]}. Use {@link #allows(String, String)} to check a policy before acting.
 *
 * <pre>{@code
 * Capabilities caps = client.sys().capabilitiesSelf("secret/data/app/db");
 * if (caps.allows("secret/data/app/db", Capabilities.UPDATE)) { ... }
 * }</pre>
 */
public final class Capabilities {
  /** Capability {@code create}. */
  public static final String CREATE = "create";

  /** Capability {@code read}. */
  public static final String READ = "read";

  /** Capability {@code update}. */
  public static final String UPDATE = "update";

  /** Capability {@code patch}. */
  public static final String PATCH = "patch";

  /** Capability {@code delete}. */
  public static final String DELETE = "delete";

  /** Capability {@code list}. */
  public static final String LIST = "list";

  /** Capability {@code sudo}. */
  public static final String SUDO = "sudo";

  /** Capability {@code deny}: nothing is allowed. */
  public static final String DENY = "deny";

  /** Capability {@code root}: everything is allowed. */
  public static final String ROOT = "root";

  private final Map<String, List<String>> byPath;

  private Capabilities(Map<String, List<String>> byPath) {
    this.byPath = Collections.unmodifiableMap(byPath);
  }

  /**
   * Creates a capability map (tests, fakes).
   *
   * @param byPath capabilities by path
   * @return the map
   */
  public static Capabilities of(Map<String, List<String>> byPath) {
    Map<String, List<String>> copy = new LinkedHashMap<>();
    byPath.forEach((k, v) -> copy.put(k, List.copyOf(v)));
    return new Capabilities(copy);
  }

  /**
   * Reads a {@code sys/capabilities*} answer: {@code data} first, then the legacy top-level copy; a
   * single-path request may only carry {@code capabilities}.
   */
  static Capabilities from(JsonNode env, List<String> paths) {
    JsonNode data = env == null ? null : env.get("data");
    Map<String, List<String>> out = new LinkedHashMap<>();
    for (String p : paths) {
      JsonNode raw = data == null ? null : data.get(p);
      if (raw == null && env != null) {
        raw = env.get(p);
      }
      if (raw == null && paths.size() == 1) {
        raw = data != null && data.has("capabilities") ? data.get("capabilities") : null;
        if (raw == null && env != null) {
          raw = env.get("capabilities");
        }
      }
      out.put(p, Wire.strings(raw));
    }
    return new Capabilities(out);
  }

  /**
   * The capabilities on one path; empty when the path was not requested.
   *
   * @param path requested path
   * @return the capabilities (never null)
   */
  public List<String> get(String path) {
    return byPath.getOrDefault(Wire.trimSlashes(path), List.of());
  }

  /**
   * Whether {@code path} grants {@code capability}: {@code root} grants everything; {@code deny} or
   * a path that was not requested grants nothing.
   *
   * @param path requested path
   * @param capability capability name, e.g. {@link #READ}
   * @return true when allowed
   */
  public boolean allows(String path, String capability) {
    for (String c : get(path)) {
      if (DENY.equals(c)) {
        return false;
      }
      if (ROOT.equals(c) || c.equals(capability)) {
        return true;
      }
    }
    return false;
  }

  /**
   * All requested paths with their capabilities.
   *
   * @return an unmodifiable map
   */
  public Map<String, List<String>> asMap() {
    return byPath;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof Capabilities c && c.byPath.equals(byPath);
  }

  @Override
  public int hashCode() {
    return Objects.hash(byPath);
  }

  @Override
  public String toString() {
    return "Capabilities" + byPath;
  }
}
