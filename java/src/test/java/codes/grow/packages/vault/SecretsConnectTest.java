// Service-owned: generated once by sdk-kit, then maintained in this repository.
package codes.grow.packages.vault;

import static org.assertj.core.api.Assertions.assertThat;

import codes.grow.packages.vault.core.ConfigException;
import codes.grow.packages.vault.core.UnsupportedException;
import codes.grow.packages.vault.secrets.ConfigLoader.SecretsBootstrap;
import codes.grow.packages.vault.secrets.ConfigLoader.SecretsConnection;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SecretsConnectTest {
  @Test
  void connectsWithoutIoOrReportsUnsupported() {
    try {
      SecretsConnection c =
          SecretsConnect.connect(
              new SecretsBootstrap(null, "http://127.0.0.1:1", null, "", "", null, null), Map.of());
      assertThat(c.provider()).isNotNull();
      if (c.close() != null) {
        c.close().run();
      }
    } catch (UnsupportedException | ConfigException e) {
      assertThat(e.getMessage()).isNotEmpty();
    }
  }
}
