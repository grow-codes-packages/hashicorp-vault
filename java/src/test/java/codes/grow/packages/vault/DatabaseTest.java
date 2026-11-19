package codes.grow.packages.vault;

import static codes.grow.packages.vault.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.vault.core.MockServer;
import codes.grow.packages.vault.core.NotFoundException;
import codes.grow.packages.vault.core.Secret;
import codes.grow.packages.vault.core.UnavailableException;
import codes.grow.packages.vault.core.ValidationException;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DatabaseTest {
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
  void credentialsAndAdmin() {
    Database db = client.database();
    assertThat(db.mount()).isEqualTo("database");
    assertThat(db.toString()).isEqualTo("Database(database)");
    enqueue(server, "database.get_credentials");
    Lease<DatabaseCredentials> lease = db.getCredentials("ro");
    assertThat(lease.leaseId()).startsWith("database/creds/");
    assertThat(lease.leaseDuration()).isEqualTo(Duration.ofMinutes(10));
    assertThat(lease.renewable()).isTrue();
    assertThat(lease.warnings()).isEmpty();
    assertThat(lease.data().username()).startsWith("v-root-");
    assertThat(lease.toString()).doesNotContain("<redacted>");
    enqueue(server, "database.get_credentials_missing_role");
    assertThatThrownBy(() -> db.getCredentials("nope")).isInstanceOf(ValidationException.class);
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> db.getCredentials("x")).isInstanceOf(UnavailableException.class);
    server.enqueue(204, "");
    assertThatThrownBy(() -> db.getCredentials("x")).isInstanceOf(UnavailableException.class);
    assertThatThrownBy(() -> db.getCredentials("")).isInstanceOf(ValidationException.class);

    enqueue(server, "database.configure_connection");
    ConnectionConfig cfg =
        ConnectionConfig.builder(
                "postgresql-database-plugin", "postgresql://{{username}}:{{password}}@pg/app")
            .username("postgres")
            .password("pg-pass-123")
            .allowedRoles("ro")
            .verifyConnection(true)
            .extra("max_open_connections", 4)
            .build();
    assertThat(cfg.toString()).doesNotContain("pg-pass-123");
    db.configureConnection("pg", cfg);
    assertThat(server.requests().get(4).uri()).isEqualTo("/v1/database/config/pg");
    assertThat(server.requests().get(4).body())
        .contains("\"plugin_name\":\"postgresql-database-plugin\"")
        .contains("\"password\":\"pg-pass-123\"")
        .contains("\"allowed_roles\":[\"ro\"]")
        .contains("\"max_open_connections\":4");
    enqueue(server, "database.configure_connection_bad");
    assertThatThrownBy(
            () ->
                db.configureConnection(
                    "pg",
                    ConnectionConfig.builder("p", "u")
                        .password(Secret.of("x"))
                        .password((String) null)
                        .build()))
        .isInstanceOf(ValidationException.class);
    enqueue(server, "database.read_connection");
    ConnectionInfo info = db.readConnection("pg");
    assertThat(info.pluginName()).isEqualTo("postgresql-database-plugin");
    assertThat(info.allowedRoles()).isNotEmpty();
    assertThat(info.connectionDetails()).containsKey("connection_url");
    enqueue(server, "database.create_role");
    db.deleteConnection("pg");

    enqueue(server, "database.create_role");
    db.createRole(
        "ro",
        RoleConfig.builder("pg", "CREATE ROLE x;")
            .revocationStatements("DROP ROLE x;")
            .renewStatements("SELECT 1;")
            .rollbackStatements("SELECT 2;")
            .defaultTtl(Duration.ofHours(1))
            .maxTtl(Duration.ofHours(2))
            .build());
    assertThat(server.requests().get(8).body())
        .contains("\"db_name\":\"pg\"")
        .contains("\"default_ttl\":\"3600s\"")
        .contains("\"max_ttl\":\"7200s\"");
    enqueue(server, "database.read_role");
    RoleInfo role = db.readRole("ro");
    assertThat(role.defaultTtl()).isEqualTo(Duration.ofMinutes(5));
    assertThat(role.maxTtl()).isEqualTo(Duration.ofMinutes(10));
    assertThat(role.creationStatements()).hasSize(1);
    assertThat(role.credentialType()).isEqualTo("password");
    enqueue(server, "database.create_role");
    db.deleteRole("ro");
    server.enqueue(404, "{\"errors\":[]}");
    assertThatThrownBy(() -> db.readRole("ro")).isInstanceOf(NotFoundException.class);
    assertThat(client.database("other").mount()).isEqualTo("other");
  }

  @Test
  void leaseOperations() {
    LeaseManager leases = client.leases();
    enqueue(server, "lease.renew");
    LeaseRenewal r = leases.renew("database/creds/ro/abc");
    assertThat(r.renewable()).isTrue();
    assertThat(server.requests().get(0).body())
        .isEqualTo("{\"lease_id\":\"database/creds/ro/abc\"}");
    enqueue(server, "lease.renew_over_max");
    LeaseRenewal capped = leases.renew("database/creds/ro/abc", Duration.ofHours(100));
    assertThat(capped.leaseDuration()).isEqualTo(Duration.ofHours(1));
    assertThat(capped.warnings()).hasSize(1);
    assertThat(server.requests().get(1).body()).contains("\"increment\":\"360000s\"");
    server.enqueue(200, "{\"lease_id\":\"\",\"lease_duration\":5}");
    assertThat(leases.renew("given-id").leaseId()).isEqualTo("given-id");
    server.enqueue(204, "");
    assertThatThrownBy(() -> leases.renew("x")).isInstanceOf(UnavailableException.class);
    enqueue(server, "lease.renew_invalid");
    assertThatThrownBy(() -> leases.renew("x")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> leases.renew("")).isInstanceOf(ValidationException.class);

    enqueue(server, "lease.lookup");
    LeaseInfo info = leases.lookup("database/creds/ro/abc");
    assertThat(info.path()).isEmpty(); // Vault does not report the lease path
    assertThat(info.renewable()).isTrue();
    assertThat(info.ttl()).isPositive();
    assertThat(info.issueTime()).isPresent();
    assertThat(info.expireTime()).isPresent();
    assertThat(info.lastRenewal()).isEmpty();
    server.enqueue(200, "{\"data\":{\"ttl\":1}}");
    assertThat(leases.lookup("id-x").id()).isEqualTo("id-x");
    enqueue(server, "lease.lookup_revoked");
    assertThatThrownBy(() -> leases.lookup("x")).isInstanceOf(ValidationException.class);

    enqueue(server, "lease.revoke");
    leases.revoke("database/creds/ro/abc");
    enqueue(server, "lease.revoke");
    leases.revokePrefix("database/creds/ro");
    assertThat(server.requests().get(9).uri())
        .isEqualTo("/v1/sys/leases/revoke-prefix/database/creds/ro");
    assertThat(server.requests().get(9).method()).isEqualTo("PUT");
    assertThatThrownBy(() -> leases.revoke(" ")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> leases.revokePrefix("")).isInstanceOf(ValidationException.class);
  }
}
