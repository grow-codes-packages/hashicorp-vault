package codes.grow.packages.vault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.vault.ConnectionConfig;
import codes.grow.packages.vault.ConnectionInfo;
import codes.grow.packages.vault.Database;
import codes.grow.packages.vault.DatabaseCredentials;
import codes.grow.packages.vault.Lease;
import codes.grow.packages.vault.LeaseInfo;
import codes.grow.packages.vault.LeaseRenewal;
import codes.grow.packages.vault.ManagedLease;
import codes.grow.packages.vault.VaultClient;
import codes.grow.packages.vault.RenewalEvent;
import codes.grow.packages.vault.RenewalOptions;
import codes.grow.packages.vault.RoleConfig;
import codes.grow.packages.vault.RoleInfo;
import codes.grow.packages.vault.core.NotFoundException;
import codes.grow.packages.vault.core.ValidationException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DatabaseIntegrationTest {
  private static final String RO_SQL =
      "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
          + " GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";";

  @Test
  void adminAndCredentials() {
    Map<String, String> env = Env.load();
    String run = Env.run();
    String conn = "pg-java-" + run;
    String role = "ro-java-" + run;
    String url =
        "postgresql://{{username}}:{{password}}@"
            + Env.get(env, "PG_HOST")
            + ":"
            + Env.get(env, "PG_PORT")
            + "/"
            + Env.get(env, "PG_DB")
            + "?sslmode=disable";
    try (VaultClient c = Env.root(env)) {
      Database db = c.database(Env.get(env, "DB_MOUNT"));
      db.configureConnection(
          conn,
          ConnectionConfig.builder("postgresql-database-plugin", url)
              .username(Env.get(env, "PG_ADMIN_USER"))
              .password(Env.get(env, "PG_ADMIN_PASSWORD"))
              .allowedRoles(role)
              .verifyConnection(true)
              .build());
      ConnectionInfo info = db.readConnection(conn);
      assertEquals("postgresql-database-plugin", info.pluginName());
      assertEquals(List.of(role), info.allowedRoles());
      assertFalse(info.connectionDetails().containsKey("password"));
      assertThrows(
          ValidationException.class,
          () ->
              db.configureConnection(
                  conn + "-bad",
                  ConnectionConfig.builder("postgresql-database-plugin", url)
                      .username(Env.get(env, "PG_ADMIN_USER"))
                      .password("wrong-password")
                      .build()));

      db.createRole(
          role,
          RoleConfig.builder(conn, RO_SQL)
              .defaultTtl(Duration.ofHours(1))
              .maxTtl(Duration.ofHours(2))
              .build());
      RoleInfo r = db.readRole(role);
      assertEquals(conn, r.dbName());
      assertEquals(Duration.ofHours(1), r.defaultTtl());
      assertEquals(Duration.ofHours(2), r.maxTtl());

      Lease<DatabaseCredentials> lease = db.getCredentials(role);
      assertTrue(lease.leaseId().startsWith(Env.get(env, "DB_MOUNT") + "/creds/" + role));
      assertTrue(lease.renewable());
      assertFalse(lease.data().username().isEmpty());
      assertFalse(lease.data().password().reveal().isEmpty());
      LeaseInfo li = c.leases().lookup(lease.leaseId());
      assertEquals(lease.leaseId(), li.id());
      assertTrue(li.renewable());
      LeaseRenewal capped = c.leases().renew(lease.leaseId(), Duration.ofHours(100));
      assertEquals(Duration.ofHours(2), capped.leaseDuration());
      assertFalse(capped.warnings().isEmpty());
      assertTrue(c.leases().renew(lease.leaseId()).renewable());
      c.leases().revoke(lease.leaseId());
      assertThrows(ValidationException.class, () -> c.leases().lookup(lease.leaseId()));
      assertThrows(ValidationException.class, () -> c.leases().renew(lease.leaseId()));

      Lease<DatabaseCredentials> second = db.getCredentials(role);
      c.leases().revokePrefix(Env.get(env, "DB_MOUNT") + "/creds/" + role);
      assertThrows(ValidationException.class, () -> c.leases().lookup(second.leaseId()));
      assertThrows(ValidationException.class, () -> db.getCredentials("unknown-" + run));

      db.deleteRole(role);
      assertThrows(NotFoundException.class, () -> db.readRole(role));
      db.deleteConnection(conn);
      assertThrows(NotFoundException.class, () -> db.readConnection(conn));
    }
  }

  @Test
  void managedLeaseRenewsThenExpires() {
    Map<String, String> env = Env.load();
    String shortRole = "short-java-" + Env.run();
    try (VaultClient c = Env.root(env)) {
      Database db = c.database(Env.get(env, "DB_MOUNT"));
      db.createRole(
          shortRole,
          RoleConfig.builder(Env.get(env, "DB_CONNECTION"), RO_SQL)
              .defaultTtl(Duration.ofSeconds(10))
              .maxTtl(Duration.ofSeconds(30))
              .build());
      Lease<DatabaseCredentials> lease = db.getCredentials(shortRole);
      assertEquals(Duration.ofSeconds(10), lease.leaseDuration());
      List<RenewalEvent> renewals = new CopyOnWriteArrayList<>();
      AtomicInteger expired = new AtomicInteger();
      ManagedLease m =
          c.leases()
              .manage(
                  lease,
                  RenewalOptions.builder()
                      .increment(Duration.ofSeconds(10))
                      .onRenew(renewals::add)
                      .onExpire(expired::incrementAndGet)
                      .build());
      assertTrue(m.running());
      assertEquals(1, c.leases().activeLeases());
      // max TTL 30 s: renewals until capped, then onExpire exactly once
      Env.eventually(Duration.ofSeconds(45), () -> expired.get() == 1);
      assertFalse(renewals.isEmpty());
      assertTrue(m.expired());
      assertEquals(0, c.leases().activeLeases());
      assertEquals(1, expired.get());

      Lease<DatabaseCredentials> other =
          c.database().getCredentials(Env.get(env, "DB_ROLE"));
      ManagedLease m2 =
          c.leases().manage(other, RenewalOptions.builder().revokeOnStop(true).build());
      c.leases().stopAll();
      assertFalse(m2.running());
      assertThrows(ValidationException.class, () -> c.leases().lookup(other.leaseId()));
      db.deleteRole(shortRole);
    }
  }
}
