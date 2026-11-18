import { inspect } from "node:util";
import { describe, expect, it, vi } from "vitest";
import { REDACTED, Secret } from "../src/index.js";
import { ManualScheduler } from "./support/clock.js";
import { NO_CONTENT, data, errors, fromFixtures, fx, rejection, vault } from "./support/vault.js";

const LEASE = "database/creds/sdk-readonly/rx654LRRjpVhmh8MAR9xsuLJ";

describe("Database", () => {
  it("getCredentials returns a lease with a redacted password", async () => {
    const m = await vault({
      "GET /v1/database/creds/sdk-readonly": fx("database.get_credentials", (b) => ({
        ...b,
        data: { ...b.data, password: "db-pass-123" },
      })),
      "GET /v1/database/creds/nope-RUN": "database.get_credentials_missing_role",
      "GET /v1/database/creds/broken": data(null),
      "GET /v1/database/creds/nopw": data({ username: "u" }),
    });
    const db = m.client().database();
    expect(db.mount).toBe("database");
    const lease = await db.getCredentials("sdk-readonly");
    expect(lease).toMatchObject({
      leaseId: LEASE,
      leaseDurationMs: 600_000,
      renewable: true,
      warnings: [],
    });
    expect(lease.data.username).toMatch(/^v-root-sdk-readonly-/);
    expect(lease.data.password.reveal()).toBe("db-pass-123");
    expect(inspect(lease)).not.toContain("db-pass-123");
    expect(JSON.stringify(lease)).toContain(REDACTED);
    const unknown = await rejection(db.getCredentials("nope-RUN"));
    expect(unknown.code).toBe("VALIDATION");
    expect(unknown.message).toContain("unknown role");
    expect((await rejection(db.getCredentials("broken"))).message).toContain("no credentials");
    expect((await db.getCredentials("nopw")).data.password.reveal()).toBe("");
  });

  it("configureConnection / readConnection / deleteConnection", async () => {
    const m = await vault({
      ...fromFixtures("database.configure_connection", "database.read_connection"),
      "DELETE /v1/database/config/rt-RUN": NO_CONTENT,
      "POST /v1/database/config/rt-bad-RUN": "database.configure_connection_bad",
      "GET /v1/database/config/odd": data({}),
    });
    const db = m.client().database();
    const url = "postgresql://{{username}}:{{password}}@postgres:5432/app?sslmode=disable";
    await db.configureConnection("rt-RUN", {
      pluginName: "postgresql-database-plugin",
      connectionUrl: url,
      username: "vault_admin",
      password: new Secret("pg-admin-pw"),
      allowedRoles: ["rt-role-RUN"],
      verifyConnection: true,
      extra: { max_open_connections: 2 },
    });
    expect(m.body()).toEqual({
      plugin_name: "postgresql-database-plugin",
      connection_url: url,
      username: "vault_admin",
      password: "pg-admin-pw",
      allowed_roles: ["rt-role-RUN"],
      verify_connection: true,
      max_open_connections: 2,
    });
    const bad = await rejection(
      db.configureConnection("rt-bad-RUN", {
        pluginName: "postgresql-database-plugin",
        connectionUrl: "postgresql://x",
        password: "wrong-pg-password",
      }),
    );
    expect(bad.code).toBe("VALIDATION");
    expect(bad.message).not.toContain("wrong-pg-password");
    const info = await db.readConnection("sdk-postgres");
    expect(info.pluginName).toBe("postgresql-database-plugin");
    expect(info.allowedRoles).toEqual(["*"]);
    expect(info.connectionDetails.username).toBe("vault_admin");
    expect(info.connectionDetails.connection_url).toBe(url);
    expect(info.connectionDetails).not.toHaveProperty("password");
    expect(await db.readConnection("odd")).toEqual({
      pluginName: "",
      allowedRoles: [],
      connectionDetails: {},
    });
    await db.deleteConnection("rt-RUN");
    expect(m.keys().at(-1)).toBe("DELETE /v1/database/config/rt-RUN");
  });

  it("createRole / readRole / deleteRole", async () => {
    const m = await vault({
      ...fromFixtures("database.create_role", "database.read_role"),
      "DELETE /v1/database/roles/rt-role-RUN": NO_CONTENT,
      "GET /v1/db2/roles/odd": data({}),
    });
    const c = m.client();
    const db = c.database();
    await db.createRole("rt-role-RUN", {
      dbName: "rt-RUN",
      creationStatements: ["CREATE ROLE x"],
      revocationStatements: ["DROP ROLE x"],
      renewStatements: [],
      rollbackStatements: [],
      defaultTtlMs: 3_600_000,
      maxTtlMs: 7_200_000,
    });
    expect(m.body()).toEqual({
      db_name: "rt-RUN",
      creation_statements: ["CREATE ROLE x"],
      revocation_statements: ["DROP ROLE x"],
      renew_statements: [],
      rollback_statements: [],
      default_ttl: "3600s",
      max_ttl: "7200s",
    });
    const role = await db.readRole("rt-role-RUN");
    expect(role).toMatchObject({
      dbName: "rt-RUN",
      defaultTtlMs: 300_000,
      maxTtlMs: 600_000,
      credentialType: "password",
    });
    expect(role.creationStatements).toHaveLength(1);
    expect(await c.database("db2").readRole("odd")).toMatchObject({
      dbName: "",
      credentialType: "",
    });
    await db.deleteRole("rt-role-RUN");
    expect(m.keys().at(-1)).toBe("DELETE /v1/database/roles/rt-role-RUN");
    await expect(db.deleteRole("")).rejects.toMatchObject({ code: "VALIDATION" });
  });
});

describe("LeaseManager", () => {
  it("renew (capped warnings), lookup, revoke, revokePrefix", async () => {
    const m = await vault({
      "PUT /v1/sys/leases/renew": [
        "lease.renew",
        "lease.renew_over_max",
        "lease.renew_invalid",
        data(null, { lease_id: undefined }),
      ],
      "PUT /v1/sys/leases/lookup": ["lease.lookup", "lease.lookup_revoked", data({})],
      ...fromFixtures("lease.revoke"),
      "PUT /v1/sys/leases/revoke-prefix/database/creds/sdk-short": NO_CONTENT,
    });
    const leases = m.client().leases;
    const r = await leases.renew(LEASE, 900_000);
    expect(m.body()).toEqual({ lease_id: LEASE, increment: "900s" });
    expect(r).toMatchObject({ leaseId: LEASE, renewable: true, leaseDurationMs: 900_000 });
    const capped = await leases.renew(LEASE, 100 * 3_600_000);
    expect(capped.leaseDurationMs).toBe(3_600_000);
    expect(capped.warnings[0]).toContain("capped");
    expect((await rejection(leases.renew(LEASE))).message).toContain("lease not found");
    expect(m.body()).toEqual({ lease_id: LEASE });
    expect((await leases.renew("x")).leaseId).toBe("x");
    const info = await leases.lookup(LEASE);
    // Vault's lookup has no `path` field (OpenBao adds one) and the recorded id is redacted.
    expect(info).toMatchObject({
      id: "REDACTED",
      path: "",
      renewable: true,
      ttlMs: 599_000,
      lastRenewal: null,
    });
    expect(info.expireTime).toBeInstanceOf(Date);
    expect((await rejection(leases.lookup("gone"))).code).toBe("VALIDATION");
    expect(await leases.lookup("y")).toMatchObject({ id: "y", path: "" });
    await leases.revoke(LEASE);
    expect(m.body()).toEqual({ lease_id: LEASE });
    await leases.revokePrefix("database/creds/sdk-short");
    expect(m.keys().at(-1)).toBe("PUT /v1/sys/leases/revoke-prefix/database/creds/sdk-short");
    await expect(leases.revoke("")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("manage() renews, detects the max TTL and fires onExpire once", async () => {
    const clock = new ManualScheduler();
    const m = await vault({
      "PUT /v1/sys/leases/renew": [
        data(null, { lease_id: LEASE, renewable: true, lease_duration: 3600 }),
        data(null, { lease_id: LEASE, renewable: true, lease_duration: 600, warnings: ["capped"] }),
      ],
    });
    const c = m.client();
    const onRenew = vi.fn();
    const onExpire = vi.fn();
    const handle = c.leases.manage(
      { leaseId: LEASE, leaseDurationMs: 3_600_000, renewable: true },
      { scheduler: clock, onRenew, onExpire },
    );
    expect(handle.leaseId).toBe(LEASE);
    expect(handle.running).toBe(true);
    expect(c.leases.activeLeases).toBe(1);
    await clock.advance(2_400_000);
    await vi.waitFor(() => expect(onRenew).toHaveBeenCalledTimes(1));
    expect(onRenew.mock.calls[0]?.[0]).toMatchObject({
      leaseId: LEASE,
      leaseDurationMs: 3_600_000,
    });
    await clock.advance(2_400_000);
    await vi.waitFor(() => expect(onRenew).toHaveBeenCalledTimes(2));
    expect(onRenew.mock.calls[1]?.[0]).toMatchObject({ warnings: ["capped"] });
    expect(handle.expiresAt).toBe(clock.now() + 600_000);
    await clock.advance(600_000);
    expect(onExpire).toHaveBeenCalledTimes(1);
    expect(handle.expired).toBe(true);
    expect(c.leases.activeLeases).toBe(0);
    await handle.stop();
  });

  it("stop() with revokeOnStop revokes once; close() stops all", async () => {
    const clock = new ManualScheduler();
    const m = await vault({ "PUT /v1/sys/leases/revoke": [NO_CONTENT, errors(500, "boom")] });
    const c = m.client();
    const a = c.leases.manage(
      { leaseId: "l/a", leaseDurationMs: 60_000, renewable: true },
      { scheduler: clock, revokeOnStop: true },
    );
    await Promise.all([a.stop(), a.stop()]);
    expect(m.keys()).toEqual(["PUT /v1/sys/leases/revoke"]);
    expect(a.running).toBe(false);
    const onError = vi.fn();
    c.leases.manage(
      { leaseId: "l/b", leaseDurationMs: 60_000, renewable: true },
      { scheduler: clock, revokeOnStop: true, onError },
    );
    c.leases.manage(
      { leaseId: "l/c", leaseDurationMs: 60_000, renewable: true },
      { scheduler: clock },
    );
    expect(c.leases.activeLeases).toBe(2);
    await c.close();
    expect(c.leases.activeLeases).toBe(0);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(() => c.leases.manage({ leaseId: "", leaseDurationMs: 1, renewable: true })).toThrow(
      /no id/,
    );
  });
});
