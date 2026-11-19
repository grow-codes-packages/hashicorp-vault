import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { REDACTED, Secret } from "../src/index.js";
import {
  NO_CONTENT,
  data,
  errors,
  fixture,
  fromFixtures,
  fx,
  rejection,
  vault,
} from "./support/vault.js";

const SERIAL = "0f:0d:60:2b:8a:bc:ab:4d:f8:9f:a7:0e:59:3a:01:10:3e:8c:a4:47";
/** The test CSR used by the Docker fixture (docker/bootstrap/test-csr.pem). */
const CSR = readFileSync(new URL("../../docker/bootstrap/test-csr.pem", import.meta.url), "utf8");

describe("Pki", () => {
  it("issueCertificate returns the chain and a redacted private key", async () => {
    const m = await vault({
      "POST /v1/pki/issue/sdk-test": [
        fx("pki.issue", (b) => ({
          ...b,
          data: { ...b.data, private_key: "PRIVATE-KEY-PEM" },
        })),
        "pki.issue_denied",
        data({ certificate: "c" }),
        data({}),
      ],
    });
    const pki = m.client().pki();
    expect(pki.mount).toBe("pki");
    const cert = await pki.issueCertificate("sdk-test", "svc.sdk.test", {
      altNames: ["alt.sdk.test"],
      ipSans: ["127.0.0.1"],
      ttlMs: 3_600_000,
    });
    expect(m.body()).toEqual({
      common_name: "svc.sdk.test",
      alt_names: "alt.sdk.test",
      ip_sans: "127.0.0.1",
      ttl: "3600s",
    });
    expect(cert.certificate).toMatch(/^-----BEGIN CERTIFICATE-----/);
    expect(cert.caChain.length).toBeGreaterThan(0);
    expect(cert.issuingCa).toMatch(/BEGIN CERTIFICATE/);
    expect(cert.serialNumber).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2})+$/);
    expect(cert.privateKeyType).toBe("ec");
    expect(cert.expiration).toBeInstanceOf(Date);
    expect(cert.privateKey.reveal()).toBe("PRIVATE-KEY-PEM");
    expect(inspect(cert)).not.toContain("PRIVATE-KEY-PEM");
    const denied = await rejection(pki.issueCertificate("sdk-test", "evil.example.com"));
    expect(denied.code).toBe("VALIDATION");
    expect(denied.message).toContain("not allowed by this role");
    const minimal = await pki.issueCertificate("sdk-test", "x.example.test", {
      uriSans: ["spiffe://x"],
      format: "pem",
      privateKeyFormat: "pkcs8",
      excludeCnFromSans: true,
      altNames: [],
    });
    expect(m.body()).toEqual({
      common_name: "x.example.test",
      uri_sans: "spiffe://x",
      format: "pem",
      private_key_format: "pkcs8",
      exclude_cn_from_sans: true,
    });
    expect(minimal).toMatchObject({
      issuingCa: "",
      caChain: [],
      serialNumber: "",
      privateKeyType: "",
    });
    expect(minimal.privateKey.reveal()).toBe("");
    expect((await rejection(pki.issueCertificate("sdk-test", "y.example.test"))).message).toContain(
      "no certificate",
    );
  });

  it("signCsr, revokeCertificate, readCertificate, listCertificates, readCaChain", async () => {
    const m = await vault({
      "POST /v1/pki/sign/sdk-test": [
        "pki.sign_csr",
        errors(400, "certificate request could not be parsed: asn1: structure error"),
      ],
      "POST /v1/pki/revoke": [
        "pki.revoke_certificate",
        "pki.revoke_missing",
        data({ revocation_time: 1795033545 }),
      ],
      [`GET /v1/pki/cert/${SERIAL}`]: ["pki.read_certificate", "pki.read_revoked", data({})],
      "GET /v1/pki/cert/00-11-22": "pki.read_certificate_missing",
      "LIST /v1/pki/certs": "pki.list_certificates",
      "LIST /v1/pki2/certs": errors(404),
      "LIST /v1/pki3/certs": errors(403, "1 error occurred: * permission denied"),
      "GET /v1/pki/ca_chain": "pki.read_ca_chain_pem",
      "GET /v1/pki2/ca_chain": { status: 200, body: "" },
    });
    const c = m.client();
    const pki = c.pki();
    const signed = await pki.signCsr("sdk-test", CSR, {
      commonName: "csr.sdk.test",
      ttlMs: 3_600_000,
    });
    expect(m.body()).toEqual({ csr: CSR, common_name: "csr.sdk.test", ttl: "3600s" });
    expect(signed.certificate).toMatch(/BEGIN CERTIFICATE/);
    expect(signed).not.toHaveProperty("privateKey");
    expect((await rejection(pki.signCsr("sdk-test", "not a csr"))).code).toBe("VALIDATION");
    const rev = await pki.revokeCertificate(SERIAL);
    expect(m.body()).toEqual({ serial_number: SERIAL });
    expect(rev.state).toBe("revoked");
    expect(rev.revocationTime?.toISOString()).toBe("2026-11-18T20:25:45.899Z");
    expect((await rejection(pki.revokeCertificate("00-11-22-33"))).message).toContain("not found");
    expect(await pki.revokeCertificate(SERIAL)).toMatchObject({ state: "revoked" });
    const info = await pki.readCertificate(SERIAL);
    expect(info.revocationTime).toBeNull();
    expect((await pki.readCertificate(SERIAL)).revocationTime).toBeInstanceOf(Date);
    expect((await rejection(pki.readCertificate(SERIAL))).message).toContain("no certificate");
    expect((await rejection(pki.readCertificate("00-11-22"))).code).toBe("NOT_FOUND");
    expect(await pki.listCertificates()).toContain(SERIAL);
    expect(await c.pki("pki2").listCertificates()).toEqual([]);
    expect((await rejection(c.pki("pki3").listCertificates())).code).toBe("PERMISSION_DENIED");
    expect(await pki.readCaChain()).toMatch(/^-----BEGIN CERTIFICATE-----/);
    expect(await c.pki("pki2").readCaChain()).toBe("");
  });

  it("tidy starts (202) and waits for Finished; tidyStatus maps fields", async () => {
    const m = await vault({
      "POST /v1/pki/tidy": "pki.tidy",
      "GET /v1/pki/tidy-status": [
        data({ state: "Running" }),
        "pki.tidy_status",
        data({ state: "Error", error: "boom" }),
      ],
    });
    const pki = m.client().pki();
    const status = await pki.tidy({ safetyBufferMs: 1000, intervalMs: 1 });
    expect(m.body(0)).toEqual({
      tidy_cert_store: true,
      tidy_revoked_certs: true,
      safety_buffer: "1s",
    });
    expect(status.state).toBe("Finished");
    expect(status.error).toBeNull();
    expect(status.timeFinished).toBeInstanceOf(Date);
    const started = await pki.tidy({ wait: false, tidyCertStore: false, tidyRevokedCerts: false });
    expect(m.body(-2)).toEqual({ tidy_cert_store: false, tidy_revoked_certs: false });
    expect(started).toMatchObject({ state: "Error", error: "boom", certStoreDeletedCount: 0 });
  });
});

describe("Sys", () => {
  it("sealStatus, leader, health (raw)", async () => {
    const m = await vault({
      "GET /v1/sys/seal-status": ["seal_status", "seal.status_after", NO_CONTENT],
      "GET /v1/sys/leader": "leader",
      "GET /v1/sys/health": "health",
    });
    const sys = m.client().sys;
    expect(await sys.sealStatus()).toMatchObject({
      type: "shamir",
      initialized: true,
      sealed: false,
      threshold: 1,
      shares: 1,
      progress: 0,
      recoverySeal: false,
      version: "2.2.2",
      buildDate: "2026-11-11T13:53:02Z",
    });
    expect(await sys.sealStatus()).toMatchObject({ sealed: true, storageType: "file" });
    expect((await rejection(sys.sealStatus())).message).toContain("empty response body");
    const leader = await sys.leader();
    // File storage: no HA on Vault (OpenBao's raft reports ha_enabled=true).
    expect(leader).toMatchObject({
      haEnabled: false,
      isSelf: false,
      leaderAddress: "",
      leaderClusterAddress: "",
      performanceStandby: false,
      performanceStandbyLastRemoteWal: 0,
    });
    expect(leader.activeTime).toBeInstanceOf(Date);
    const health = await sys.health();
    expect(health).toMatchObject({
      state: "active",
      initialized: true,
      sealed: false,
      version: "2.2.2",
    });
    expect(health.serverTime).toBeInstanceOf(Date);
    expect(m.req().headers["x-vault-token"]).toBe("root-token-test");
    expect(await sys.version()).toBe("2.2.2");
  });

  it("policies", async () => {
    const m = await vault({
      ...fromFixtures("policy.write", "policy.read", "policy.list", "policy.delete"),
      "PUT /v1/sys/policies/acl/bad-RUN": "policy.write_invalid",
      "GET /v1/sys/policies/acl/missing-RUN": "policy.read_missing",
      "DELETE /v1/sys/policies/acl/root": "policy.delete_root",
      "GET /v1/sys/policies/acl/noname": data({}),
    });
    const sys = m.client().sys;
    const hcl = 'path "secret/data/rt/*" {\n  capabilities = ["read"]\n}\n';
    await sys.writePolicy("rt-pol-RUN", hcl);
    expect(m.body()).toEqual({ policy: hcl });
    expect(await sys.readPolicy("rt-pol-RUN")).toEqual({ name: "rt-pol-RUN", policy: hcl });
    expect(await sys.readPolicy("noname")).toEqual({ name: "noname", policy: "" });
    expect(await sys.listPolicies()).toEqual([
      "default",
      "default-ceiling",
      "rt-pol-RUN",
      "sdk-app",
      "sdk-oidc",
      "root",
    ]);
    await sys.deletePolicy("rt-pol-RUN");
    const invalid = await rejection(sys.writePolicy("bad-RUN", "path {"));
    expect(invalid.code).toBe("VALIDATION");
    expect(invalid.message).toContain("failed to parse policy");
    expect((await rejection(sys.readPolicy("missing-RUN"))).code).toBe("NOT_FOUND");
    expect((await rejection(sys.deletePolicy("root"))).code).toBe("VALIDATION");
    await expect(sys.writePolicy("x", "")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("secrets engines and auth methods", async () => {
    const m = await vault({
      "GET /v1/sys/mounts": ["mounts.list", "approle.denied_read"],
      "POST /v1/sys/mounts/rt-kv-RUN": ["mounts.enable", "mounts.enable_conflict"],
      ...fromFixtures("mounts.disable", "auth.list", "auth.enable", "auth.disable"),
    });
    const sys = m.client().sys;
    const mounts = await sys.listMounts();
    expect(mounts["secret/"]).toMatchObject({ type: "kv", options: { version: "2" } });
    expect(mounts["kv1/"]?.options.version).toBe("1");
    expect(Object.keys(mounts)).not.toContain("request_id");
    expect((await rejection(sys.listMounts())).code).toBe("PERMISSION_DENIED");
    await sys.enableSecretsEngine("rt-kv-RUN", "kv", {
      options: { version: "2" },
      description: "sdk rt",
    });
    expect(m.body()).toEqual({ type: "kv", options: { version: "2" }, description: "sdk rt" });
    const conflict = await rejection(
      sys.enableSecretsEngine("/rt-kv-RUN/", "kv", {
        defaultLeaseTtlMs: 60_000,
        maxLeaseTtlMs: 120_000,
        local: false,
        sealWrap: false,
      }),
    );
    expect(m.body()).toEqual({
      type: "kv",
      config: { default_lease_ttl: "60s", max_lease_ttl: "120s" },
      local: false,
      seal_wrap: false,
    });
    expect(conflict.code).toBe("VALIDATION");
    expect(conflict.message).toContain("already in use");
    await sys.disableSecretsEngine("rt-kv-RUN");
    const auths = await sys.listAuthMethods();
    expect(auths["approle/"]?.type).toBe("approle");
    expect(auths["token/"]?.type).toBe("token");
    await sys.enableAuthMethod("rt-ap-RUN", "approle", { description: "sdk temp" });
    expect(m.body()).toEqual({ type: "approle", description: "sdk temp" });
    await sys.disableAuthMethod("rt-ap-RUN");
    expect(m.keys().at(-1)).toBe("DELETE /v1/sys/auth/rt-ap-RUN");
  });

  it("enableAuthMethod with TTL config", async () => {
    const m = await vault({ "POST /v1/sys/auth/up2": NO_CONTENT });
    await m.client().sys.enableAuthMethod("up2", "userpass", {
      defaultLeaseTtlMs: 1000,
      maxLeaseTtlMs: 2000,
      local: true,
    });
    expect(m.body()).toEqual({
      type: "userpass",
      config: { default_lease_ttl: "1s", max_lease_ttl: "2s" },
      local: true,
    });
  });

  it("AppRole administration", async () => {
    const m = await vault({
      "POST /v1/auth/ar-RUN/role/rt-role-RUN": "approle.create_role",
      "GET /v1/auth/ar-RUN/role/rt-role-RUN/role-id": fx("approle.read_role_id", (b) => ({
        ...b,
        data: { role_id: "0a235ec1-2d7d-fd7a-8b4f-8a684196312e" },
      })),
      "LIST /v1/auth/ar-RUN/role": "approle.list_roles",
      "POST /v1/auth/ar-RUN/role/rt-role-RUN/secret-id": fx("approle.generate_secret_id", (b) => ({
        ...b,
        data: { ...b.data, secret_id: "sid-123", secret_id_accessor: "acc-123" },
      })),
      "GET /v1/auth/ar-RUN/role/missing/role-id": errors(404),
      "LIST /v1/auth/approle/role": errors(404),
      "LIST /v1/auth/denied/role": errors(403, "1 error occurred: * permission denied"),
      "DELETE /v1/auth/approle/role/old": NO_CONTENT,
      "POST /v1/auth/approle/role/y": NO_CONTENT,
      "GET /v1/auth/approle/role/x/role-id": data({}),
      "POST /v1/auth/approle/role/x/secret-id": data({}),
    });
    const sys = m.client().sys;
    await sys.createAppRole("rt-role-RUN", {
      mount: "ar-RUN",
      tokenPolicies: ["sdk-app"],
      secretIdNumUses: 1,
      tokenTtlMs: 600_000,
    });
    expect(m.body()).toEqual({
      token_policies: ["sdk-app"],
      secret_id_num_uses: 1,
      token_ttl: "600s",
    });
    expect(await sys.readRoleId("rt-role-RUN", { mount: "ar-RUN" })).toBe(
      "0a235ec1-2d7d-fd7a-8b4f-8a684196312e",
    );
    expect((await rejection(sys.readRoleId("missing", { mount: "ar-RUN" }))).code).toBe(
      "NOT_FOUND",
    );
    const sid = await sys.generateSecretId("rt-role-RUN", {
      mount: "ar-RUN",
      metadata: { tag: "sdk" },
    });
    expect(m.body()).toEqual({ metadata: '{"tag":"sdk"}' });
    expect(sid.secretId.reveal()).toBe("sid-123");
    expect(sid.secretIdNumUses).toBe(1);
    expect(sid.secretIdTtlMs).toBe(0);
    expect(inspect(sid)).not.toContain("sid-123");
    expect(String(sid.secretIdAccessor)).toBe(REDACTED);
    expect(await sys.listAppRoles({ mount: "ar-RUN" })).toEqual(["rt-role-RUN", "sdk-app"]);
    expect(await sys.listAppRoles()).toEqual([]);
    expect((await rejection(sys.listAppRoles({ mount: "denied" }))).code).toBe("PERMISSION_DENIED");
    await sys.deleteAppRole("old");
    await sys.createAppRole("y", {
      tokenMaxTtlMs: 1000,
      secretIdTtlMs: 0,
      bindSecretId: true,
      tokenType: "batch",
    });
    expect(m.body()).toEqual({
      token_max_ttl: "1s",
      secret_id_ttl: "0s",
      bind_secret_id: true,
      token_type: "batch",
    });
    expect((await rejection(sys.readRoleId("x"))).message).toContain("no role_id");
    expect(
      (
        await rejection(
          sys.generateSecretId("x", { cidrList: ["10.0.0.0/8"], ttlMs: 1000, numUses: 2 }),
        )
      ).message,
    ).toContain("no secret_id");
    expect(m.body()).toEqual({ cidr_list: ["10.0.0.0/8"], ttl: "1s", num_uses: 2 });
  });
});

describe("Wrapping", () => {
  it("wrap -> lookupWrapping -> unwrap; tokens are redacted", async () => {
    const m = await vault({
      "POST /v1/sys/wrapping/wrap": [
        fx("wrapping.wrap", (b) => ({
          ...b,
          wrap_info: { ...b.wrap_info, token: "wrap-tok-1" },
        })),
        errors(400, "wrap_ttl must be set"),
        data(null),
      ],
      "POST /v1/sys/wrapping/lookup": [
        "wrapping.lookup",
        errors(400, "wrapping token is not valid or does not exist"),
      ],
      "POST /v1/sys/wrapping/unwrap": ["wrapping.unwrap", "wrapping.unwrap_again"],
    });
    const w = m.client().wrapping;
    const info = await w.wrap({ foo: "bar", n: 1 }, 300_000);
    expect(m.req().headers["x-vault-wrap-ttl"]).toBe("300s");
    expect(m.body()).toEqual({ foo: "bar", n: 1 });
    expect(info).toMatchObject({ ttlMs: 300_000, creationPath: "sys/wrapping/wrap" });
    expect(info.token.reveal()).toBe("wrap-tok-1");
    expect(inspect(info)).not.toContain("wrap-tok-1");
    const lookup = await w.lookupWrapping(info.token);
    expect(m.req().headers["x-vault-token"]).toBeUndefined();
    expect(m.body()).toEqual({ token: "wrap-tok-1" });
    expect(lookup).toMatchObject({ creationPath: "sys/wrapping/wrap", creationTtlMs: 300_000 });
    expect(lookup.creationTime).toBeInstanceOf(Date);
    const unwrapped = await w.unwrap(info.token);
    expect(m.req().headers["x-vault-token"]).toBe("wrap-tok-1");
    expect(m.req().body).toBe("");
    expect(unwrapped.data).toEqual({ foo: "bar", n: 1 });
    expect(unwrapped.auth).toBeUndefined();
    const used = await rejection(w.unwrap("wrap-tok-1"));
    expect(used.code).toBe("VALIDATION");
    expect(used.message).toContain("not valid or does not exist");
    expect((await rejection(w.lookupWrapping("wrap-tok-1"))).code).toBe("VALIDATION");
    expect((await rejection(w.wrap({ x: 1 }, 0))).code).toBe("VALIDATION");
    expect((await rejection(w.wrap({ x: 1 }, 1000))).message).toContain("no wrap_info");
    await expect(w.unwrap("")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("unwrap of a wrapped login returns its auth block", async () => {
    const login = fixture("approle.login").body as { auth: object };
    const m = await vault({
      "POST /v1/sys/wrapping/unwrap": {
        status: 200,
        body: {
          ...login,
          auth: { ...login.auth, client_token: "s.wrapped" },
          lease_id: "l",
          lease_duration: 5,
          renewable: true,
          warnings: ["w"],
        },
      },
      "POST /v1/sys/wrapping/lookup": data({}),
    });
    const w = m.client().wrapping;
    const r = await w.unwrap(new Secret("wt"));
    expect(r.data).toBeNull();
    expect(r.auth?.clientToken.reveal()).toBe("s.wrapped");
    expect(r).toMatchObject({
      leaseId: "l",
      leaseDurationMs: 5000,
      renewable: true,
      warnings: ["w"],
    });
    expect(await w.lookupWrapping("t")).toEqual({
      creationPath: "",
      creationTime: null,
      creationTtlMs: 0,
    });
  });
});
