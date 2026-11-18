import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  ConfigError,
  ErrorCode,
  NotFoundError,
  PACKAGE_KEY,
  PermissionDeniedError,
  REDACTED,
  RetryPolicy,
  Secret,
  UnavailableError,
  VENDOR_ENV,
  VaultClient,
  VaultConfig,
  VaultError,
} from "../src/index.js";
import { mapVaultError } from "../src/http.js";
import { closedPort } from "./helpers/server.js";
import { NO_CONTENT, data, errors, fixture, fx, rejection, vault } from "./support/vault.js";

describe("VaultConfig", () => {
  it("uses defaults and freezes", () => {
    const c = new VaultConfig();
    expect(c.url).toBe("http://127.0.0.1:8200");
    expect(c.requestTimeoutMs).toBe(30_000);
    expect(c.retry).toBeInstanceOf(RetryPolicy);
    expect(c.token).toBeUndefined();
    expect(c.namespace).toBeUndefined();
    expect(c.kvMount).toBe("secret");
    expect(c.kvVersion).toBeUndefined();
    expect(Object.isFrozen(c)).toBe(true);
    expect(VaultConfig.from(c)).toBe(c);
    expect(VaultConfig.from().url).toBe(c.url);
    expect(VaultConfig.ENV_PREFIX).toBe(`GROW_${PACKAGE_KEY.toUpperCase().replace(/-/g, "_")}_`);
  });

  it("keeps optional settings", () => {
    const hooks = {};
    const logger = { debug() {}, info() {}, warn() {}, error() {} };
    const c = new VaultConfig({
      proxy: "http://p:1",
      userAgentSuffix: "s",
      hooks,
      logger,
      token: new Secret("abcd"),
      namespace: "team-a",
      kvMount: "/kv/",
      kvVersion: 1,
    });
    expect(c.proxy).toBe("http://p:1");
    expect(c.userAgentSuffix).toBe("s");
    expect(c.hooks).toBe(hooks);
    expect(c.logger).toBe(logger);
    expect(c.knownSecrets()).toEqual(["abcd"]);
    expect(c.namespace).toBe("team-a");
    expect(c.kvVersion).toBe(1);
    expect(new VaultConfig({ namespace: "" }).namespace).toBeUndefined();
  });

  it("validate() raises ConfigError", () => {
    expect(() => new VaultConfig({ url: "ftp://x" })).toThrow(ConfigError);
    expect(() => new VaultConfig({ token: "   " })).toThrow(ConfigError);
    expect(() => new VaultConfig({ kvMount: "//" })).toThrow(/kvMount/);
    expect(() => new VaultConfig({ kvVersion: 3 as never })).toThrow(/kvVersion/);
  });

  it("core.redaction.config: toString/JSON/inspect hide credentials", () => {
    const c = new VaultConfig({
      token: "super-secret-tok",
      headers: { "x-api-key": "hdr-secret" },
    });
    for (const form of [String(c), JSON.stringify(c), inspect(c), `${c.token}`]) {
      expect(form).not.toContain("super-secret-tok");
      expect(form).not.toContain("hdr-secret");
    }
    expect(String(c)).toContain(REDACTED);
    expect(String(c)).toMatch(/^VaultConfig\(/);
    expect(new VaultConfig().toJSON()).toMatchObject({
      token: null,
      namespace: null,
      kvMount: "secret",
      kvVersion: null,
    });
  });

  it("vendor variables: the Vault CLI names", () => {
    expect(VENDOR_ENV.url).toEqual(["VAULT_ADDR"]);
    expect(VENDOR_ENV.token).toEqual(["VAULT_TOKEN"]);
    expect(VENDOR_ENV.namespace).toEqual(["VAULT_NAMESPACE"]);
    expect(VENDOR_ENV.caCert).toEqual(["VAULT_CACERT"]);
    expect(VENDOR_ENV.clientCert).toEqual(["VAULT_CLIENT_CERT"]);
    expect(VENDOR_ENV.clientKey).toEqual(["VAULT_CLIENT_KEY"]);
    expect(VENDOR_ENV.insecureSkipVerify).toEqual(["VAULT_SKIP_VERIFY"]);
  });

  it("core.config.env-precedence: explicit > GROW_* > vendor > default", () => {
    const env = {
      GROW_HASHICORP_VAULT_URL: "http://grow:1",
      VAULT_ADDR: "http://vault:3",
      VAULT_TOKEN: "vault-token",
      GROW_HASHICORP_VAULT_REQUEST_TIMEOUT: "5s",
      GROW_HASHICORP_VAULT_MAX_RETRIES: "7",
      VAULT_NAMESPACE: "ns-vault",
      VAULT_CACERT: "/ca.pem",
      VAULT_CLIENT_CERT: "/c.pem",
      VAULT_CLIENT_KEY: "/k.pem",
      VAULT_SKIP_VERIFY: "true",
    };
    const c = VaultConfig.fromEnv({}, env);
    expect(c.url).toBe("http://grow:1");
    expect(c.token?.reveal()).toBe("vault-token");
    expect(c.requestTimeoutMs).toBe(5000);
    expect(c.retry.maxRetries).toBe(7);
    expect(c.namespace).toBe("ns-vault");
    expect(c.tls).toMatchObject({
      caCertPath: "/ca.pem",
      clientCertPath: "/c.pem",
      clientKeyPath: "/k.pem",
      insecureSkipVerify: true,
    });
    expect(VaultConfig.fromEnv({}, { VAULT_ADDR: "http://v:3" }).url).toBe("http://v:3");
    expect(
      VaultConfig.fromEnv(
        {},
        { GROW_HASHICORP_VAULT_TOKEN: "grow", VAULT_TOKEN: "vault" },
      ).token?.reveal(),
    ).toBe("grow");
    expect(
      VaultConfig.fromEnv({}, { GROW_HASHICORP_VAULT_NAMESPACE: "g", VAULT_NAMESPACE: "v" })
        .namespace,
    ).toBe("g");
    // BAO_* (OpenBao CLI) names are not read by the Vault package.
    expect(VaultConfig.fromEnv({}, { BAO_ADDR: "http://bao:2" }).url).toBe(VaultConfig.DEFAULT_URL);
    const explicit = VaultConfig.fromEnv(
      { url: "http://explicit:3", token: "explicit-token", namespace: "x" },
      env,
    );
    expect(explicit.url).toBe("http://explicit:3");
    expect(explicit.token?.reveal()).toBe("explicit-token");
    expect(explicit.namespace).toBe("x");
    expect(VaultConfig.fromEnv({}, {}).url).toBe(VaultConfig.DEFAULT_URL);
    expect(VaultConfig.fromEnv().url).toBeTypeOf("string");
    const err = (() => {
      try {
        VaultConfig.fromEnv({}, { GROW_HASHICORP_VAULT_TOTAL_TIMEOUT: "forever-and-secret" });
      } catch (e) {
        return e as Error;
      }
      return undefined;
    })();
    expect(err).toBeInstanceOf(ConfigError);
    expect(err?.message).toContain("GROW_HASHICORP_VAULT_TOTAL_TIMEOUT");
    expect(err?.message).not.toContain("forever-and-secret");
  });
});

describe("VaultClient basics", () => {
  it("health maps every node state and never throws", async () => {
    const m = await vault({
      "GET /v1/sys/health": [
        "health",
        fx("init.health_sealed", (b) => ({ ...b })),
        fx("init.health_uninit"),
        data(null, {}),
      ],
    });
    // sys/health answers 200 in every state thanks to the custom status codes.
    const c = m.client();
    const active = await c.health();
    expect(active).toMatchObject({ healthy: true, status: "active" });
    expect(active.details).toMatchObject({ version: "2.2.2", sealed: "false" });
    expect(new URL(m.req(0).url, "http://x").searchParams.get("sealedcode")).toBe("200");
    expect(m.req(0).headers["x-vault-token"]).toBe("root-token-test");
  });

  it("health derives sealed/uninitialized/standby/perfstandby from the body", async () => {
    const sealed = fixture("init.health_sealed").body as Record<string, unknown>;
    const uninit = fixture("init.health_uninit").body as Record<string, unknown>;
    const m = await vault({
      "GET /v1/sys/health": [
        { status: 200, body: sealed },
        { status: 200, body: uninit },
        { status: 200, body: { initialized: true, sealed: false, standby: true } },
        {
          status: 200,
          body: { initialized: true, sealed: false, standby: true, performance_standby: true },
        },
        { status: 200, body: "" },
        { status: 500, body: { errors: ["boom"] } },
      ],
    });
    const c = m.client();
    expect(await c.health()).toMatchObject({ healthy: false, status: "sealed" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "uninitialized" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "standby" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "perfstandby" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "unreachable" });
    expect(await c.health()).toMatchObject({
      healthy: false,
      status: "unhealthy",
      details: { httpStatus: "500" },
    });
  });

  it("core.health.unreachable: closed port -> unreachable; cancellation rethrows", async () => {
    const port = await closedPort();
    const c = new VaultClient({ url: `http://127.0.0.1:${port}`, retry: { maxRetries: 0 } });
    expect(await c.health()).toEqual({
      healthy: false,
      status: "unreachable",
      details: { error: "UNAVAILABLE" },
    });
    await expect(c.health({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await c.close();
  });

  it("ping uses lookup-self; a bad token is AUTHENTICATION and never leaks", async () => {
    const m = await vault({
      "GET /v1/auth/token/lookup-self": ["token.lookup_self", "ping.bad_token", errors(400, "x")],
    });
    const c = m.client({ token: "wrong-token-xyz" });
    expect(await c.ping()).toBeGreaterThanOrEqual(0);
    const err = await rejection(c.ping());
    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe("AUTHENTICATION");
    expect(err.httpStatus).toBe(403);
    expect(err.message).not.toContain("wrong-token-xyz");
    expect((await rejection(c.ping())).code).toBe("AUTHENTICATION");
  });

  it("serverVersion and sys.version read sys/health", async () => {
    const m = await vault({
      "GET /v1/sys/health": ["health", { status: 200, body: { initialized: true } }],
    });
    const c = m.client();
    expect(await c.serverVersion()).toBe("2.2.2");
    await expect(c.serverVersion()).rejects.toMatchObject({ code: "UNSUPPORTED" });
  });

  it("core.close.idempotent: close twice; calls after close raise CONFIG", async () => {
    const m = await vault({ "GET /v1/sys/health": "health" });
    const c = m.client();
    await c.health();
    expect(c.closed).toBe(false);
    await c.close();
    await c.close();
    expect(c.closed).toBe(true);
    await expect(c.ping()).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("fromEnv builds from GROW_* variables; namespace header is sent", async () => {
    const m = await vault({ "GET /v1/auth/token/lookup-self": "token.lookup_self" });
    process.env.GROW_HASHICORP_VAULT_URL = m.url;
    process.env.GROW_HASHICORP_VAULT_NAMESPACE = "sdk-ns";
    try {
      const c = VaultClient.fromEnv({ token: "env-token" });
      expect(c.config.url).toBe(m.url);
      await c.ping();
      expect(m.req().headers["x-vault-namespace"]).toBe("sdk-ns");
      expect(m.req().headers["x-vault-token"]).toBe("env-token");
      expect(m.req().headers["user-agent"]).toMatch(
        /^grow-codes-hashicorp-vault\/\S+ \(typescript\)$/,
      );
      await c.close();
    } finally {
      delete process.env.GROW_HASHICORP_VAULT_URL;
      delete process.env.GROW_HASHICORP_VAULT_NAMESPACE;
    }
  });

  it("setToken replaces and removes the token", async () => {
    const m = await vault({ "GET /v1/auth/token/lookup-self": "token.lookup_self" });
    const c = m.client();
    c.setToken("other");
    expect(String(c.token)).toBe(REDACTED);
    await c.ping();
    expect(m.req().headers["x-vault-token"]).toBe("other");
    c.setToken(undefined);
    expect(c.token).toBeUndefined();
    await c.ping();
    expect(m.req().headers["x-vault-token"]).toBeUndefined();
    expect(c.transport.userAgent).toContain("grow-codes-hashicorp-vault/");
  });

  it("request() calls any path with list, query, wrapping and envelope decoding", async () => {
    const m = await vault({
      "LIST /v1/sys/version-history": "version_history",
      "GET /v1/secret/data/a%20b": fx("wrapping.wrap_kv_read"),
      "DELETE /v1/kv1/x": NO_CONTENT,
      "PUT /v1/sys/leases/renew": "lease.renew_over_max",
    });
    const c = m.client();
    const history = await c.request<{ keys: string[] }>("GET", "/sys/version-history", {
      list: true,
    });
    expect(history.data?.keys).toEqual(["2.2.2"]);
    const wrapped = await c.request("GET", "secret/data/a b", { wrapTtlMs: 60_000 });
    expect(m.req().headers["x-vault-wrap-ttl"]).toBe("60s");
    expect(wrapped.data).toBeNull();
    expect(wrapped.wrapInfo?.ttlMs).toBe(60_000);
    expect(String(wrapped.wrapInfo?.token)).toBe(REDACTED);
    const del = await c.request("DELETE", "kv1/x");
    expect(del).toMatchObject({ status: 204, data: null, leaseId: "", warnings: [] });
    const renewed = await c.request("PUT", "sys/leases/renew", { json: { lease_id: "l" } });
    expect(renewed.leaseDurationMs).toBe(3_600_000);
    expect(renewed.renewable).toBe(true);
    expect(renewed.warnings[0]).toContain("capped");
  });
});

describe("error mapping", () => {
  it("403: plain 'permission denied' = AUTHENTICATION, policy denial = PERMISSION_DENIED", async () => {
    const m = await vault({
      "GET /v1/secret/data/sdk/denied/hello": "approle.denied_read",
      "GET /v1/secret/data/sdk/allowed/hello": "ping.no_token",
      "GET /v1/secret/data/x": errors(403, "invalid token"),
    });
    const c = m.client({ kvVersion: 2 });
    const denied = await rejection(c.kv().read("sdk/denied/hello"));
    expect(denied).toBeInstanceOf(PermissionDeniedError);
    expect(denied.message).toMatch(
      /^kv\.read secret\/sdk\/denied\/hello: 1 error occurred: \* permission denied +\(HTTP 403\)$/,
    );
    expect((await rejection(c.kv().read("sdk/allowed/hello"))).code).toBe("AUTHENTICATION");
    expect((await rejection(c.kv().read("x"))).code).toBe("AUTHENTICATION");
  });

  it("400 CAS mismatch = CONFLICT, 405 = UNSUPPORTED, 501 = UNAVAILABLE, 429 = RATE_LIMITED", async () => {
    const m = await vault({
      "POST /v1/secret/data/a": "kv2.write_cas0_conflict",
      "PATCH /v1/kv1/a": "kv1.patch_unsupported",
      "GET /v1/secret/data/b": errors(501, "Vault is not initialized"),
      // A rate-limit quota (not configured in the Docker fixture; shape from the Vault docs).
      "GET /v1/kv1/sdk/allowed/hello": {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": "29" },
        body: JSON.stringify({
          errors: ['request path "kv1/sdk/allowed/hello": rate limit quota exceeded'],
        }),
      },
      "GET /v1/secret/data/sealed": "sealed.request",
      "GET /v1/secret/data/c": errors(400, "bad"),
    });
    const c = m.client({ kvVersion: 2 });
    const cas = await rejection(c.kv().write("a", { v: 1 }, { cas: 9 }));
    expect(cas.code).toBe("CONFLICT");
    expect(cas.httpStatus).toBe(400);
    expect((await rejection(c.request("PATCH", "kv1/a", { json: {} }))).code).toBe("UNSUPPORTED");
    const unavailable = await rejection(c.kv().read("b"));
    expect(unavailable).toBeInstanceOf(UnavailableError);
    const limited = await rejection(c.kvV1("kv1").read("sdk/allowed/hello"));
    expect(limited.code).toBe("RATE_LIMITED");
    expect(limited.retryAfterMs).toBe(29_000);
    expect((await rejection(c.kv().read("c"))).code).toBe("VALIDATION");
    const sealed = await rejection(c.kv().read("sealed"));
    expect(sealed).toBeInstanceOf(UnavailableError);
    expect(sealed.httpStatus).toBe(503);
    expect(sealed.message).toContain("Vault is sealed");
  });

  it("404 = NOT_FOUND; mapVaultError keeps other errors", () => {
    const e = new NotFoundError("x");
    expect(mapVaultError(e)).toBe(e);
    const p = new PermissionDeniedError("op: 1 error occurred (HTTP 403)", { httpStatus: 403 });
    expect(mapVaultError(p)).toBe(p);
    const login = mapVaultError(
      new VaultError(ErrorCode.Validation, "op: invalid role (HTTP 400)", {
        httpStatus: 400,
        requestId: "r1",
        retryAfterMs: 5,
        cause: new Error("c"),
      }),
      true,
    );
    expect(login).toMatchObject({ code: "AUTHENTICATION", requestId: "r1", retryAfterMs: 5 });
  });

  it("transient 5xx is retried for idempotent requests", async () => {
    const m = await vault({
      "GET /v1/sys/seal-status": [errors(502, "bad gateway"), "seal_status"],
    });
    const c = m.client({ retry: { maxRetries: 2, initialBackoffMs: 1 } });
    expect((await c.sys.sealStatus()).sealed).toBe(false);
    expect(m.requests).toHaveLength(2);
  });
});
