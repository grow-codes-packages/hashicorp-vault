// Vault-only surface: namespaces (`withNamespace`, Enterprise feature) and capability checks
// (`sys.capabilities` / `sys.capabilitiesSelf`).

import { describe, expect, it } from "vitest";
import { Capability, VaultClient } from "../src/index.js";
import { data, rejection, vault } from "./support/vault.js";

describe("withNamespace (Enterprise only; Vault OSS ignores the header)", () => {
  it("the view sends X-Vault-Namespace on every request, the parent is unchanged", async () => {
    const m = await vault({
      "GET /v1/secret/data/app/RUN/login": "namespace.header_kv",
      "GET /v1/sys/health": "health.namespace_header",
      "GET /v1/auth/token/lookup-self": "token.lookup_self",
    });
    const c = m.client({ kvVersion: 2 });
    expect(c.namespace).toBeUndefined();
    const team = c.withNamespace("team-a");
    expect(team).toBeInstanceOf(VaultClient);
    expect(team).not.toBe(c);
    expect(team.namespace).toBe("team-a");
    expect(team.config.namespace).toBe("team-a");
    expect(team.config.url).toBe(c.config.url);
    expect(team.config.kvVersion).toBe(2);
    expect(team.config.retry).toBe(c.config.retry);
    const full = new VaultClient({
      url: c.config.url,
      proxy: "http://proxy:3128",
      userAgentSuffix: "ua",
      hooks: {},
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    }).withNamespace("x");
    expect(full.config).toMatchObject({ proxy: "http://proxy:3128", userAgentSuffix: "ua" });
    expect(full.config.hooks).toBeDefined();
    expect(full.config.logger).toBeDefined();
    expect(full.config.token).toBeUndefined();
    // OSS answers from the root namespace (recorded with the header set).
    expect((await team.kv().read("app/RUN/login")).data).toEqual({ value: "login-ok" });
    expect(m.req().headers["x-vault-namespace"]).toBe("team-a");
    expect(m.req().headers["x-vault-token"]).toBe("root-token-test");
    expect((await team.health()).healthy).toBe(true);
    expect(m.req().headers["x-vault-namespace"]).toBe("team-a");
    await team.ping();
    expect(m.req().headers["x-vault-namespace"]).toBe("team-a");
    await c.kv().read("app/RUN/login");
    expect(m.req().headers["x-vault-namespace"]).toBeUndefined();
    expect(c.namespace).toBeUndefined();
  });

  it("nested views replace the namespace; an empty name selects the root namespace", async () => {
    const m = await vault({ "GET /v1/sys/health": "health" });
    const c = m.client({ namespace: "base" });
    await c.sys.health();
    expect(m.req().headers["x-vault-namespace"]).toBe("base");
    const child = c.withNamespace(" /team-a/child/ ");
    expect(child.namespace).toBe("team-a/child");
    await child.sys.health();
    expect(m.req().headers["x-vault-namespace"]).toBe("team-a/child");
    const root = child.withNamespace("");
    expect(root.namespace).toBeUndefined();
    await root.sys.health();
    expect(m.req().headers["x-vault-namespace"]).toBeUndefined();
  });

  it("the view starts with the parent's token, then owns its token", async () => {
    const m = await vault({
      "GET /v1/auth/token/lookup-self": "token.lookup_self",
      "GET /v1/secret/data/app/RUN/login": {
        status: 403,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ errors: ["permission denied"] }),
      },
    });
    const c = m.client();
    const view = c.withNamespace("ns1");
    expect(view.token?.reveal()).toBe("root-token-test");
    view.setToken("s.from-view");
    expect(c.token?.reveal()).toBe("root-token-test");
    c.setToken("s.from-parent");
    expect(view.token?.reveal()).toBe("s.from-view");
    await view.ping();
    expect(m.req().headers["x-vault-token"]).toBe("s.from-view");
    expect(m.req().headers["x-vault-namespace"]).toBe("ns1");
    await c.ping();
    expect(m.req().headers["x-vault-token"]).toBe("s.from-parent");
    expect(m.req().headers["x-vault-namespace"]).toBeUndefined();
    // The view's own token is redacted in errors as well.
    const err = await rejection(view.kvV2("secret").read("app/RUN/login"));
    expect(err.code).toBe("AUTHENTICATION");
    expect(String(err)).not.toContain("s.from-view");
  });

  it("rejects a namespace containing whitespace eagerly (CONFIG)", async () => {
    const m = await vault();
    const c = m.client();
    for (const ns of ["a b", "team\tb", "/a\nb/"]) {
      expect(() => c.withNamespace(ns)).toThrow(/must not contain whitespace/);
    }
    expect(() => m.client({ namespace: "a b" })).toThrow(/must not contain whitespace/);
  });

  it("closing a view keeps the parent usable; closing the parent closes its views", async () => {
    const m = await vault({ "GET /v1/sys/health": "health" });
    const c = m.client();
    const a = c.withNamespace("a");
    await a.close();
    await a.close();
    expect(a.closed).toBe(true);
    expect((await c.sys.health()).state).toBe("active");
    const b = c.withNamespace("b");
    await c.close();
    expect(b.closed).toBe(true);
    expect(c.closed).toBe(true);
    expect(() => c.withNamespace("c")).toThrow(/closed/);
    expect((await rejection(b.sys.health())).code).toBe("CANCELLED");
  });

  it("rejects a non-string namespace", async () => {
    const m = await vault();
    expect(() => m.client().withNamespace(42 as never)).toThrow(/must be a string/);
  });

  it("namespaces are an Enterprise feature: OSS answers sys/namespaces with 404", async () => {
    const m = await vault({ "LIST /v1/sys/namespaces": "namespace.list" });
    const err = await rejection(m.client().request("GET", "sys/namespaces", { list: true }));
    expect(err.code).toBe("NOT_FOUND");
    expect(err.message).toContain("enterprise-only feature");
  });
});

describe("capabilities", () => {
  it("capabilitiesSelf returns the capabilities per requested path", async () => {
    const m = await vault({
      "POST /v1/sys/capabilities-self": [
        "capabilities_self.plural",
        "capabilities_self.plural",
        "capabilities_self.single",
        "capabilities_self.root",
      ],
    });
    const sys = m.client().sys;
    const allowed = "secret/data/app/RUN/x";
    const denied = "secret/data/denied/RUN";
    expect(await sys.capabilitiesSelf([allowed, `/${denied}/`])).toEqual({
      [allowed]: ["create", "delete", "patch", "read", "update"],
      [denied]: ["deny"],
    });
    expect(m.body()).toEqual({ paths: [allowed, denied] });
    const caps = await sys.capabilitiesSelf([allowed, denied]);
    expect(caps.allows(allowed, Capability.Read)).toBe(true);
    expect(caps.allows(`/${allowed}/`, "patch")).toBe(true);
    expect(caps.allows(allowed, Capability.Sudo)).toBe(false);
    expect(caps.allows(denied, Capability.Read)).toBe(false);
    expect(caps.allows("not-requested", Capability.Read)).toBe(false);
    expect(Object.keys(caps)).toEqual([allowed, denied]);
    expect(m.req().headers["x-vault-token"]).toBe("root-token-test");
    expect(await sys.capabilitiesSelf("transit/encrypt/sdk-aes")).toEqual({
      "transit/encrypt/sdk-aes": ["update"],
    });
    expect(m.body()).toEqual({ paths: ["transit/encrypt/sdk-aes"] });
    const root = await sys.capabilitiesSelf(["sys/mounts"]);
    expect(root).toEqual({ "sys/mounts": ["root"] });
    expect(root.allows("sys/mounts", Capability.Delete)).toBe(true);
  });

  it("falls back to the top-level copy and to `capabilities` for one path", async () => {
    const m = await vault({
      "POST /v1/sys/capabilities-self": [
        data(null, { "a/b": ["read"] }),
        data({ capabilities: ["list"] }),
        data({ other: ["read"] }),
        { status: 204 },
      ],
    });
    const sys = m.client().sys;
    expect(await sys.capabilitiesSelf("a/b")).toEqual({ "a/b": ["read"] });
    expect(await sys.capabilitiesSelf("c")).toEqual({ c: ["list"] });
    expect(await sys.capabilitiesSelf(["x", "y"])).toEqual({ x: [], y: [] });
    expect((await rejection(sys.capabilitiesSelf("z"))).message).toContain("empty response body");
  });

  it("capabilities(token, paths) checks another token; needs sys/capabilities", async () => {
    const m = await vault({
      "POST /v1/sys/capabilities": ["capabilities.token", "capabilities.forbidden"],
    });
    const sys = m.client().sys;
    const caps = await sys.capabilities("s.app-token", ["secret/data/app/RUN/x", "sys/mounts"]);
    expect(caps).toEqual({
      "secret/data/app/RUN/x": ["create", "delete", "patch", "read", "update"],
      "sys/mounts": ["deny"],
    });
    expect(m.body()).toEqual({
      token: "s.app-token",
      paths: ["secret/data/app/RUN/x", "sys/mounts"],
    });
    const err = await rejection(sys.capabilities("s.app-token", "secret/data/app/x"));
    expect(err.code).toBe("PERMISSION_DENIED");
    expect(err.message).not.toContain("s.app-token");
  });

  it("validates input without a request", async () => {
    const m = await vault();
    const sys = m.client().sys;
    await expect(sys.capabilitiesSelf([])).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(sys.capabilitiesSelf([" "])).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(sys.capabilities("", ["a"])).rejects.toMatchObject({ code: "VALIDATION" });
    expect(m.requests).toHaveLength(0);
  });
});
