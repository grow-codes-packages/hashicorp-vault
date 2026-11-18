// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type HealthStatus,
  HttpTransport,
  type QueryValue,
  Secret,
  type TransportOptions,
  ValidationError,
  healthStatus,
  probeHealth,
} from "./core/index.js";
import { VaultConfig, type VaultConfigOptions } from "./config.js";
import { AuthApi } from "./auth.js";
import { Database } from "./database.js";
import {
  type ClientContext,
  type TokenHolder,
  VaultHttp,
  encodePath,
  parseTime,
  secondsToMs,
  strings,
  trimSlashes,
} from "./http.js";
import { KvMount, KvV1, KvV2 } from "./kv.js";
import { LeaseManager } from "./leases.js";
import { Pki } from "./pki.js";
import { VaultSecretsProvider, type VaultSecretsOptions } from "./provider.js";
import { Sys } from "./sys.js";
import { Transit } from "./transit.js";
import { Wrapping, type WrapInfo } from "./wrapping.js";

/** Shared state handed from a client to its {@link VaultClient.withNamespace} view. */
interface ViewState {
  tokens: TokenHolder;
  transport: HttpTransport;
}

/** Set by `withNamespace()` for the duration of the view's constructor call. */
let pendingView: ViewState | undefined;

/** Per-call options. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Test seams (undici `MockAgent`, fake sleep). Not part of the stable API. */
export type ClientInternals = Pick<TransportOptions, "dispatcher" | "sleep" | "now">;

/** Options of {@link VaultClient.request}. */
export interface RawRequestOptions extends CallOptions {
  /** Query parameters. */
  query?: Readonly<Record<string, QueryValue>>;
  /** JSON body. */
  json?: unknown;
  /** Extra headers. */
  headers?: Readonly<Record<string, string>>;
  /** Sends the LIST operation (`GET ...?list=true`). */
  list?: boolean;
  /** Wraps the response in a single-use token valid for this many ms. */
  wrapTtlMs?: number;
  /** Mark a POST as safe to retry. */
  idempotent?: boolean;
}

/** Result of {@link VaultClient.request}: the decoded Vault envelope. */
export interface RawResponse<T = Record<string, unknown>> {
  /** HTTP status (204 = no content). */
  status: number;
  /** The response data (`null` when the response had none). */
  data: T | null;
  /** Lease id (empty when the response has no lease). */
  leaseId: string;
  /** Lease TTL in ms. */
  leaseDurationMs: number;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** Server warnings. */
  warnings: string[];
  /** Set when the response was wrapped (`wrapTtlMs`). */
  wrapInfo?: WrapInfo;
}

/**
 * Client for HashiCorp Vault.
 *
 * ```ts
 * const client = VaultClient.fromEnv();          // VAULT_ADDR / VAULT_TOKEN / GROW_HASHICORP_VAULT_*
 * await client.kv().write("app/db", { password: "s3cret" });
 * const secret = await client.kv().read("app/db");
 * await client.close();
 * ```
 */
export class VaultClient {
  /** The immutable configuration. */
  readonly config: VaultConfig;
  /** Logins, token self-service and token renewal. */
  readonly auth: AuthApi;
  /** System backend (health, seal status, policies, mounts, auth methods, AppRole admin). */
  readonly sys: Sys;
  /** Response wrapping. */
  readonly wrapping: Wrapping;
  /** Lease renew/revoke/lookup and automatic lease renewal. */
  readonly leases: LeaseManager;
  readonly #transport: HttpTransport;
  readonly #http: VaultHttp;
  readonly #ctx: ClientContext;
  readonly #kvMounts = new Map<string, KvMount>();
  readonly #providers = new Set<VaultSecretsProvider>();
  readonly #views = new Set<VaultClient>();
  readonly #tokens: TokenHolder;
  /** `true` for a {@link withNamespace} view (it does not own the transport). */
  readonly #isView: boolean;
  #closed = false;
  #onClose: (() => void) | undefined;

  /** Accepts a {@link VaultConfig} or plain options. */
  constructor(config: VaultConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = VaultConfig.from(config);
    this.config = cfg;
    const parent = pendingView;
    pendingView = undefined;
    if (parent === undefined) {
      let token = cfg.token;
      const tokens: TokenHolder = {
        get: () => token,
        set: (t) => {
          token = t;
        },
      };
      this.#tokens = tokens;
      this.#transport = new HttpTransport({
        ...internals,
        config: cfg,
        knownSecrets: () => [...cfg.knownSecrets(), tokens.get()],
      });
      this.#isView = false;
    } else {
      this.#tokens = parent.tokens;
      this.#transport = parent.transport;
      this.#isView = true;
    }
    this.#http = new VaultHttp(this.#transport, this.#tokens, cfg.namespace);
    this.#ctx = { http: this.#http, config: cfg, tokens: this.#tokens };
    this.auth = new AuthApi(this.#ctx);
    this.sys = new Sys(this.#ctx);
    this.wrapping = new Wrapping(this.#ctx);
    this.leases = new LeaseManager(this.#ctx);
  }

  /** Builds a client from `GROW_HASHICORP_VAULT_*` and `VAULT_*` environment variables. */
  static fromEnv(overrides: VaultConfigOptions = {}): VaultClient {
    return new VaultClient(VaultConfig.fromEnv(overrides));
  }

  /** The shared HTTP transport. @internal */
  get transport(): HttpTransport {
    return this.#transport;
  }

  /** Internal module context (HTTP layer, config, token holder). @internal */
  get context(): ClientContext {
    return this.#ctx;
  }

  /** The current client token (from the config, a login or {@link setToken}). */
  get token(): Secret | undefined {
    return this.#tokens.get();
  }

  /**
   * Replaces the client token (`undefined` removes it). A {@link withNamespace} view shares the
   * token with its parent client, so the change is visible in both.
   */
  setToken(token: string | Secret | undefined): void {
    this.#tokens.set(Secret.from(token));
  }

  /** The namespace sent as `X-Vault-Namespace`, or `undefined` for the root namespace. */
  get namespace(): string | undefined {
    return this.config.namespace;
  }

  /**
   * A client view that sends `X-Vault-Namespace: <namespace>` on every request (an empty string
   * selects the root namespace: no header). The view shares the connection pool and the token
   * with this client; this client is not changed. Closing the view stops only its own renewers,
   * leases and watchers; closing this client also closes its views.
   *
   * **Vault Enterprise only.** Vault OSS ignores the header and serves the root namespace, so a
   * wrong namespace is not detected there.
   *
   * ```ts
   * const team = client.withNamespace("team-a");
   * await team.kv().read("app/db"); // X-Vault-Namespace: team-a
   * ```
   */
  withNamespace(namespace: string): VaultClient {
    if (typeof namespace !== "string") {
      throw new ValidationError("withNamespace: namespace must be a string");
    }
    if (this.#closed) throw new ValidationError("withNamespace: the client is closed");
    const ns = trimSlashes(namespace.trim());
    pendingView = { tokens: this.#tokens, transport: this.#transport };
    let view: VaultClient;
    try {
      view = new VaultClient(this.config.withNamespace(ns === "" ? undefined : ns));
    } finally {
      pendingView = undefined;
    }
    this.#views.add(view);
    view.#onClose = () => this.#views.delete(view);
    return view;
  }

  /** Whether {@link close} was called. */
  get closed(): boolean {
    return this.#closed;
  }

  /**
   * KV mount with auto-detected version (default mount `config.kvMount`). The same instance is
   * returned for the same mount.
   */
  kv(mount: string = this.config.kvMount): KvMount {
    const key = trimSlashes(mount);
    let kv = this.#kvMounts.get(key);
    if (kv === undefined) {
      kv = new KvMount(this.#ctx, key, this.config.kvVersion);
      this.#kvMounts.set(key, kv);
    }
    return kv;
  }

  /** KV version 1 mount (no detection). */
  kvV1(mount: string = this.config.kvMount): KvV1 {
    return new KvV1(this.#ctx, mount);
  }

  /** KV version 2 mount (no detection). */
  kvV2(mount: string = this.config.kvMount): KvV2 {
    return new KvV2(this.#ctx, mount);
  }

  /** Transit engine (default mount `transit`). */
  transit(mount = "transit"): Transit {
    return new Transit(this.#ctx, mount);
  }

  /** Database engine (default mount `database`). */
  database(mount = "database"): Database {
    return new Database(this.#ctx, mount);
  }

  /** PKI engine (default mount `pki`). */
  pki(mount = "pki"): Pki {
    return new Pki(this.#ctx, mount);
  }

  /**
   * {@link SecretsProvider} over a KV mount (default `config.kvMount`). `client.close()` stops
   * its watchers.
   */
  secrets(options: VaultSecretsOptions = {}): VaultSecretsProvider {
    const provider: VaultSecretsProvider = new VaultSecretsProvider(
      this.kv(options.mount ?? this.config.kvMount),
      options,
      () => this.#providers.delete(provider),
    );
    this.#providers.add(provider);
    return provider;
  }

  /**
   * Calls any Vault API path (`/v1/<path>`) with the client token, namespace, retries and
   * error mapping. Use it for endpoints this SDK has no method for.
   */
  async request<T = Record<string, unknown>>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    options: RawRequestOptions = {},
  ): Promise<RawResponse<T>> {
    const res = await this.#http.call<T>({
      method,
      path: encodePath(path),
      operation: `${method} ${trimSlashes(path)}`,
      ...options,
    });
    const env = res.body ?? {};
    const out: RawResponse<T> = {
      status: res.status,
      data: env.data ?? null,
      leaseId: env.lease_id ?? "",
      leaseDurationMs: secondsToMs(env.lease_duration),
      renewable: env.renewable === true,
      warnings: strings(env.warnings),
    };
    const w = env.wrap_info;
    if (w !== undefined && w !== null) {
      const accessor = Secret.from(w.accessor);
      out.wrapInfo = {
        token: new Secret(w.token),
        ...(accessor === undefined ? {} : { accessor }),
        ttlMs: secondsToMs(w.ttl),
        creationTime: parseTime(w.creation_time),
        creationPath: w.creation_path ?? "",
      };
    }
    return out;
  }

  /**
   * Unauthenticated health: `GET /v1/sys/health` (answers 200 in every node state). `healthy`
   * is `true` only for an active, unsealed node; `status` is `active`, `standby`,
   * `perfstandby`, `sealed` or `uninitialized` (`unreachable`/`unhealthy` on errors). Never
   * throws except for `CANCELLED` and `CONFIG`.
   */
  health(options: CallOptions = {}): Promise<HealthStatus> {
    return probeHealth(async () => {
      const h = await this.sys.health(options);
      return healthStatus(
        h.state,
        {
          version: h.version,
          initialized: h.initialized,
          sealed: h.sealed,
          standby: h.standby,
          clusterName: h.clusterName === "" ? undefined : h.clusterName,
        },
        h.state === "active",
      );
    });
  }

  /**
   * Authenticated round trip (`GET /v1/auth/token/lookup-self`, allowed for every valid
   * token). Returns the latency in ms; a missing, invalid or revoked token raises
   * `AuthenticationError`.
   */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    await this.#http.send({
      method: "GET",
      path: "auth/token/lookup-self",
      operation: "ping",
      signal: options.signal,
      // lookup-self is allowed for every valid token: 400/401/403 mean bad credentials.
      login: true,
    });
    return performance.now() - start;
  }

  /** Server version from `sys/health` (e.g. `2.2.2`). */
  async serverVersion(options: CallOptions = {}): Promise<string> {
    return this.sys.version(options);
  }

  /**
   * Stops token renewers, managed leases and secret watchers, then releases connections.
   * Idempotent.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await Promise.all([...this.#views].map((v) => v.close()));
    this.auth.stopRenewers();
    await this.leases.stopAll();
    await Promise.all([...this.#providers].map((p) => p.close()));
    this.#onClose?.();
    if (!this.#isView) await this.#transport.close();
  }
}
