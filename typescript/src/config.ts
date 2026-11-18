// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type CommonConfig,
  type CommonConfigOptions,
  type CommonVendorEnv,
  ConfigError,
  type EnvMap,
  EnvReader,
  type Hooks,
  type ClientLogger,
  REDACTED,
  type RetryPolicy,
  Secret,
  type TlsOptions,
  describeCommonConfig,
  mergeOptions,
  readCommonEnv,
  resolveCommonConfig,
  secretValues,
  validateCommonConfig,
} from "./core/index.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Port text from the stack catalog; the default URL uses its first number. */
const CATALOG_PORT = "8200";

/** KV secrets engine version: `1` (unversioned) or `2` (versioned). */
export type KvVersion = 1 | 2;

/** Options accepted by {@link VaultConfig} (all optional). */
export interface VaultConfigOptions extends CommonConfigOptions {
  /**
   * Client token sent as `X-Vault-Token` (env `GROW_HASHICORP_VAULT_TOKEN`, `VAULT_TOKEN`).
   * Leave it unset when the client logs in with an auth method (`client.auth.login(...)`).
   */
  token?: string | Secret;
  /**
   * Namespace sent as `X-Vault-Namespace` (env `GROW_HASHICORP_VAULT_NAMESPACE`, `VAULT_NAMESPACE`).
   * Namespaces are a Vault Enterprise feature: Vault OSS ignores the header and serves the root
   * namespace, so a wrong value is not detected there.
   */
  namespace?: string;
  /** Default KV mount used by `client.kv()` and `client.secrets()` (default `"secret"`). */
  kvMount?: string;
  /**
   * KV version of every mount, skipping auto-detection (`sys/internal/ui/mounts`). Set it for
   * tokens that cannot read the mount preflight endpoint. Default: auto-detect per mount.
   */
  kvVersion?: KvVersion;
}

/** Vendor environment variables (the Vault CLI names) read after `GROW_HASHICORP_VAULT_*`. */
export const VENDOR_ENV: CommonVendorEnv & {
  /** Vendor variables for the token. */
  token: readonly string[];
  /** Namespace sent as `X-Vault-Namespace`. */
  namespace: readonly string[];
} = {
  /** Endpoint base URL. */
  url: ["VAULT_ADDR"],
  token: ["VAULT_TOKEN"],
  /** Namespace sent as `X-Vault-Namespace`. */
  namespace: ["VAULT_NAMESPACE"],
  caCert: ["VAULT_CACERT"],
  clientCert: ["VAULT_CLIENT_CERT"],
  clientKey: ["VAULT_CLIENT_KEY"],
  insecureSkipVerify: ["VAULT_SKIP_VERIFY"],
};

/** Immutable configuration of {@link VaultClient}. */
export class VaultConfig implements CommonConfig {
  /** Default endpoint (`http://127.0.0.1:8200`). */
  static readonly DEFAULT_URL = `http://127.0.0.1:${/\d+/.exec(CATALOG_PORT)?.[0] ?? "8080"}`;
  /** Prefix of every environment variable. */
  static readonly ENV_PREFIX = "GROW_HASHICORP_VAULT_";
  /** Default KV mount. */
  static readonly DEFAULT_KV_MOUNT = "secret";

  /** Endpoint base URL. */
  readonly url: string;
  /** Connection setup timeout in ms. */
  readonly connectTimeoutMs: number;
  /** Per-attempt timeout in ms. */
  readonly requestTimeoutMs: number;
  /** Whole-call timeout in ms, including retries. */
  readonly totalTimeoutMs: number;
  /** Retry policy. */
  readonly retry: RetryPolicy;
  /** TLS settings. */
  readonly tls: Readonly<TlsOptions>;
  /** Proxy URL (environment proxies are ignored). */
  readonly proxy?: string;
  /** Extra request headers (values redacted in debug output). */
  readonly headers: Readonly<Record<string, string>>;
  /** Appended after the standard User-Agent. */
  readonly userAgentSuffix?: string;
  /** Request/response hooks. */
  readonly hooks?: Hooks;
  /** Diagnostic logger (silent by default). */
  readonly logger?: ClientLogger;
  /** Client token (redacted in every string form). */
  readonly token?: Secret;
  /** Namespace (`X-Vault-Namespace`). */
  readonly namespace?: string;
  /** Default KV mount. */
  readonly kvMount: string;
  /** Fixed KV version, or `undefined` for auto-detection. */
  readonly kvVersion?: KvVersion;

  /** Applies defaults, validates (throws {@link ConfigError}) and freezes. */
  constructor(options: VaultConfigOptions = {}) {
    const common = resolveCommonConfig(options, VaultConfig.DEFAULT_URL);
    this.url = common.url;
    this.connectTimeoutMs = common.connectTimeoutMs;
    this.requestTimeoutMs = common.requestTimeoutMs;
    this.totalTimeoutMs = common.totalTimeoutMs;
    this.retry = common.retry;
    this.tls = common.tls;
    this.headers = common.headers;
    if (common.proxy !== undefined) this.proxy = common.proxy;
    if (common.userAgentSuffix !== undefined) this.userAgentSuffix = common.userAgentSuffix;
    if (common.hooks !== undefined) this.hooks = common.hooks;
    if (common.logger !== undefined) this.logger = common.logger;
    const token = Secret.from(options.token);
    if (token !== undefined) this.token = token;
    if (options.namespace !== undefined && options.namespace !== "") {
      this.namespace = options.namespace;
    }
    this.kvMount = options.kvMount ?? VaultConfig.DEFAULT_KV_MOUNT;
    if (options.kvVersion !== undefined) this.kvVersion = options.kvVersion;
    this.validate();
    Object.freeze(this);
  }

  /** Returns `options` when it already is a config, otherwise builds one. */
  static from(options: VaultConfigOptions = {}): VaultConfig {
    if (options instanceof VaultConfig) return options;
    return new VaultConfig(options);
  }

  /**
   * Builds a config from the environment. Precedence: explicit `overrides` >
   * `GROW_HASHICORP_VAULT_<NAME>` > vendor variables ({@link VENDOR_ENV}: `VAULT_*`) > defaults. Reads `URL`, `TOKEN`, `NAMESPACE`, `CA_CERT`, `CLIENT_CERT`, `CLIENT_KEY`,
   * `INSECURE_SKIP_VERIFY`, `PROXY`, the timeouts and `MAX_RETRIES`.
   */
  static fromEnv(overrides: VaultConfigOptions = {}, env: EnvMap = process.env): VaultConfig {
    const reader = new EnvReader(VaultConfig.ENV_PREFIX, env);
    const fromEnv: VaultConfigOptions = readCommonEnv(reader, VENDOR_ENV);
    const token = reader.secret("TOKEN", VENDOR_ENV.token);
    if (token !== undefined) fromEnv.token = token;
    const namespace = reader.string("NAMESPACE", VENDOR_ENV.namespace);
    if (namespace !== undefined) fromEnv.namespace = namespace;
    const merged = mergeOptions<VaultConfigOptions>(fromEnv, overrides);
    return new VaultConfig(merged);
  }

  /** A copy of this config with another namespace (`undefined` = root namespace). @internal */
  withNamespace(namespace: string | undefined): VaultConfig {
    const options: VaultConfigOptions = {
      url: this.url,
      connectTimeoutMs: this.connectTimeoutMs,
      requestTimeoutMs: this.requestTimeoutMs,
      totalTimeoutMs: this.totalTimeoutMs,
      retry: this.retry,
      tls: this.tls,
      headers: this.headers,
      kvMount: this.kvMount,
    };
    if (this.proxy !== undefined) options.proxy = this.proxy;
    if (this.userAgentSuffix !== undefined) options.userAgentSuffix = this.userAgentSuffix;
    if (this.hooks !== undefined) options.hooks = this.hooks;
    if (this.logger !== undefined) options.logger = this.logger;
    if (this.token !== undefined) options.token = this.token;
    if (this.kvVersion !== undefined) options.kvVersion = this.kvVersion;
    if (namespace !== undefined) options.namespace = namespace;
    return new VaultConfig(options);
  }

  /** Throws {@link ConfigError} when a setting is invalid. */
  validate(): void {
    validateCommonConfig(this);
    if (this.token?.reveal().trim() === "")
      throw new ConfigError("invalid configuration: token must not be blank");
    if (this.kvMount.replace(/^\/+|\/+$/g, "") === "")
      throw new ConfigError("invalid configuration: kvMount must not be empty");
    const kvVersion: unknown = this.kvVersion;
    if (kvVersion !== undefined && kvVersion !== 1 && kvVersion !== 2)
      throw new ConfigError("invalid configuration: kvVersion must be 1 or 2");
  }

  /** Credential values to redact from error messages and logs. */
  knownSecrets(): string[] {
    return secretValues(this.token);
  }

  /** Debug form with every credential redacted. */
  toJSON(): Record<string, unknown> {
    return {
      ...describeCommonConfig(this),
      token: this.token === undefined ? null : REDACTED,
      namespace: this.namespace ?? null,
      kvMount: this.kvMount,
      kvVersion: this.kvVersion ?? null,
    };
  }

  toString(): string {
    return `VaultConfig(${JSON.stringify(this.toJSON())})`;
  }

  /** `util.inspect` form (credentials redacted). */
  [INSPECT](): string {
    return this.toString();
  }
}
