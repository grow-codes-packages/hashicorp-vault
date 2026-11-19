package codes.grow.packages.vault;

import codes.grow.packages.vault.core.Secret;
import java.util.concurrent.atomic.AtomicReference;

/** What a service module needs from the client: HTTP layer, config and the current token. */
final class ClientContext {
  final VaultHttp http;
  final VaultConfig config;
  final AtomicReference<Secret> token;

  ClientContext(VaultHttp http, VaultConfig config, AtomicReference<Secret> token) {
    this.http = http;
    this.config = config;
    this.token = token;
  }
}
