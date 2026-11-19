package codes.grow.packages.vault;

import codes.grow.packages.vault.core.Secret;

/**
 * Dynamic database credentials ({@code GET database/creds/<role>}).
 *
 * @param username generated user name
 * @param password generated password (redacted)
 */
public record DatabaseCredentials(String username, Secret password) {}
