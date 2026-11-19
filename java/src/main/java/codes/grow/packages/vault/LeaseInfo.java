package codes.grow.packages.vault;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Lease details ({@code PUT sys/leases/lookup}).
 *
 * @param id lease id
 * @param path secret path that created the lease ({@code ""} on Vault, which does not report it)
 * @param issueTime issue time
 * @param expireTime expiry time
 * @param lastRenewal last renewal time
 * @param renewable whether it can be renewed
 * @param ttl remaining TTL
 */
public record LeaseInfo(
    String id,
    String path,
    Optional<Instant> issueTime,
    Optional<Instant> expireTime,
    Optional<Instant> lastRenewal,
    boolean renewable,
    Duration ttl) {}
