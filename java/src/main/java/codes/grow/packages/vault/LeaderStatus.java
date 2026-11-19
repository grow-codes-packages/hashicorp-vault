package codes.grow.packages.vault;

import java.time.Instant;
import java.util.Optional;

/**
 * Leader status ({@code GET sys/leader}).
 *
 * @param haEnabled whether high availability is enabled
 * @param isSelf whether this node is the leader
 * @param activeTime when the leader became active
 * @param leaderAddress leader API address
 * @param leaderClusterAddress leader cluster address
 * @param performanceStandby whether this node is a performance standby (Vault Enterprise)
 * @param performanceStandbyLastRemoteWal last WAL index a performance standby has seen (0 on OSS)
 */
public record LeaderStatus(
    boolean haEnabled,
    boolean isSelf,
    Optional<Instant> activeTime,
    String leaderAddress,
    String leaderClusterAddress,
    boolean performanceStandby,
    long performanceStandbyLastRemoteWal) {}
