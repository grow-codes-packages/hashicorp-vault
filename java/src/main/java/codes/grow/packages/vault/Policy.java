package codes.grow.packages.vault;

/**
 * An ACL policy.
 *
 * @param name policy name
 * @param policy HCL text
 */
public record Policy(String name, String policy) {}
