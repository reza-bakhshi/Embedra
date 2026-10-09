package io.github.rezabakhshi.embedra.analyzers.plugins;

/**
 * Resource limits allocated to a single scanner plugin execution (AN-009).
 *
 * @param maxWallTimeMs maximum execution time in milliseconds (10 to 60,000)
 * @param maxMemoryBytes maximum memory allocation threshold in bytes
 * @param maxFindings maximum number of findings before scan is capped
 */
public record PluginResourceBudget(
        long maxWallTimeMs,
        long maxMemoryBytes,
        int maxFindings) {

    public static final long DEFAULT_WALL_TIME_MS = 5_000L;

    public static final long DEFAULT_MEMORY_BYTES = 16L * 1024L * 1024L;

    public static final int DEFAULT_MAX_FINDINGS = 500;

    public PluginResourceBudget {
        if (maxWallTimeMs < 10 || maxWallTimeMs > 60_000) {
            throw new IllegalArgumentException(
                    "maxWallTimeMs must be between 10 and 60,000 ms: " + maxWallTimeMs);
        }
        if (maxMemoryBytes < 1024) {
            throw new IllegalArgumentException("maxMemoryBytes must be at least 1024: " + maxMemoryBytes);
        }
        if (maxFindings < 1 || maxFindings > 50_000) {
            throw new IllegalArgumentException("maxFindings must be between 1 and 50,000: " + maxFindings);
        }
    }

    public static PluginResourceBudget defaults() {
        return new PluginResourceBudget(DEFAULT_WALL_TIME_MS, DEFAULT_MEMORY_BYTES, DEFAULT_MAX_FINDINGS);
    }
}
