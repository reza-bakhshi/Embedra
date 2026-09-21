package io.github.rezabakhshi.embedra.core;

import java.time.Duration;
import java.util.Objects;

/** Central immutable parser resource limits. */
public record ParserLimits(
        long maxInputBytes,
        long maxAllocationBytes,
        long maxExtractedBytes,
        long maxObjects,
        int maxNestingDepth,
        Duration maxWallTime) {
    private static final long MEBIBYTE = 1024L * 1024L;

    public ParserLimits {
        if (maxInputBytes <= 0 || maxAllocationBytes <= 0 || maxExtractedBytes <= 0
            || maxObjects <= 0 || maxNestingDepth <= 0) {
            throw new IllegalArgumentException("Parser limits must be positive");
        }
        Objects.requireNonNull(maxWallTime, "maxWallTime");
        if (maxWallTime.isZero() || maxWallTime.isNegative()) {
            throw new IllegalArgumentException("Maximum wall time must be positive");
        }
    }

    public static ParserLimits defaults() {
        return new ParserLimits(256 * MEBIBYTE, 16 * MEBIBYTE, 512 * MEBIBYTE,
            1_000_000, 32, Duration.ofSeconds(30));
    }

    public ParserLimits withMaxAllocationBytes(long value) {
        return new ParserLimits(maxInputBytes, value, maxExtractedBytes, maxObjects,
            maxNestingDepth, maxWallTime);
    }
}
