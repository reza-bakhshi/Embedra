package io.github.rezabakhshi.embedra.ghidra.crypto;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Summary report of cryptographic findings applied to a Ghidra program.
 */
public record GhidraCryptoApplicationReport(
        int totalFindings,
        int bookmarksCreated,
        int commentsCreated,
        Map<CryptoCategory, Integer> categoryCounts,
        Map<CryptoConfidence, Integer> confidenceCounts) {

    public GhidraCryptoApplicationReport {
        if (totalFindings < 0 || bookmarksCreated < 0 || commentsCreated < 0) {
            throw new IllegalArgumentException("Counts must be non-negative");
        }
        Objects.requireNonNull(categoryCounts, "categoryCounts must not be null");
        Objects.requireNonNull(confidenceCounts, "confidenceCounts must not be null");
        categoryCounts = Collections.unmodifiableMap(Map.copyOf(categoryCounts));
        confidenceCounts = Collections.unmodifiableMap(Map.copyOf(confidenceCounts));
    }
}
