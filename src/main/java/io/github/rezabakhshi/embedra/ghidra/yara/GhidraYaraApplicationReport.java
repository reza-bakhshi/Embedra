package io.github.rezabakhshi.embedra.ghidra.yara;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Summary report of YARA rule matches applied to a Ghidra program.
 */
public record GhidraYaraApplicationReport(
        int totalMatches,
        int bookmarksCreated,
        int commentsCreated,
        Map<String, Integer> ruleCounts) {

    public GhidraYaraApplicationReport {
        if (totalMatches < 0 || bookmarksCreated < 0 || commentsCreated < 0) {
            throw new IllegalArgumentException("Counts must be non-negative");
        }
        Objects.requireNonNull(ruleCounts, "ruleCounts must not be null");
        ruleCounts = Collections.unmodifiableMap(Map.copyOf(ruleCounts));
    }
}
