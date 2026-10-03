package io.github.rezabakhshi.embedra.ghidra.ctf;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityCategory;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfSeverity;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable report detailing CTF findings applied to a Ghidra program.
 *
 * @param totalFindings total number of findings applied
 * @param bookmarksCreated number of bookmarks created in the program
 * @param commentsCreated number of comments created in the program
 * @param countByCategory map of findings count per entity category
 * @param countBySeverity map of findings count per severity level
 */
public record GhidraCtfApplicationReport(
        int totalFindings,
        int bookmarksCreated,
        int commentsCreated,
        Map<CtfEntityCategory, Integer> countByCategory,
        Map<CtfSeverity, Integer> countBySeverity) {

    public GhidraCtfApplicationReport {
        Objects.requireNonNull(countByCategory, "countByCategory must not be null");
        Objects.requireNonNull(countBySeverity, "countBySeverity must not be null");
        countByCategory = Map.copyOf(countByCategory);
        countBySeverity = Map.copyOf(countBySeverity);
    }
}
