package io.github.rezabakhshi.embedra.ghidra.yara;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraMatch;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Transactional Ghidra applicator for YARA pattern matching findings.
 */
public final class GhidraYaraApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra YARA Analysis";

    public static final String BOOKMARK_CATEGORY_PREFIX = "Embedra YARA: ";

    private GhidraYaraApplicator() {
    }

    /**
     * Applies discovered YARA rule matches to the Ghidra program.
     */
    public static GhidraYaraApplicationReport apply(
            Program program,
            List<YaraMatch> matches,
            TaskMonitor monitor) throws CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(matches, "matches must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        Map<String, Integer> ruleCounts = new LinkedHashMap<>();
        for (YaraMatch m : matches) {
            ruleCounts.put(m.ruleName(), ruleCounts.getOrDefault(m.ruleName(), 0) + 1);
        }

        int bookmarksCreated = 0;
        int commentsCreated = 0;

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Annotate Embedra YARA Matches")) {

            for (YaraMatch m : matches) {
                monitor.checkCancelled();
                try {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(m.address());
                    if (program.getMemory().contains(addr)) {
                        String bookmarkCategory = BOOKMARK_CATEGORY_PREFIX + m.ruleName();
                        String bookmarkText = String.format("[%s] %s", m.ruleName(), m.description());

                        program.getBookmarkManager().setBookmark(
                                addr, BookmarkType.INFO, bookmarkCategory, bookmarkText);
                        bookmarksCreated++;

                        String commentText = String.format("[YARA: %s] %s", m.ruleName(), m.description());
                        applyCommentNonDestructive(program, addr, CommentType.EOL, commentText);
                        commentsCreated++;
                    }
                } catch (Exception ignored) {
                    // Skip invalid addresses safely
                }
            }

            // Populate Program Options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("Total Matches Count", matches.size());
            for (Map.Entry<String, Integer> entry : ruleCounts.entrySet()) {
                options.setInt("Matches (" + entry.getKey() + ")", entry.getValue());
            }

            tx.commit();
        }

        return new GhidraYaraApplicationReport(
                matches.size(), bookmarksCreated, commentsCreated, ruleCounts);
    }

    private static void applyCommentNonDestructive(
            Program program, Address addr, CommentType type, String comment) {
        String existing = program.getListing().getComment(type, addr);
        if (existing == null || existing.isBlank()) {
            program.getListing().setComment(addr, type, comment);
        } else if (!existing.contains(comment)) {
            program.getListing().setComment(addr, type, existing + " | " + comment);
        }
    }
}
