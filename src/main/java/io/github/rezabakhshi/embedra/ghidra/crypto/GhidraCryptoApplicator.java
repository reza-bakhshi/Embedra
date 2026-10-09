package io.github.rezabakhshi.embedra.ghidra.crypto;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Transactional Ghidra applicator for cryptographic analysis findings (AN-003, AN-006, AN-010).
 *
 * <p>Populates program options under {@code Embedra Crypto Analysis} and creates informative
 * bookmarks under {@code Embedra Crypto: <CATEGORY>} and non-destructive EOL comments without
 * modifying or destroying existing user symbols or bookmarks.</p>
 */
public final class GhidraCryptoApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra Crypto Analysis";

    public static final String BOOKMARK_CATEGORY_PREFIX = "Embedra Crypto: ";

    private GhidraCryptoApplicator() {
    }

    /**
     * Applies discovered cryptographic findings to the Ghidra program.
     */
    public static GhidraCryptoApplicationReport apply(
            Program program,
            List<CryptoFinding> findings,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(findings, "findings must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        Map<CryptoCategory, Integer> categoryCounts = new EnumMap<>(CryptoCategory.class);
        for (CryptoCategory cat : CryptoCategory.values()) {
            categoryCounts.put(cat, 0);
        }

        Map<CryptoConfidence, Integer> confidenceCounts = new EnumMap<>(CryptoConfidence.class);
        for (CryptoConfidence conf : CryptoConfidence.values()) {
            confidenceCounts.put(conf, 0);
        }

        for (CryptoFinding f : findings) {
            categoryCounts.put(f.category(), categoryCounts.get(f.category()) + 1);
            confidenceCounts.put(f.confidence(), confidenceCounts.get(f.confidence()) + 1);
        }

        int bookmarksCreated = 0;
        int commentsCreated = 0;

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Annotate Embedra Crypto Findings")) {

            for (CryptoFinding f : findings) {
                monitor.checkCancelled();
                try {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(f.address());
                    if (program.getMemory().contains(addr)) {
                        String bookmarkCategory = BOOKMARK_CATEGORY_PREFIX + f.category().name();
                        String label = f.attributes().containsKey("crypto.library.display")
                                ? f.attributes().get("crypto.library.display") + " " + f.algorithm().displayName()
                                : f.algorithm().displayName();
                        String bookmarkText = String.format("[%s (%s)] %s",
                                label, f.confidence().displayName(),
                                truncateForDisplay(f.maskedValue(), 60));

                        program.getBookmarkManager().setBookmark(
                                addr, BookmarkType.INFO, bookmarkCategory, bookmarkText);
                        bookmarksCreated++;

                        String commentText = String.format("[Crypto: %s (%s)] %s - %s",
                                label, f.confidence().displayName(),
                                f.maskedValue(), f.explanation());
                        applyCommentNonDestructive(program, addr, CommentType.EOL, commentText);
                        commentsCreated++;
                    }
                } catch (Exception ignored) {
                    // Skip invalid addresses safely
                }
            }

            // Populate Program Options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("Total Findings Count", findings.size());
            for (CryptoCategory cat : CryptoCategory.values()) {
                options.setInt("Findings (" + cat.name() + ")", categoryCounts.get(cat));
            }
            for (CryptoConfidence conf : CryptoConfidence.values()) {
                options.setInt("Findings (" + conf.name() + ")", confidenceCounts.get(conf));
            }

            tx.commit();
        } catch (Exception e) {
            // Roll back automatically on failure or cancellation
        }

        return new GhidraCryptoApplicationReport(
                findings.size(),
                bookmarksCreated,
                commentsCreated,
                categoryCounts,
                confidenceCounts
        );
    }

    private static void applyCommentNonDestructive(
            Program program,
            Address addr,
            CommentType commentType,
            String newComment) {
        String existing = program.getListing().getComment(commentType, addr);
        if (existing == null || existing.isBlank()) {
            program.getListing().setComment(addr, commentType, newComment);
        } else if (!existing.contains(newComment)) {
            program.getListing().setComment(addr, commentType, existing + " | " + newComment);
        }
    }

    private static String truncateForDisplay(String str, int maxLen) {
        if (str.length() <= maxLen) {
            return str;
        }
        return str.substring(0, maxLen - 3) + "...";
    }
}
