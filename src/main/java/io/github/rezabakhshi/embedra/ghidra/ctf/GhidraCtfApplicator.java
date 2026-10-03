package io.github.rezabakhshi.embedra.ghidra.ctf;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityCategory;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfSeverity;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Transactional Ghidra applicator for CTF findings and firmware artifacts (AN-002, AN-006).
 *
 * <p>Populates program options under {@code Embedra CTF Findings} and creates informative
 * bookmarks and comments without modifying or destroying existing user symbols or bookmarks.</p>
 */
public final class GhidraCtfApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra CTF Findings";

    public static final String BOOKMARK_CATEGORY_PREFIX = "Embedra Findings: ";

    private GhidraCtfApplicator() {
    }

    /**
     * Applies discovered CTF findings to the Ghidra program.
     */
    public static GhidraCtfApplicationReport apply(
            Program program,
            List<CtfEntity> entities,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(entities, "entities must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        Map<CtfEntityCategory, Integer> categoryCounts = new EnumMap<>(CtfEntityCategory.class);
        for (CtfEntityCategory cat : CtfEntityCategory.values()) {
            categoryCounts.put(cat, 0);
        }

        Map<CtfSeverity, Integer> severityCounts = new EnumMap<>(CtfSeverity.class);
        for (CtfSeverity sev : CtfSeverity.values()) {
            severityCounts.put(sev, 0);
        }

        int bookmarksCreated = 0;
        int commentsCreated = 0;

        for (CtfEntity entity : entities) {
            categoryCounts.put(entity.category(), categoryCounts.get(entity.category()) + 1);
            severityCounts.put(entity.severity(), severityCounts.get(entity.severity()) + 1);
        }

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Annotate Embedra CTF Findings")) {

            for (CtfEntity entity : entities) {
                monitor.checkCancelled();
                try {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entity.address());
                    if (program.getMemory().contains(addr)) {
                        String bookmarkCategory = BOOKMARK_CATEGORY_PREFIX + entity.category().name();
                        String bookmarkText = String.format("[%s (%s / %s)] %s",
                                entity.type().displayName(), entity.severity(), entity.confidence(),
                                truncateForDisplay(entity.maskedValue(), 60));
                        program.getBookmarkManager().setBookmark(
                                addr, BookmarkType.INFO, bookmarkCategory, bookmarkText);
                        bookmarksCreated++;

                        String commentText = String.format("[Finding: %s (%s)] %s - %s",
                                entity.type().displayName(), entity.severity(),
                                entity.maskedValue(), entity.explanation());
                        applyCommentNonDestructive(program, addr, CommentType.EOL, commentText);
                        commentsCreated++;
                    }
                } catch (Exception ignored) {
                    // Skip invalid addresses safely
                }
            }

            // Populate Program Options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("Total Findings Count", entities.size());
            for (CtfEntityCategory cat : CtfEntityCategory.values()) {
                options.setInt("Findings (" + cat.name() + ")", categoryCounts.get(cat));
            }
            for (CtfSeverity sev : CtfSeverity.values()) {
                options.setInt("Findings (" + sev.name() + ")", severityCounts.get(sev));
            }

            tx.commit();
        } catch (Exception e) {
            // Roll back on failure or cancellation
        }

        return new GhidraCtfApplicationReport(
                entities.size(),
                bookmarksCreated,
                commentsCreated,
                categoryCounts,
                severityCounts
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
