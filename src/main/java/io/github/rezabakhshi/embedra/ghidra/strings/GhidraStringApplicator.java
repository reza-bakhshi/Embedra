package io.github.rezabakhshi.embedra.ghidra.strings;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.List;
import java.util.Objects;

/**
 * Transactional Ghidra applicator for multi-encoding and stack-recovered string annotations.
 *
 * <p>Populates program options under {@code Embedra String Analysis} and creates informative
 * bookmarks and comments without modifying or destroying existing user symbols or bookmarks.</p>
 */
public final class GhidraStringApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra String Analysis";

    public static final String BOOKMARK_CATEGORY_STATIC = "Embedra Strings";

    public static final String BOOKMARK_CATEGORY_STACK = "Embedra Stack Strings";

    private GhidraStringApplicator() {
    }

    /**
     * Applies discovered static strings and recovered stack strings to the Ghidra program.
     */
    public static GhidraStringApplicationReport apply(
            Program program,
            List<ExtractedString> staticStrings,
            List<RecoveredStackString> stackStrings,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(staticStrings, "staticStrings must not be null");
        Objects.requireNonNull(stackStrings, "stackStrings must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        int asciiCount = 0;
        int utf8Count = 0;
        int utf16LeCount = 0;
        int utf16BeCount = 0;
        int pascalCount = 0;
        int bookmarksCreated = 0;
        int commentsCreated = 0;

        for (ExtractedString str : staticStrings) {
            switch (str.encoding()) {
                case ASCII -> asciiCount++;
                case UTF_8 -> utf8Count++;
                case UTF_16LE -> utf16LeCount++;
                case UTF_16BE -> utf16BeCount++;
                case PASCAL_8, PASCAL_16 -> pascalCount++;
            }
        }

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Annotate Embedra Multi-Encoding & Stack Strings")) {

            // 1. Annotate static strings
            for (ExtractedString str : staticStrings) {
                monitor.checkCancelled();
                try {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(str.offset());
                    if (program.getMemory().contains(addr)) {
                        String bookmarkText = String.format("[%s (%s)] %s",
                                str.encoding(), str.confidence(), truncateForDisplay(str.content(), 60));
                        program.getBookmarkManager().setBookmark(
                                addr, BookmarkType.INFO, BOOKMARK_CATEGORY_STATIC, bookmarkText);
                        bookmarksCreated++;

                        String commentText = String.format("[String: %s] %s", str.encoding(), str.content());
                        applyCommentNonDestructive(program, addr, CommentType.EOL, commentText);
                        commentsCreated++;
                    }
                } catch (Exception ignored) {
                    // Skip invalid or unmapped addresses safely
                }
            }

            // 2. Annotate recovered stack strings
            for (RecoveredStackString stackStr : stackStrings) {
                monitor.checkCancelled();
                try {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(stackStr.startInstructionAddress());
                    if (program.getMemory().contains(addr)) {
                        String bookmarkText = String.format("[Stack %s (%s) @ SP+0x%X] %s",
                                stackStr.encoding(), stackStr.confidence(),
                                stackStr.stackOffset(), truncateForDisplay(stackStr.content(), 60));
                        program.getBookmarkManager().setBookmark(
                                addr, BookmarkType.INFO, BOOKMARK_CATEGORY_STACK, bookmarkText);
                        bookmarksCreated++;

                        String commentText = String.format("[Stack String: %s @ SP+0x%X] %s",
                                stackStr.encoding(), stackStr.stackOffset(), stackStr.content());
                        applyCommentNonDestructive(program, addr, CommentType.EOL, commentText);
                        commentsCreated++;
                    }
                } catch (Exception ignored) {
                    // Skip invalid or unmapped addresses safely
                }
            }

            // 3. Populate Program Options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("ASCII Strings Count", asciiCount);
            options.setInt("UTF-8 Strings Count", utf8Count);
            options.setInt("UTF-16LE Strings Count", utf16LeCount);
            options.setInt("UTF-16BE Strings Count", utf16BeCount);
            options.setInt("Pascal Strings Count", pascalCount);
            options.setInt("Total Static Strings Count", staticStrings.size());
            options.setInt("Recovered Stack Strings Count", stackStrings.size());
            options.setInt("Total Strings Count", staticStrings.size() + stackStrings.size());

            tx.commit();
        } catch (Exception e) {
            // Roll back on cancellation or failure
        }

        return new GhidraStringApplicationReport(
                staticStrings.size(),
                stackStrings.size(),
                asciiCount,
                utf8Count,
                utf16LeCount,
                utf16BeCount,
                pascalCount,
                bookmarksCreated,
                commentsCreated);
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
