package io.github.rezabakhshi.embedra.ghidra.logging;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.logging.DiagnosticLogLevel;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.List;
import java.util.Objects;

/**
 * Transactional Ghidra applicator for logging, assert, and panic call-site annotations (AN-004, AN-006).
 */
public final class GhidraLoggingApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra Logging Analysis";

    public static final String BOOKMARK_PREFIX = "Embedra Logging: ";

    private GhidraLoggingApplicator() {
    }

    /**
     * Applies discovered logging and assert call sites to the Ghidra program.
     *
     * @param program Ghidra program
     * @param callSites list of recovered logging call sites
     * @param monitor task monitor
     * @return application report
     */
    public static GhidraLoggingApplicationReport apply(
            Program program,
            List<LoggingCallSite> callSites,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(callSites, "callSites must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        int panicCount = 0;
        int assertCount = 0;
        int errorCount = 0;
        int warningCount = 0;
        int infoCount = 0;
        int debugCount = 0;
        int bookmarksCreated = 0;
        int commentsCreated = 0;

        for (LoggingCallSite site : callSites) {
            switch (site.level()) {
                case PANIC -> panicCount++;
                case ASSERT -> assertCount++;
                case ERROR -> errorCount++;
                case WARNING -> warningCount++;
                case INFO -> infoCount++;
                case DEBUG -> debugCount++;
            }
        }

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Annotate Embedra Logging & Diagnostics")) {

            for (LoggingCallSite site : callSites) {
                monitor.checkCancelled();
                try {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(site.callInstructionAddress());
                    if (program.getMemory().contains(addr)) {
                        String bookmarkCategory = BOOKMARK_PREFIX + site.level().name();
                        String bookmarkText = site.summary();
                        program.getBookmarkManager().setBookmark(
                                addr, BookmarkType.INFO, bookmarkCategory, bookmarkText);
                        bookmarksCreated++;

                        String commentText = buildCommentText(site);
                        applyCommentNonDestructive(program, addr, CommentType.EOL, commentText);
                        commentsCreated++;
                    }
                } catch (Exception ignored) {
                    // Skip invalid or unmapped addresses safely
                }
            }

            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("Total Logging Call Sites", callSites.size());
            options.setInt("Panic Count", panicCount);
            options.setInt("Assert Count", assertCount);
            options.setInt("Error Count", errorCount);
            options.setInt("Warning Count", warningCount);
            options.setInt("Info Count", infoCount);
            options.setInt("Debug Count", debugCount);

            tx.commit();
        } catch (Exception e) {
            // Roll back on failure or cancellation
        }

        return new GhidraLoggingApplicationReport(
                callSites.size(),
                panicCount,
                assertCount,
                errorCount,
                warningCount,
                infoCount,
                debugCount,
                bookmarksCreated,
                commentsCreated);
    }

    private static String buildCommentText(LoggingCallSite site) {
        StringBuilder sb = new StringBuilder();
        sb.append("[Log: ").append(site.level().name()).append("] ");
        if (site.formatString() != null && !site.formatString().rawText().isBlank()) {
            sb.append("\"").append(site.formatString().rawText()).append("\"");
        } else if (site.expression() != null) {
            sb.append("assert(").append(site.expression()).append(")");
        } else if (site.message() != null) {
            sb.append(site.message());
        }

        if (site.fileName() != null) {
            sb.append(" (").append(site.fileName());
            if (site.lineNumber() != null) {
                sb.append(":").append(site.lineNumber());
            }
            sb.append(")");
        }
        return sb.toString();
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
}
