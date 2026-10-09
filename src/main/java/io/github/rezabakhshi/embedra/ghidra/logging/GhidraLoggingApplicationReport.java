package io.github.rezabakhshi.embedra.ghidra.logging;

/**
 * Report detailing annotations applied to a Ghidra program for logging, assert, and panic recovery (AN-004).
 *
 * @param totalCallSites total number of logging/assert call sites identified
 * @param panicCount count of panic call sites
 * @param assertCount count of assert call sites
 * @param errorCount count of error logging call sites
 * @param warningCount count of warning logging call sites
 * @param infoCount count of info logging call sites
 * @param debugCount count of debug logging call sites
 * @param bookmarksCreated number of bookmarks created
 * @param commentsCreated number of EOL comments created
 */
public record GhidraLoggingApplicationReport(
        int totalCallSites,
        int panicCount,
        int assertCount,
        int errorCount,
        int warningCount,
        int infoCount,
        int debugCount,
        int bookmarksCreated,
        int commentsCreated) {
}
