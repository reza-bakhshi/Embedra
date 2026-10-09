package io.github.rezabakhshi.embedra.ghidra.findings;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Synchronizes unified findings with Ghidra program bookmarks and tracks suppression annotations (AN-006).
 */
public final class GhidraFindingBookmarkSynchronizer {

    public static final String SUPPRESSED_TAG = "[SUPPRESSED";

    private GhidraFindingBookmarkSynchronizer() {
    }

    /**
     * Extracts existing Embedra findings from program bookmarks.
     *
     * @param program Ghidra program
     * @return list of unified findings discovered from bookmarks
     */
    public static List<UnifiedFinding> extractFindingsFromBookmarks(Program program) {
        Objects.requireNonNull(program, "program must not be null");

        List<UnifiedFinding> findings = new ArrayList<>();
        var bookmarkManager = program.getBookmarkManager();
        var iter = bookmarkManager.getBookmarksIterator(BookmarkType.INFO);

        int counter = 1;
        while (iter.hasNext()) {
            Bookmark b = iter.next();
            String cat = b.getCategory();
            if (cat == null) {
                continue;
            }

            FindingCategory category = null;
            String subcategory = "UNKNOWN";

            if (cat.startsWith("Embedra Findings: ")) {
                category = FindingCategory.CTF_ENTITY;
                subcategory = cat.substring("Embedra Findings: ".length()).trim();
            } else if (cat.startsWith("Embedra Crypto: ")) {
                category = FindingCategory.CRYPTOGRAPHY;
                subcategory = cat.substring("Embedra Crypto: ".length()).trim();
            } else if (cat.startsWith("Embedra Logging: ")) {
                category = FindingCategory.LOGGING_DIAGNOSTIC;
                subcategory = cat.substring("Embedra Logging: ".length()).trim();
            } else if (cat.startsWith("Embedra Lead: ")) {
                category = FindingCategory.SECURITY_LEAD;
                subcategory = cat.substring("Embedra Lead: ".length()).trim();
            } else if (cat.startsWith("Embedra Plugin: ")) {
                category = FindingCategory.CUSTOM_PLUGIN;
                subcategory = cat.substring("Embedra Plugin: ".length()).trim();
            }

            if (category == null) {
                continue;
            }

            String comment = b.getComment() != null ? b.getComment() : "";
            boolean isSuppressed = comment.contains(SUPPRESSED_TAG);
            String suppressionReason = null;
            if (isSuppressed) {
                int start = comment.indexOf(SUPPRESSED_TAG);
                int end = comment.indexOf(']', start);
                if (end > start) {
                    String sub = comment.substring(start + SUPPRESSED_TAG.length(), end).trim();
                    if (sub.startsWith(":")) {
                        suppressionReason = sub.substring(1).trim();
                    }
                }
            }

            FindingSeverity sev = inferSeverity(category, subcategory);
            FindingConfidence conf = inferConfidence(comment);

            String id = String.format("FND-%04d", counter++);
            String platform = program.getLanguage().getProcessor().toString();

            findings.add(new UnifiedFinding(
                    id,
                    category,
                    subcategory,
                    sev,
                    conf,
                    0.80,
                    platform,
                    b.getAddress().getOffset(),
                    4,
                    comment,
                    comment,
                    false,
                    isSuppressed,
                    suppressionReason,
                    Map.of("bookmarkCategory", cat)));
        }

        return Collections.unmodifiableList(findings);
    }

    /**
     * Synchronizes a finding's suppression state to its corresponding bookmark.
     */
    public static boolean setFindingSuppression(
            Program program,
            UnifiedFinding finding,
            boolean suppressed,
            String reason) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(finding, "finding must not be null");

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Update Finding Suppression")) {
            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(finding.address());
            if (addr == null) {
                return false;
            }

            var bmManager = program.getBookmarkManager();
            Bookmark[] bookmarks = bmManager.getBookmarks(addr, BookmarkType.INFO);

            for (Bookmark b : bookmarks) {
                String cat = b.getCategory();
                if (cat != null && cat.startsWith("Embedra ")) {
                    String comment = b.getComment() != null ? b.getComment() : "";
                    String newComment;

                    if (suppressed) {
                        if (!comment.contains(SUPPRESSED_TAG)) {
                            newComment = comment + " [SUPPRESSED"
                                    + (reason != null && !reason.isBlank() ? ": " + reason.trim() : "") + "]";
                            bmManager.setBookmark(addr, BookmarkType.INFO, cat, newComment);
                        }
                    } else {
                        if (comment.contains(SUPPRESSED_TAG)) {
                            newComment = comment.replaceAll("\\[SUPPRESSED(?:[^\\]]*)\\]", "").trim();
                            bmManager.setBookmark(addr, BookmarkType.INFO, cat, newComment);
                        }
                    }
                }
            }

            tx.commit();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static FindingSeverity inferSeverity(FindingCategory cat, String subcategory) {
        String sub = subcategory.toUpperCase(Locale.ROOT);
        if (sub.contains("PANIC") || sub.contains("CRITICAL") || sub.contains("KEY_MATERIAL")) {
            return FindingSeverity.CRITICAL;
        }
        if (sub.contains("ASSERT") || sub.contains("ERROR") || sub.contains("PASSWORD") || sub.contains("CIPHER")) {
            return FindingSeverity.HIGH;
        }
        if (sub.contains("WARNING") || sub.contains("DEBUG") || sub.contains("HASH")) {
            return FindingSeverity.MEDIUM;
        }
        return FindingSeverity.LOW;
    }

    private static FindingConfidence inferConfidence(String comment) {
        String upper = comment.toUpperCase(Locale.ROOT);
        if (upper.contains("CONFIRMED") || upper.contains("HIGH")) {
            return FindingConfidence.CONFIRMED;
        }
        if (upper.contains("LIKELY") || upper.contains("MEDIUM")) {
            return FindingConfidence.LIKELY;
        }
        return FindingConfidence.PLAUSIBLE;
    }
}
