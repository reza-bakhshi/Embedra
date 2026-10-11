package io.github.rezabakhshi.embedra.ghidra.leads;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.List;
import java.util.Objects;

/**
 * Transactional applicator annotating Ghidra programs with candidate security leads (AN-005, AN-006).
 */
public final class GhidraSecurityLeadApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra Security Leads";

    public static final String BOOKMARK_PREFIX = "Embedra Lead: ";

    private GhidraSecurityLeadApplicator() {
    }

    /**
     * Applies discovered security leads to the Ghidra program transactionally.
     *
     * @param program Ghidra program
     * @param report security leads report
     * @param monitor task monitor
     * @return summary application report
     */
    public static GhidraSecurityLeadApplicationReport apply(
            Program program,
            SecurityLeadsReport report,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(report, "report must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        List<SecurityLead> leads = report.rankedLeads();
        int pwCmp = 0;
        int dbgCmd = 0;
        int dbgShl = 0;
        int otaEnd = 0;
        int authBr = 0;
        int highConf = 0;

        for (SecurityLead lead : leads) {
            switch (lead.category()) {
                case PASSWORD_TOKEN_COMPARISON -> pwCmp++;
                case DEBUG_COMMAND -> dbgCmd++;
                case DEBUG_SHELL -> dbgShl++;
                case OTA_ENDPOINT -> otaEnd++;
                case AUTHORIZATION_BRANCH -> authBr++;
            }
            if (lead.confidence() == LeadConfidence.HIGH) {
                highConf++;
            }
        }

        int bmkCount = 0;
        int cmtCount = 0;

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Embedra Security Leads Application")) {
            var bookmarkManager = program.getBookmarkManager();
            var listing = program.getListing();
            var addrFactory = program.getAddressFactory();

            for (SecurityLead lead : leads) {
                monitor.checkCancelled();

                Address addr = addrFactory.getDefaultAddressSpace().getAddress(lead.address());
                if (addr == null || !program.getMemory().contains(addr)) {
                    continue;
                }

                String bookmarkCategory = BOOKMARK_PREFIX + lead.category().displayName();
                String bookmarkComment = String.format("[%s | Score: %.2f] %s",
                        lead.confidence().displayName(), lead.confidenceScore(), lead.maskedTarget(true));

                // Idempotent bookmark check
                var existingBookmarks = bookmarkManager.getBookmarks(addr, BookmarkType.INFO);
                boolean bmkExists = false;
                for (var b : existingBookmarks) {
                    if (bookmarkCategory.equals(b.getCategory()) && bookmarkComment.equals(b.getComment())) {
                        bmkExists = true;
                        break;
                    }
                }

                if (!bmkExists) {
                    bookmarkManager.setBookmark(addr, BookmarkType.INFO, bookmarkCategory, bookmarkComment);
                    bmkCount++;
                }

                // Add non-destructive EOL comment
                String leadComment = String.format("[Lead: %s (%s)] %s",
                        lead.category().displayName(), lead.confidence().displayName(),
                        lead.description());

                String existingComment = listing.getComment(CommentType.EOL, addr);
                if (existingComment == null || existingComment.isBlank()) {
                    listing.setComment(addr, CommentType.EOL, leadComment);
                    cmtCount++;
                } else if (!existingComment.contains(lead.category().displayName())) {
                    listing.setComment(addr, CommentType.EOL, existingComment + " | " + leadComment);
                    cmtCount++;
                }
            }

            // Register structured program options
            var options = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            options.setInt("Total Security Leads", leads.size());
            options.setInt("High Confidence Leads", highConf);
            options.setInt("Password Comparisons", pwCmp);
            options.setInt("Debug Commands", dbgCmd);
            options.setInt("Debug Shells", dbgShl);
            options.setInt("OTA Endpoints", otaEnd);
            options.setInt("Authorization Branches", authBr);

            tx.commit();
        } catch (Exception e) {
            // Roll back on cancellation or failure
        }

        return new GhidraSecurityLeadApplicationReport(
                leads.size(),
                bmkCount,
                cmtCount,
                pwCmp,
                dbgCmd,
                dbgShl,
                otaEnd,
                authBr,
                highConf);
    }
}
