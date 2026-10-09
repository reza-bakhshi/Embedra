package io.github.rezabakhshi.embedra.ghidra.leads;

/**
 * Summary report of actions performed by {@link GhidraSecurityLeadApplicator} (AN-005, AN-006).
 */
public record GhidraSecurityLeadApplicationReport(
        int totalLeads,
        int bookmarksCreated,
        int commentsCreated,
        int passwordComparisons,
        int debugCommands,
        int debugShells,
        int otaEndpoints,
        int authorizationBranches,
        int highConfidenceLeads) {
}
