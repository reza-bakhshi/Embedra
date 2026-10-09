package io.github.rezabakhshi.embedra.ghidra.plugins;

import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginFinding;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.List;
import java.util.Objects;

/**
 * Applies scanner plugin findings to Ghidra bookmarks and program options within a transaction (AN-006, AN-009).
 */
public final class GhidraPluginApplicator {

    public static final String PROGRAM_OPTIONS_CATEGORY = "Embedra Plugin Analysis";

    private GhidraPluginApplicator() {
    }

    /**
     * Application summary report.
     */
    public record Report(int totalFindings, int bookmarksCreated, boolean optionsUpdated) {
    }

    /**
     * Applies plugin findings to the program.
     */
    public static Report apply(
            Program program,
            List<ScannerPluginFinding> findings,
            TaskMonitor monitor) {
        Objects.requireNonNull(program, "program must not be null");
        findings = findings == null ? List.of() : findings;

        int bookmarksCreated = 0;

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Apply Embedra Scanner Plugin Findings")) {

            BookmarkManager bm = program.getBookmarkManager();
            var space = program.getAddressFactory().getDefaultAddressSpace();

            for (ScannerPluginFinding f : findings) {
                if (monitor != null && monitor.isCancelled()) {
                    break;
                }

                Address addr = space.getAddress(f.address());
                if (addr != null) {
                    String category = "Embedra Plugin: " + f.pluginId();
                    String comment = f.explanation() + " [" + f.severity() + ", " + f.confidence() + "]";
                    bm.setBookmark(addr, BookmarkType.INFO, category, comment);
                    bookmarksCreated++;
                }
            }

            Options opts = program.getOptions(PROGRAM_OPTIONS_CATEGORY);
            opts.setLong("Last Analysis Timestamp", System.currentTimeMillis());
            opts.setInt("Total Plugin Findings", findings.size());
            opts.setInt("Bookmarks Created", bookmarksCreated);

            tx.commit();
            return new Report(findings.size(), bookmarksCreated, true);
        } catch (Exception e) {
            return new Report(findings.size(), bookmarksCreated, false);
        }
    }
}
