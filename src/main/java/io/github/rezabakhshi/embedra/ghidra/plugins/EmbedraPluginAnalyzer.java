package io.github.rezabakhshi.embedra.ghidra.plugins;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginResourceBudget;
import io.github.rezabakhshi.embedra.analyzers.plugins.PluginScanContext;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginBatchReport;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginExecutionResult;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginFinding;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginRegistry;
import io.github.rezabakhshi.embedra.analyzers.plugins.ScannerPluginRunner;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Automated Ghidra analyzer running bounded local scanner plugins across program memory (AN-009).
 */
public final class EmbedraPluginAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Local Scanner Plugins";

    public static final String DESCRIPTION = "Executes registered local scanner plugins under strict "
            + "resource boundaries (AN-009)";

    public static final String OPT_PLUGIN_DIR = "Plugin Directory";

    public static final String OPT_MAX_TIMEOUT_MS = "Max Timeout (ms)";

    public static final String OPT_MAX_FINDINGS = "Max Findings Per Plugin";

    private final ScannerPluginRegistry registry;

    public EmbedraPluginAnalyzer() {
        this(new ScannerPluginRegistry());
    }

    public EmbedraPluginAnalyzer(ScannerPluginRegistry registry) {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        this.registry = registry;
        setPriority(AnalysisPriority.DATA_ANALYSIS.after().after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    public ScannerPluginRegistry registry() {
        return registry;
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getMemory() != null;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_PLUGIN_DIR, "", null,
                "Path to directory containing custom scanner plugin JSON manifests.");
        options.registerOption(OPT_MAX_TIMEOUT_MS, (int) PluginResourceBudget.DEFAULT_WALL_TIME_MS, null,
                "Maximum wall time in milliseconds per plugin execution.");
        options.registerOption(OPT_MAX_FINDINGS, PluginResourceBudget.DEFAULT_MAX_FINDINGS, null,
                "Maximum findings emitted per plugin before execution is capped.");
    }

    @Override
    public boolean added(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        monitor.checkCancelled();

        Options opts = program.getOptions(GhidraPluginApplicator.PROGRAM_OPTIONS_CATEGORY);
        String pluginDir = opts.getString(OPT_PLUGIN_DIR, "");
        int maxTimeoutMs = opts.getInt(OPT_MAX_TIMEOUT_MS, (int) PluginResourceBudget.DEFAULT_WALL_TIME_MS);
        int maxFindings = opts.getInt(OPT_MAX_FINDINGS, PluginResourceBudget.DEFAULT_MAX_FINDINGS);

        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = monitor::isCancelled;

        if (pluginDir != null && !pluginDir.isBlank()) {
            try {
                int discovered = registry.discoverPluginsInDirectory(Path.of(pluginDir), limits, token);
                if (discovered > 0) {
                    log.appendMsg(NAME, "Discovered " + discovered + " plugins in " + pluginDir);
                }
            } catch (Exception e) {
                log.appendMsg(NAME, "Failed to discover plugins in " + pluginDir + ": " + e.getMessage());
            }
        }

        if (registry.allPlugins().isEmpty()) {
            return true;
        }

        PluginResourceBudget budget = new PluginResourceBudget(
                Math.max(10, Math.min(60_000, maxTimeoutMs)),
                PluginResourceBudget.DEFAULT_MEMORY_BYTES,
                Math.max(1, Math.min(50_000, maxFindings))
        );

        PluginScanContext context;
        try {
            context = GhidraScannerPluginExtractor.extract(program, budget, limits, token);
        } catch (io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException e) {
            if (monitor.isCancelled()) {
                throw new CancelledException();
            }
            log.appendMsg(NAME, "Failed to extract program context: " + e.getMessage());
            return false;
        }

        try (ScannerPluginRunner runner = new ScannerPluginRunner()) {
            ScannerPluginBatchReport batchReport = registry.executeAll(context, runner);

            List<ScannerPluginFinding> allFindings = new ArrayList<>();
            for (ScannerPluginExecutionResult res : batchReport.results()) {
                allFindings.addAll(res.findings());
                if (!res.isSuccessful()) {
                    log.appendMsg(NAME, "Plugin '" + res.pluginId() + "' finished with status: "
                            + res.status() + " (" + res.diagnosticMessage() + ")");
                }
            }

            GhidraPluginApplicator.Report appReport = GhidraPluginApplicator.apply(program, allFindings, monitor);

            log.appendMsg(NAME, String.format(
                    "Embedra Scanner Plugins: executed %d plugins in %d ms, found %d findings (%d bookmarks created)",
                    batchReport.results().size(),
                    batchReport.totalDuration().toMillis(),
                    allFindings.size(),
                    appReport.bookmarksCreated()
            ));
        }

        return true;
    }
}
