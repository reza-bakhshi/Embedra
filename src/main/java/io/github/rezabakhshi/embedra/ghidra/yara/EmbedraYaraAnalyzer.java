package io.github.rezabakhshi.embedra.ghidra.yara;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.yara.CompiledYaraRuleset;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraMatch;
import io.github.rezabakhshi.embedra.analyzers.yara.YaraScanner;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Automated Ghidra analyzer for YARA pattern scanning across memory blocks (AN-009).
 */
public final class EmbedraYaraAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra YARA Pattern Analysis";

    public static final String DESCRIPTION = "Scans memory blocks for file formats, container headers, "
            + "cryptographic signatures, and user-defined YARA rules";

    private static final String OPT_CUSTOM_RULES_DIR = "Custom Rules Directory";

    private static final String OPT_ENABLE_CRYPTO = "Enable Built-in Crypto Rules";

    private static final String OPT_ENABLE_FORMATS = "Enable Built-in Format Rules";

    private static final String OPT_ENABLE_THREATS = "Enable Built-in Threat & Malware Rules";

    public EmbedraYaraAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.DATA_ANALYSIS);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getMemory() != null;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_CUSTOM_RULES_DIR, "", null,
                "Path to directory containing custom .yar/.yara rule files.");
        options.registerOption(OPT_ENABLE_CRYPTO, true, null,
                "Enable built-in cryptographic signatures (AES, SHA, CRC, etc.).");
        options.registerOption(OPT_ENABLE_FORMATS, true, null,
                "Enable built-in file format and container signatures (SquashFS, ELF, ZIP, etc.).");
        options.registerOption(OPT_ENABLE_THREATS, true, null,
                "Enable built-in threat, malware, and backdoor signatures (Mirai, Gafgyt, shellcode, etc.).");
    }

    @Override
    public boolean added(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        monitor.checkCancelled();

        Options options = program.getOptions(GhidraYaraApplicator.PROGRAM_OPTIONS_CATEGORY);
        boolean enableCrypto = options.getBoolean(OPT_ENABLE_CRYPTO, true);
        boolean enableFormats = options.getBoolean(OPT_ENABLE_FORMATS, true);
        boolean enableThreats = options.getBoolean(OPT_ENABLE_THREATS, true);
        String customDir = options.getString(OPT_CUSTOM_RULES_DIR, "");

        CompiledYaraRuleset.Builder builder = CompiledYaraRuleset.builder();
        if (enableCrypto) {
            try {
                builder.addResource("/rules/crypto/ciphers.yar");
                builder.addResource("/rules/crypto/hashes.yar");
            } catch (Exception e) {
                log.appendMsg(NAME, "Failed to load built-in crypto YARA rules: " + e.getMessage());
            }
        }
        if (enableFormats) {
            try {
                builder.addResource("/rules/formats/containers.yar");
                builder.addResource("/rules/formats/encodings.yar");
            } catch (Exception e) {
                log.appendMsg(NAME, "Failed to load built-in format YARA rules: " + e.getMessage());
            }
        }
        if (enableThreats) {
            try {
                builder.addResource("/rules/threats/malware.yar");
                builder.addResource("/rules/threats/backdoors.yar");
            } catch (Exception e) {
                log.appendMsg(NAME, "Failed to load built-in threat YARA rules: " + e.getMessage());
            }
        }
        if (customDir != null && !customDir.isBlank()) {
            try {
                builder.addDirectory(Path.of(customDir));
            } catch (Exception e) {
                log.appendMsg(NAME, "Failed to load custom YARA rules from " + customDir + ": " + e.getMessage());
            }
        }

        CompiledYaraRuleset ruleset = builder.build();
        if (ruleset.ruleCount() == 0) {
            return true;
        }

        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = monitor::isCancelled;
        YaraScanner scanner = new YaraScanner(ruleset, limits);

        List<YaraMatch> allMatches = new ArrayList<>();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || block.getSize() <= 0) {
                continue;
            }

            if (set != null && !set.isEmpty() && !set.intersects(block.getStart(), block.getEnd())) {
                continue;
            }

            try {
                int size = (int) Math.min(block.getSize(), limits.maxInputBytes());
                byte[] bytes = new byte[size];
                block.getBytes(block.getStart(), bytes);

                List<YaraMatch> matches = scanner.scan(bytes, block.getStart().getOffset(), token);
                allMatches.addAll(matches);
            } catch (Exception e) {
                if (monitor.isCancelled()) {
                    throw new CancelledException();
                }
                log.appendMsg(NAME, "Warning: error scanning block " + block.getName() + ": " + e.getMessage());
            }
        }

        if (!allMatches.isEmpty()) {
            GhidraYaraApplicationReport report = GhidraYaraApplicator.apply(program, allMatches, monitor);
            log.appendMsg(NAME, String.format(
                    "Completed YARA analysis: %d matches found (%d bookmarks, %d comments)",
                    report.totalMatches(), report.bookmarksCreated(), report.commentsCreated()));
        }

        return true;
    }
}
