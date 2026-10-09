package io.github.rezabakhshi.embedra.analyzers.leads.scanner;

import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Unified scanner orchestrating security lead discovery across comparisons, commands, shells, and OTA (AN-005).
 */
public final class SecurityLeadScanner {

    private final ComparisonLeadScanner comparisonScanner;

    private final DebugCommandLeadScanner debugCommandScanner;

    private final OtaLeadScanner otaScanner;

    public SecurityLeadScanner() {
        this(new ComparisonLeadScanner(), new DebugCommandLeadScanner(), new OtaLeadScanner());
    }

    public SecurityLeadScanner(
            ComparisonLeadScanner comparisonScanner,
            DebugCommandLeadScanner debugCommandScanner,
            OtaLeadScanner otaScanner) {
        this.comparisonScanner = Objects.requireNonNull(comparisonScanner, "comparisonScanner must not be null");
        this.debugCommandScanner = Objects.requireNonNull(debugCommandScanner, "debugCommandScanner must not be null");
        this.otaScanner = Objects.requireNonNull(otaScanner, "otaScanner must not be null");
    }

    /**
     * Executes unified lead scanning across all configured analyzers.
     *
     * @param functions map of function entry addresses to instruction sequences
     * @param stringTable map of memory addresses to string literals
     * @param symbolMap map of addresses to symbol names
     * @param commandTableEntries discovered command table entries (or empty list)
     * @param arch target instruction set architecture
     * @param limits parser resource bounds
     * @param token cooperative cancellation token
     * @return aggregated report of ranked security leads
     * @throws DiagnosticException if scanning is cancelled or fails
     */
    public SecurityLeadsReport scanAll(
            Map<Long, List<StackInstruction>> functions,
            Map<Long, String> stringTable,
            Map<Long, String> symbolMap,
            List<DebugCommandLeadScanner.CommandTableEntry> commandTableEntries,
            InstructionArch arch,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(stringTable, "stringTable must not be null");
        Objects.requireNonNull(symbolMap, "symbolMap must not be null");
        Objects.requireNonNull(limits, "limits must not be null");

        List<SecurityLead> allLeads = new ArrayList<>();

        // 1. Scan debug commands, command tables, and shells
        List<SecurityLead> commandLeads = debugCommandScanner.scan(
                stringTable, symbolMap, commandTableEntries, limits, token);
        allLeads.addAll(commandLeads);

        // 2. Scan OTA endpoints and handlers
        if (allLeads.size() < limits.maxObjects()) {
            List<SecurityLead> otaLeads = otaScanner.scan(stringTable, symbolMap, limits, token);
            for (SecurityLead l : otaLeads) {
                if (allLeads.size() >= limits.maxObjects()) {
                    break;
                }
                allLeads.add(l);
            }
        }

        // 3. Scan function disassemblies for candidate comparisons and authorization branches
        if (functions != null && arch != null) {
            for (Map.Entry<Long, List<StackInstruction>> fn : functions.entrySet()) {
                if (token != null && token.isCancellationRequested()) {
                    token.throwIfCancellationRequested();
                }
                if (allLeads.size() >= limits.maxObjects()) {
                    break;
                }

                List<SecurityLead> cmpLeads = comparisonScanner.scanFunction(
                        fn.getKey(), fn.getValue(), stringTable, symbolMap, arch, limits, token);
                for (SecurityLead l : cmpLeads) {
                    if (allLeads.size() >= limits.maxObjects()) {
                        break;
                    }
                    allLeads.add(l);
                }
            }
        }

        return new SecurityLeadsReport(allLeads);
    }
}
