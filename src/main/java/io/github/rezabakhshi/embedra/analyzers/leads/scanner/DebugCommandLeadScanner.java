package io.github.rezabakhshi.embedra.analyzers.leads.scanner;

import io.github.rezabakhshi.embedra.analyzers.leads.HeuristicFactor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Scans for candidate debug/hidden commands, command tables, and interactive debug shells (AN-005).
 */
public final class DebugCommandLeadScanner {

    private static final Set<String> HIGH_RISK_COMMANDS = Set.of(
            "root", "admin", "debug", "shell", "su", "factory", "diag", "backdoor",
            "dump", "memdump", "reboot", "erase", "format", "flash", "raw", "unlock",
            "peek", "poke", "telnet", "sh", "bash", "setenv", "printenv", "sysreset",
            "factory_reset", "testmode", "at+debug", "at+factory");

    private static final Set<String> KNOWN_SHELL_SYMBOLS = Set.of(
            "esp_console_init", "esp_console_cmd_register", "esp_console_run",
            "microrl_init", "embedded_cli_init", "freertos_cliinit",
            "cli_init", "shell_init", "uart_shell_init", "console_init",
            "cmd_tbl_init", "run_command");

    private static final Pattern SHELL_PROMPT_PATTERN = Pattern.compile(
            "^(?:[A-Za-z0-9_-]{1,16}(?:@(?:esp32|stm32|embedded|device))?)?[#$%>]\\s*$");

    public DebugCommandLeadScanner() {
    }

    /**
     * Scans string tables, symbols, and pointer tables for command and shell leads.
     */
    public List<SecurityLead> scan(
            Map<Long, String> stringTable,
            Map<Long, String> symbolMap,
            List<CommandTableEntry> commandTableEntries,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(stringTable, "stringTable must not be null");
        Objects.requireNonNull(symbolMap, "symbolMap must not be null");
        Objects.requireNonNull(limits, "limits must not be null");

        List<SecurityLead> leads = new ArrayList<>();
        int leadCounter = 1;

        // 1. Detect candidate debug shells via symbols and prompt strings
        boolean hasShellSymbol = false;
        long shellSymbolAddr = 0;
        String detectedShellSymbol = "";

        for (Map.Entry<Long, String> sym : symbolMap.entrySet()) {
            String lower = sym.getValue().toLowerCase(Locale.ROOT);
            for (String known : KNOWN_SHELL_SYMBOLS) {
                if (lower.contains(known)) {
                    hasShellSymbol = true;
                    shellSymbolAddr = sym.getKey();
                    detectedShellSymbol = sym.getValue();
                    break;
                }
            }
            if (hasShellSymbol) {
                break;
            }
        }

        for (Map.Entry<Long, String> entry : stringTable.entrySet()) {
            if (token != null && token.isCancellationRequested()) {
                token.throwIfCancellationRequested();
            }
            if (leads.size() >= limits.maxObjects()) {
                break;
            }

            long strAddr = entry.getKey();
            String strVal = entry.getValue();

            if (isShellPrompt(strVal)) {
                List<HeuristicFactor> factors = new ArrayList<>();
                double score = 0.40;
                factors.add(HeuristicFactor.of("SHELL_PROMPT_PATTERN",
                        "String matches interactive CLI/shell prompt pattern: \"" + strVal + "\"", 0.40));

                if (hasShellSymbol) {
                    factors.add(HeuristicFactor.of("SHELL_INIT_SYMBOL",
                            "Corroborating console/shell symbol found in binary: " + detectedShellSymbol, 0.45));
                    score += 0.45;
                }

                double normalizedScore = Math.min(1.0, score);
                LeadConfidence conf = LeadConfidence.fromScore(normalizedScore);
                LeadSeverity sev = hasShellSymbol ? LeadSeverity.HIGH : LeadSeverity.MEDIUM;

                String leadId = String.format("LEAD-SHL-%04d", leadCounter++);
                String desc = String.format("Candidate interactive debug shell prompt at 0x%X: \"%s\"%s",
                        strAddr, strVal, hasShellSymbol ? " (corroborated by " + detectedShellSymbol + ")" : "");

                Map<String, String> attrs = new HashMap<>();
                attrs.put("promptString", strVal);
                if (hasShellSymbol) {
                    attrs.put("corroboratingSymbol", detectedShellSymbol);
                    attrs.put("corroboratingSymbolAddress", "0x" + Long.toHexString(shellSymbolAddr));
                }

                leads.add(new SecurityLead(
                        leadId,
                        LeadCategory.DEBUG_SHELL,
                        conf,
                        normalizedScore,
                        sev,
                        strAddr,
                        detectedShellSymbol.isBlank() ? null : detectedShellSymbol,
                        strVal,
                        desc,
                        factors,
                        attrs,
                        false));
            }
        }

        // 2. Scan discovered command table structures
        if (commandTableEntries != null) {
            for (CommandTableEntry cte : commandTableEntries) {
                if (token != null && token.isCancellationRequested()) {
                    token.throwIfCancellationRequested();
                }
                if (leads.size() >= limits.maxObjects()) {
                    break;
                }

                String cmdLower = cte.commandName().toLowerCase(Locale.ROOT);
                boolean isHighRisk = HIGH_RISK_COMMANDS.contains(cmdLower);

                List<HeuristicFactor> factors = new ArrayList<>();
                factors.add(HeuristicFactor.of("COMMAND_TABLE_STRUCTURE",
                        "Entry discovered in CLI dispatch table (handler: 0x"
                                + Long.toHexString(cte.handlerAddress()) + ")", 0.45));
                double score = 0.45;

                if (isHighRisk) {
                    factors.add(HeuristicFactor.of("HIGH_RISK_COMMAND_KEYWORD",
                            "Command name \"" + cte.commandName() + "\" matches administrative/debug keyword", 0.45));
                    score += 0.45;
                } else if (cmdLower.contains("debug") || cmdLower.contains("test") || cmdLower.contains("cfg")) {
                    factors.add(HeuristicFactor.of("DEBUG_SUBSTRING_MATCH",
                            "Command name contains diagnostic substring", 0.25));
                    score += 0.25;
                }

                if (hasShellSymbol) {
                    factors.add(HeuristicFactor.of("SHELL_ENVIRONMENT_PRESENT",
                            "Console/shell environment present in binary", 0.15));
                    score += 0.15;
                }

                double normalizedScore = Math.min(1.0, score);
                LeadConfidence conf = LeadConfidence.fromScore(normalizedScore);
                LeadSeverity sev = isHighRisk ? LeadSeverity.HIGH : LeadSeverity.MEDIUM;

                String leadId = String.format("LEAD-CMD-%04d", leadCounter++);
                String desc = String.format("Candidate debug command \"%s\" registered in table at 0x%X (handler 0x%X)",
                        cte.commandName(), cte.tableEntryAddress(), cte.handlerAddress());

                Map<String, String> attrs = new HashMap<>();
                attrs.put("commandName", cte.commandName());
                attrs.put("tableAddress", "0x" + Long.toHexString(cte.tableEntryAddress()));
                attrs.put("handlerAddress", "0x" + Long.toHexString(cte.handlerAddress()));
                if (cte.helpText() != null && !cte.helpText().isBlank()) {
                    attrs.put("helpText", cte.helpText());
                }

                leads.add(new SecurityLead(
                        leadId,
                        LeadCategory.DEBUG_COMMAND,
                        conf,
                        normalizedScore,
                        sev,
                        cte.tableEntryAddress(),
                        null,
                        cte.commandName(),
                        desc,
                        factors,
                        attrs,
                        false));
            }
        }

        // 3. Scan standalone high-risk command strings
        for (Map.Entry<Long, String> entry : stringTable.entrySet()) {
            if (token != null && token.isCancellationRequested()) {
                token.throwIfCancellationRequested();
            }
            if (leads.size() >= limits.maxObjects()) {
                break;
            }

            long strAddr = entry.getKey();
            String strVal = entry.getValue().trim();
            String lower = strVal.toLowerCase(Locale.ROOT);

            if (HIGH_RISK_COMMANDS.contains(lower) && strVal.length() >= 3) {
                // Check if already covered by command table
                boolean alreadyCovered = commandTableEntries != null && commandTableEntries.stream()
                        .anyMatch(cte -> cte.commandName().equalsIgnoreCase(strVal));
                if (alreadyCovered) {
                    continue;
                }

                List<HeuristicFactor> factors = new ArrayList<>();
                factors.add(HeuristicFactor.of("HIGH_RISK_COMMAND_KEYWORD",
                        "Standalone string matches administrative or debug command keyword", 0.35));
                double score = 0.35;
                if (hasShellSymbol) {
                    factors.add(HeuristicFactor.of("SHELL_ENVIRONMENT_PRESENT",
                            "Console/shell environment present in binary", 0.25));
                    score += 0.25;
                }

                double normalizedScore = Math.min(1.0, score);
                LeadConfidence conf = LeadConfidence.fromScore(normalizedScore);
                String leadId = String.format("LEAD-CMD-%04d", leadCounter++);
                String desc = String.format("Candidate debug command keyword string at 0x%X: \"%s\"",
                        strAddr, strVal);

                Map<String, String> attrs = Map.of("commandKeyword", strVal);

                leads.add(new SecurityLead(
                        leadId,
                        LeadCategory.DEBUG_COMMAND,
                        conf,
                        normalizedScore,
                        LeadSeverity.MEDIUM,
                        strAddr,
                        null,
                        strVal,
                        desc,
                        factors,
                        attrs,
                        false));
            }
        }

        return List.copyOf(leads);
    }

    private static boolean isShellPrompt(String s) {
        if (s == null || s.isEmpty() || s.length() > 32) {
            return false;
        }
        String trimmed = s.trim();
        if (s.equals("# ") || s.equals("$ ") || s.equals("> ") || s.equals(">> ")
                || s.equalsIgnoreCase("shell> ") || s.equalsIgnoreCase("cli> ")
                || s.equalsIgnoreCase("debug> ") || s.equalsIgnoreCase("admin> ")
                || s.equalsIgnoreCase("esp> ") || s.equalsIgnoreCase("cmd> ")
                || trimmed.equals("#") || trimmed.equals("$") || trimmed.equals(">")
                || trimmed.equalsIgnoreCase("shell>") || trimmed.equalsIgnoreCase("cli>")
                || trimmed.equalsIgnoreCase("debug>") || trimmed.equalsIgnoreCase("admin>")
                || trimmed.equalsIgnoreCase("esp>") || trimmed.equalsIgnoreCase("cmd>")) {
            return true;
        }
        return SHELL_PROMPT_PATTERN.matcher(trimmed).matches();
    }

    /**
     * Discovered command table descriptor.
     */
    public record CommandTableEntry(
            long tableEntryAddress,
            String commandName,
            long handlerAddress,
            String helpText) {

        public CommandTableEntry {
            Objects.requireNonNull(commandName, "commandName must not be null");
        }
    }
}
