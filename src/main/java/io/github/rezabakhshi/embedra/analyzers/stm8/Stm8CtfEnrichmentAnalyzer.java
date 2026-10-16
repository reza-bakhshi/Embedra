package io.github.rezabakhshi.embedra.analyzers.stm8;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityScanner;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfScanOptions;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLeadsReport;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.ComparisonLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.DebugCommandLeadScanner.CommandTableEntry;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.OtaLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.leads.scanner.SecurityLeadScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.MultiEncodingStringScanner;
import io.github.rezabakhshi.embedra.analyzers.strings.StringScanOptions;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackStringRecoveryAnalyzer;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Pure, bounded STM8 CTF entity, string recovery, and security lead enrichment pipeline.
 */
public final class Stm8CtfEnrichmentAnalyzer {

    private final MultiEncodingStringScanner stringScanner;

    private final StackStringRecoveryAnalyzer stackAnalyzer;

    private final CtfEntityScanner ctfScanner;

    private final SecurityLeadScanner securityLeadScanner;

    public Stm8CtfEnrichmentAnalyzer() {
        this.stringScanner = new MultiEncodingStringScanner();
        this.stackAnalyzer = new StackStringRecoveryAnalyzer();
        this.ctfScanner = new CtfEntityScanner();
        this.securityLeadScanner = new SecurityLeadScanner(
                new ComparisonLeadScanner(),
                new DebugCommandLeadScanner(),
                new OtaLeadScanner());
    }

    public Stm8CtfEnrichmentReport analyze(
            Stm8CtfEnrichmentContext context,
            Stm8SignaturePack signaturePack,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(signaturePack, "signaturePack must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (context.flashBytes().length > limits.maxInputBytes()
                || context.flashBytes().length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "STM8 flash payload exceeds parser limits",
                    null));
        }

        // 1. Signature matching (SPL and compiler runtimes)
        Stm8SignatureMatchReport sigReport = Stm8SignatureMatcher.match(
                context.signatureContext(), signaturePack, limits, token);

        token.throwIfCancellationRequested();

        // 2. Multi-encoding static string scanning
        StringScanOptions stringOptions = StringScanOptions.defaults();
        List<ExtractedString> extractedStrings = stringScanner.scan(
                context.flashBytes(), context.flashBase(), stringOptions, limits, token);

        token.throwIfCancellationRequested();

        // 3. Stack-constructed string recovery for STM8
        List<RecoveredStackString> stackStrings = new ArrayList<>();
        if (!context.functionInstructions().isEmpty()) {
            try {
                stackStrings = stackAnalyzer.analyzeFunctions(
                        context.functionInstructions(), limits, token);
            } catch (Exception ignored) {
                // Keep static strings
            }
        }

        token.throwIfCancellationRequested();

        // 4. CTF Entity scanning (flags, credentials, endpoints, keys)
        CtfScanOptions ctfOptions = CtfScanOptions.defaults();
        List<CtfEntity> ctfEntities = new ArrayList<>();
        try {
            ctfEntities.addAll(ctfScanner.scanBytes(
                    context.flashBytes(), context.flashBase(), ctfOptions, token));
            ctfEntities.addAll(ctfScanner.scanStrings(extractedStrings, ctfOptions, token));
            ctfEntities.addAll(ctfScanner.scanStackStrings(stackStrings, ctfOptions, token));
        } catch (Exception ignored) {
        }

        token.throwIfCancellationRequested();

        // 5. Build string table for security leads
        Map<Long, String> stringTable = new HashMap<>();
        for (ExtractedString es : extractedStrings) {
            stringTable.put(es.offset(), es.content());
        }
        for (RecoveredStackString ss : stackStrings) {
            stringTable.put(ss.stackOffset(), ss.content());
        }

        // 6. Scan command tables with 16-bit and 24-bit pointer awareness
        List<CommandTableEntry> commandTables = scanStm8CommandTables(
                context.flashBytes(), context.flashBase(), stringTable, limits, token);

        token.throwIfCancellationRequested();

        // 7. Security lead scanning
        List<SecurityLead> leads = new ArrayList<>();
        try {
            SecurityLeadsReport leadsReport = securityLeadScanner.scanAll(
                    context.functionInstructions(),
                    stringTable,
                    context.symbolMap(),
                    commandTables,
                    InstructionArch.STM8,
                    limits,
                    token);
            leads.addAll(leadsReport.leads());
        } catch (Exception ignored) {
        }

        List<String> detectorsRun = List.of(
                "stm8-spl-signatures",
                "stm8-compiler-runtime-signatures",
                "stm8-string-recovery",
                "stm8-ctf-entity-scanner",
                "stm8-security-leads-discovery");

        return new Stm8CtfEnrichmentReport(
                sigReport,
                extractedStrings,
                ctfEntities,
                leads,
                detectorsRun);
    }

    private static List<CommandTableEntry> scanStm8CommandTables(
            byte[] bytes,
            long baseAddr,
            Map<Long, String> stringTable,
            ParserLimits limits,
            CancellationToken token) {
        List<CommandTableEntry> entries = new ArrayList<>();
        int length = bytes.length;
        if (length < 4) {
            return entries;
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);

        // Scan 16-bit pointer pairs (strPtr 2 bytes, fnPtr 2 bytes)
        for (int offset = 0; offset <= length - 4; offset += 2) {
            if (token.isCancellationRequested() || entries.size() >= limits.maxObjects()) {
                break;
            }
            long strPtr = Short.toUnsignedLong(buffer.getShort(offset));
            long fnPtr = Short.toUnsignedLong(buffer.getShort(offset + 2));

            if (stringTable.containsKey(strPtr) && fnPtr >= baseAddr && fnPtr < baseAddr + length) {
                String cmdStr = stringTable.get(strPtr).trim();
                if (cmdStr.length() >= 2 && cmdStr.length() <= 32) {
                    entries.add(new CommandTableEntry(baseAddr + offset, cmdStr, fnPtr, ""));
                }
            }
        }

        // Scan 24-bit pointer pairs (strPtr 3 bytes, fnPtr 3 bytes)
        if (entries.isEmpty() && length >= 6) {
            for (int offset = 0; offset <= length - 6; offset += 3) {
                if (token.isCancellationRequested() || entries.size() >= limits.maxObjects()) {
                    break;
                }
                long strPtr = (((long) (bytes[offset] & 0xFF)) << 16)
                        | (((long) (bytes[offset + 1] & 0xFF)) << 8)
                        | ((long) (bytes[offset + 2] & 0xFF));
                long fnPtr = (((long) (bytes[offset + 3] & 0xFF)) << 16)
                        | (((long) (bytes[offset + 4] & 0xFF)) << 8)
                        | ((long) (bytes[offset + 5] & 0xFF));

                if (stringTable.containsKey(strPtr) && fnPtr >= baseAddr && fnPtr < baseAddr + length) {
                    String cmdStr = stringTable.get(strPtr).trim();
                    if (cmdStr.length() >= 2 && cmdStr.length() <= 32) {
                        entries.add(new CommandTableEntry(baseAddr + offset, cmdStr, fnPtr, ""));
                    }
                }
            }
        }

        return entries;
    }
}
