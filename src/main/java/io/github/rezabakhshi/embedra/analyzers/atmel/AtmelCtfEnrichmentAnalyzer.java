package io.github.rezabakhshi.embedra.analyzers.atmel;

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
 * Pure, bounded Atmel and Microchip CTF entity, string recovery, and security lead enrichment pipeline.
 */
public final class AtmelCtfEnrichmentAnalyzer {

    private final MultiEncodingStringScanner stringScanner;

    private final StackStringRecoveryAnalyzer stackAnalyzer;

    private final CtfEntityScanner ctfScanner;

    private final SecurityLeadScanner securityLeadScanner;

    public AtmelCtfEnrichmentAnalyzer() {
        this.stringScanner = new MultiEncodingStringScanner();
        this.stackAnalyzer = new StackStringRecoveryAnalyzer();
        this.ctfScanner = new CtfEntityScanner();
        this.securityLeadScanner = new SecurityLeadScanner(
                new ComparisonLeadScanner(),
                new DebugCommandLeadScanner(),
                new OtaLeadScanner());
    }

    public AtmelCtfEnrichmentReport analyze(
            AtmelCtfEnrichmentContext context,
            AtmelSignaturePack signaturePack,
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
                    "Atmel flash payload exceeds parser limits",
                    null));
        }

        // 1. Signature matching (Arduino, AVR-libc, ASF, FreeRTOS)
        AtmelSignatureMatchReport sigReport = AtmelSignatureMatcher.match(
                context.signatureContext(), signaturePack, limits, token);

        token.throwIfCancellationRequested();

        // 2. Multi-encoding static string scanning
        StringScanOptions stringOptions = StringScanOptions.defaults();
        List<ExtractedString> extractedStrings = stringScanner.scan(
                context.flashBytes(), context.flashBase(), stringOptions, limits, token);

        token.throwIfCancellationRequested();

        // 3. Stack-constructed string recovery
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

        // 6. Scan command tables (16-bit for AVR8, 32-bit for SAM Cortex-M)
        boolean isAvr = context.signatureContext().architecture().equalsIgnoreCase("AVR8");
        List<CommandTableEntry> commandTables = scanAtmelCommandTables(
                context.flashBytes(), context.flashBase(), stringTable, isAvr, limits, token);

        token.throwIfCancellationRequested();

        // 7. Security lead scanning
        InstructionArch arch = isAvr ? InstructionArch.AVR8 : InstructionArch.ARM_THUMB;
        List<SecurityLead> leads = new ArrayList<>();
        try {
            SecurityLeadsReport leadsReport = securityLeadScanner.scanAll(
                    context.functionInstructions(),
                    stringTable,
                    context.symbolMap(),
                    commandTables,
                    arch,
                    limits,
                    token);
            leads.addAll(leadsReport.leads());
        } catch (Exception ignored) {
        }

        List<String> detectorsRun = List.of(
                "arduino-core-signatures",
                "avr-libc-signatures",
                "atmel-start-asf-signatures",
                "freertos-signatures",
                "atmel-string-recovery",
                "atmel-ctf-entity-scanner",
                "atmel-security-leads-discovery");

        return new AtmelCtfEnrichmentReport(
                sigReport,
                extractedStrings,
                stackStrings,
                ctfEntities,
                leads,
                detectorsRun);
    }

    private static List<CommandTableEntry> scanAtmelCommandTables(
            byte[] bytes,
            long baseAddr,
            Map<Long, String> stringTable,
            boolean isAvr,
            ParserLimits limits,
            CancellationToken token) {
        List<CommandTableEntry> entries = new ArrayList<>();
        int length = bytes.length;
        int ptrSize = isAvr ? 2 : 4;
        int entrySize = ptrSize * 2;
        if (length < entrySize) {
            return entries;
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

        for (int offset = 0; offset <= length - entrySize; offset += ptrSize) {
            if (token.isCancellationRequested() || entries.size() >= limits.maxObjects()) {
                break;
            }
            long strPtr = isAvr
                    ? Short.toUnsignedLong(buffer.getShort(offset))
                    : Integer.toUnsignedLong(buffer.getInt(offset));
            long fnPtr = isAvr
                    ? Short.toUnsignedLong(buffer.getShort(offset + ptrSize))
                    : Integer.toUnsignedLong(buffer.getInt(offset + ptrSize));

            if (strPtr == 0 || fnPtr == 0) {
                continue;
            }

            if (stringTable.containsKey(strPtr)) {
                String cmdStr = stringTable.get(strPtr);
                if (cmdStr.length() >= 2 && cmdStr.matches("^[a-zA-Z0-9_\\-]+$")) {
                    long tableAddr = baseAddr + offset;
                    entries.add(new CommandTableEntry(tableAddr, cmdStr, fnPtr, ""));
                }
            }
        }

        return entries;
    }
}
