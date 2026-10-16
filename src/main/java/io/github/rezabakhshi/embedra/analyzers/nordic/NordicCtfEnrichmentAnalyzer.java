package io.github.rezabakhshi.embedra.analyzers.nordic;

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
 * Pure, bounded Nordic CTF entity, string recovery, and security lead enrichment pipeline (NRF-009).
 */
public final class NordicCtfEnrichmentAnalyzer {

    private final MultiEncodingStringScanner stringScanner;

    private final StackStringRecoveryAnalyzer stackAnalyzer;

    private final CtfEntityScanner ctfScanner;

    private final SecurityLeadScanner securityLeadScanner;

    public NordicCtfEnrichmentAnalyzer() {
        this.stringScanner = new MultiEncodingStringScanner();
        this.stackAnalyzer = new StackStringRecoveryAnalyzer();
        this.ctfScanner = new CtfEntityScanner();
        this.securityLeadScanner = new SecurityLeadScanner(
                new ComparisonLeadScanner(),
                new DebugCommandLeadScanner(),
                new OtaLeadScanner());
    }

    public NordicCtfEnrichmentReport analyze(
            NordicCtfEnrichmentContext context,
            NordicSignaturePack signaturePack,
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
                    "Nordic flash payload exceeds parser limits",
                    null));
        }

        // 1. Signature matching (nRF5 SDK, NCS Zephyr, and SoftDevice)
        NordicSignatureMatchReport sigReport = NordicSignatureMatcher.match(
                context.signatureContext(), signaturePack, limits, token);

        token.throwIfCancellationRequested();

        // 2. Multi-encoding static string scanning
        StringScanOptions stringOptions = StringScanOptions.defaults();
        List<ExtractedString> extractedStrings = stringScanner.scan(
                context.flashBytes(), context.flashBase(), stringOptions, limits, token);

        token.throwIfCancellationRequested();

        // 3. Stack-constructed string recovery for ARM Thumb
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

        // 6. Scan 32-bit command tables with ARM Thumb pointer awareness
        List<CommandTableEntry> commandTables = scanNordicCommandTables(
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
                    InstructionArch.ARM_THUMB,
                    limits,
                    token);
            leads.addAll(leadsReport.leads());
        } catch (Exception ignored) {
        }

        List<String> detectorsRun = List.of(
                "nrf5-sdk-signatures",
                "ncs-zephyr-signatures",
                "softdevice-api-dispatch",
                "nordic-string-recovery",
                "nordic-ctf-entity-scanner",
                "nordic-security-leads-discovery");

        return new NordicCtfEnrichmentReport(
                sigReport,
                extractedStrings,
                stackStrings,
                ctfEntities,
                leads,
                detectorsRun);
    }

    private static List<CommandTableEntry> scanNordicCommandTables(
            byte[] bytes,
            long baseAddr,
            Map<Long, String> stringTable,
            ParserLimits limits,
            CancellationToken token) {
        List<CommandTableEntry> entries = new ArrayList<>();
        int length = bytes.length;
        if (length < 8) {
            return entries;
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

        // Scan 32-bit pointer pairs (strPtr 4 bytes LE, fnPtr 4 bytes LE)
        for (int offset = 0; offset <= length - 8; offset += 4) {
            if (token.isCancellationRequested() || entries.size() >= limits.maxObjects()) {
                break;
            }
            long strPtr = Integer.toUnsignedLong(buffer.getInt(offset));
            long fnPtr = Integer.toUnsignedLong(buffer.getInt(offset + 4));
            long fnAddr = fnPtr & ~1L; // Clear Thumb bit

            if (stringTable.containsKey(strPtr) && fnAddr >= baseAddr && fnAddr < baseAddr + length) {
                String cmdStr = stringTable.get(strPtr).trim();
                if (cmdStr.length() >= 2 && cmdStr.length() <= 64) {
                    entries.add(new CommandTableEntry(baseAddr + offset, cmdStr, fnAddr, ""));
                }
            }
        }

        return entries;
    }
}
