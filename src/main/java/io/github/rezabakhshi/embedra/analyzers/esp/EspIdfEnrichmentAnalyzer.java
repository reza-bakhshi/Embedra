package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescription;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Pure, bounded ESP-IDF metadata, logging, FreeRTOS, and signature analysis. */
public final class EspIdfEnrichmentAnalyzer {
    private static final Set<String> LOG_TARGETS = Set.of("esp_log_write", "esp_log_writev");

    private static final Set<String> FREERTOS_SYMBOLS = Set.of(
        "xTaskCreate", "xTaskCreatePinnedToCore", "vTaskDelay", "vTaskDelete",
        "pxCurrentTCB", "xQueueCreate", "xQueueSend", "xQueueReceive");

    public EspIdfEnrichmentReport analyze(EspAnalysisContext context,
            EspIdfSignaturePack signaturePack, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(signaturePack, "signaturePack");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        enforceLimits(context, signaturePack, limits);

        EspIdfMetadata metadata = metadata(context);
        Map<Long, EspStringFact> strings = new HashMap<>();
        for (EspStringFact fact : context.strings()) {
            token.throwIfCancellationRequested();
            strings.putIfAbsent(fact.address(), fact);
        }
        Map<Long, EspSymbolFact> symbols = new HashMap<>();
        for (EspSymbolFact fact : context.symbols()) {
            token.throwIfCancellationRequested();
            symbols.putIfAbsent(fact.address(), fact);
        }

        List<EspLoggingCall> logging = logging(context, strings, symbols, token);
        List<EspFreeRtosEvidence> freeRtos = freeRtos(context, token);
        List<String> unsupported = new ArrayList<>();
        unsupported.add("freertos-heap-objects");
        List<EspLibraryMatch> matches = signatures(context, signaturePack, token,
            unsupported);
        unsupported.sort(String::compareTo);
        return new EspIdfEnrichmentReport(metadata, logging, freeRtos, matches,
            List.of("esp-idf-metadata", "esp-library-signatures", "esp-logging-calls",
                "freertos-symbols"), unsupported);
    }

    private static EspIdfMetadata metadata(EspAnalysisContext context) {
        if (context.appDescription().isEmpty()) {
            return new EspIdfMetadata(Optional.empty(), Optional.empty(), Optional.empty(),
                Confidence.UNKNOWN, List.of());
        }
        EspAppDescription description = context.appDescription().orElseThrow();
        Evidence evidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD,
            "esp_app_desc_t", "IDF, project, and version fields decoded at source offset "
                + description.sourceRange().offset());
        return new EspIdfMetadata(Optional.of(description.idfVersion()),
            Optional.of(description.projectName()), Optional.of(description.version()),
            Confidence.DERIVED, List.of(evidence));
    }

    private static List<EspLoggingCall> logging(EspAnalysisContext context,
            Map<Long, EspStringFact> strings, Map<Long, EspSymbolFact> symbols,
            CancellationToken token) throws DiagnosticException {
        List<EspLoggingCall> results = new ArrayList<>();
        for (EspCallFact call : context.calls()) {
            token.throwIfCancellationRequested();
            EspSymbolFact target = symbols.get(call.targetAddress());
            if (target == null || target.kind() != EspSymbolFactKind.FUNCTION
                || !LOG_TARGETS.contains(target.name()) || call.arguments().size() < 3) {
                continue;
            }
            EspStringFact tag = strings.get(call.arguments().get(1));
            EspStringFact format = strings.get(call.arguments().get(2));
            if (tag == null || format == null) {
                continue;
            }
            results.add(new EspLoggingCall(call.callAddress(), call.callerAddress(),
                target.name(), Optional.of(tag.value()), Optional.of(format.value()),
                Confidence.DERIVED, List.of(new Evidence(EvidenceKind.DERIVED_RULE,
                    target.provenance(), "Resolved call target and constant tag/format pointers"))));
        }
        results.sort(Comparator.comparingLong(EspLoggingCall::callAddress));
        return List.copyOf(results);
    }

    private static List<EspFreeRtosEvidence> freeRtos(EspAnalysisContext context,
            CancellationToken token) throws DiagnosticException {
        List<EspFreeRtosEvidence> results = new ArrayList<>();
        for (EspSymbolFact symbol : context.symbols()) {
            token.throwIfCancellationRequested();
            if (FREERTOS_SYMBOLS.contains(symbol.name())) {
                results.add(new EspFreeRtosEvidence(symbol.name(), symbol.address(), symbol.kind(),
                    Confidence.DERIVED, List.of(new Evidence(EvidenceKind.VENDOR_DATA_PACK,
                        symbol.provenance(), "Exact resolved FreeRTOS symbol"))));
            }
        }
        results.sort(Comparator.comparing(EspFreeRtosEvidence::name)
            .thenComparingLong(EspFreeRtosEvidence::address));
        return List.copyOf(results);
    }

    private static List<EspLibraryMatch> signatures(EspAnalysisContext context,
            EspIdfSignaturePack pack, CancellationToken token, List<String> unsupported)
            throws DiagnosticException {
        String index = context.deviceId() + "/" + context.idfVersion() + "/"
            + context.toolchain() + "/" + context.optimization();
        List<EspLibrarySignature> indexed = pack.signatures().stream()
            .filter(signature -> signature.deviceId().equals(context.deviceId())
                && signature.idfVersion().equals(context.idfVersion())
                && signature.toolchain().equals(context.toolchain())
                && signature.optimization().equals(context.optimization()))
            .toList();
        if (indexed.isEmpty()) {
            unsupported.add("signature-index:" + index);
            return List.of();
        }
        List<EspLibraryMatch> results = new ArrayList<>();
        for (EspFunctionFact function : context.functions()) {
            token.throwIfCancellationRequested();
            byte[] bytes = function.bytes();
            for (EspLibrarySignature signature : indexed) {
                token.throwIfCancellationRequested();
                if (signature.matches(bytes)) {
                    Confidence confidence = signature.isFullySpecified()
                        ? Confidence.VERIFIED : Confidence.DERIVED;
                    EvidenceKind evidenceKind = signature.isFullySpecified()
                        ? EvidenceKind.EXACT_SIGNATURE_MATCH : EvidenceKind.DERIVED_RULE;
                    results.add(new EspLibraryMatch(signature.signatureId(),
                        signature.library(), signature.functionName(), function.address(),
                        pack.identity(), confidence, List.of(new Evidence(
                            evidenceKind, pack.identity(),
                            "Matched indexed signature " + signature.signatureId()))));
                }
            }
        }
        results.sort(Comparator.comparingLong(EspLibraryMatch::address)
            .thenComparing(EspLibraryMatch::signatureId));
        return List.copyOf(results);
    }

    private static void enforceLimits(EspAnalysisContext context,
            EspIdfSignaturePack pack, ParserLimits limits) throws DiagnosticException {
        long objects = checkedAdd(context.strings().size(), context.symbols().size());
        objects = checkedAdd(objects, context.calls().size());
        objects = checkedAdd(objects, context.functions().size());
        objects = checkedAdd(objects, pack.signatures().size());
        long bytes = 0;
        for (EspStringFact string : context.strings()) {
            bytes = checkedAdd(bytes, string.value().getBytes(StandardCharsets.UTF_8).length);
        }
        for (EspFunctionFact function : context.functions()) {
            bytes = checkedAdd(bytes, function.bytes().length);
        }
        for (EspLibrarySignature signature : pack.signatures()) {
            bytes = checkedAdd(bytes, signature.pattern().length);
            bytes = checkedAdd(bytes, signature.mask().length);
        }
        if (objects > limits.maxObjects() || bytes > limits.maxInputBytes()
            || bytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP enrichment input exceeds configured resource limits", null));
        }
    }

    private static long checkedAdd(long left, long right) throws DiagnosticException {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException exception) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP enrichment resource accounting overflow", null));
        }
    }
}
