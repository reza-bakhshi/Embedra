package io.github.rezabakhshi.embedra.analyzers.atmel;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Pure, bounded, evidence-gated Atmel and Microchip runtime signature matcher.
 *
 * <p>Signatures are applied only when the context records exact part, series, and architecture evidence.
 * Missing evidence or unavailable indexes produce explicit non-match reports without guessing.</p>
 */
public final class AtmelSignatureMatcher {

    private static final int MAX_UNMATCHED_DETAILS = 128;

    private AtmelSignatureMatcher() {
    }

    public static AtmelSignatureMatchReport match(
            AtmelSignatureContext context,
            AtmelSignaturePack pack,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(pack, "pack must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();
        enforceLimits(context, pack, limits);

        if (context.series().isBlank() || context.exactPart().isBlank() || context.architecture().isBlank()) {
            return new AtmelSignatureMatchReport(
                    List.of(),
                    List.of(new AtmelSignatureNonMatch(
                            AtmelSignatureNonMatch.Kind.EVIDENCE_MISSING,
                            "Architecture, series, or exact part evidence is not recorded for " + context.exactPart())),
                    0,
                    0);
        }

        String arch = context.architecture();
        String series = context.series();
        String compiler = context.compiler().orElse("ANY");

        List<AtmelLibrarySignature> indexed = pack.signatures().stream()
                .filter(signature -> (signature.architecture().equalsIgnoreCase(arch)
                                || signature.architecture().equalsIgnoreCase("ANY")
                                || arch.equalsIgnoreCase("ANY"))
                        && (signature.series().equalsIgnoreCase(series)
                                || signature.series().equalsIgnoreCase("ANY")
                                || series.equalsIgnoreCase("ANY"))
                        && (compiler.equalsIgnoreCase("ANY")
                                || signature.compiler().equalsIgnoreCase("ANY")
                                || signature.compiler().equalsIgnoreCase(compiler)))
                .toList();

        if (indexed.isEmpty()) {
            return new AtmelSignatureMatchReport(
                    List.of(),
                    List.of(new AtmelSignatureNonMatch(
                            AtmelSignatureNonMatch.Kind.INDEX_UNAVAILABLE,
                            "No signature is indexed for " + arch + "/" + series + "/" + compiler)),
                    0,
                    0);
        }

        List<AtmelSignatureMatch> matches = new ArrayList<>();
        List<AtmelSignatureNonMatch> nonMatches = new ArrayList<>();
        int unmatched = 0;

        for (AtmelFunctionBytes function : context.functions()) {
            token.throwIfCancellationRequested();
            byte[] bytes = function.bytes();
            boolean matched = false;

            for (AtmelLibrarySignature signature : indexed) {
                token.throwIfCancellationRequested();
                if (!signature.matches(bytes)) {
                    continue;
                }
                matched = true;
                Confidence confidence = signature.isFullySpecified()
                        ? Confidence.VERIFIED : Confidence.DERIVED;
                EvidenceKind evidenceKind = signature.isFullySpecified()
                        ? EvidenceKind.EXACT_SIGNATURE_MATCH : EvidenceKind.DERIVED_RULE;

                matches.add(new AtmelSignatureMatch(
                        signature.signatureId(),
                        signature.library(),
                        signature.subsystem(),
                        signature.functionName(),
                        function.address(),
                        pack.identity(),
                        confidence,
                        List.of(new Evidence(
                                evidenceKind,
                                pack.identity(),
                                "Matched Atmel/Microchip signature " + signature.signatureId()))));
                break;
            }

            if (!matched) {
                unmatched++;
                if (nonMatches.size() < MAX_UNMATCHED_DETAILS) {
                    nonMatches.add(new AtmelSignatureNonMatch(
                            AtmelSignatureNonMatch.Kind.NO_MATCH,
                            "No signature matched function at 0x" + Long.toHexString(function.address())));
                }
            }
        }

        matches.sort(Comparator.comparing(AtmelSignatureMatch::address));

        return new AtmelSignatureMatchReport(
                matches,
                nonMatches,
                context.functions().size(),
                indexed.size());
    }

    private static void enforceLimits(
            AtmelSignatureContext context,
            AtmelSignaturePack pack,
            ParserLimits limits) throws DiagnosticException {
        if (context.functions().size() > limits.maxObjects()
                || pack.signatures().size() > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Atmel signature input exceeds maximum object limits",
                    null));
        }
    }
}
