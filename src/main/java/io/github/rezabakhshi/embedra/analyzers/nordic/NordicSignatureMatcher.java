package io.github.rezabakhshi.embedra.analyzers.nordic;

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
 * Pure, bounded, evidence-gated Nordic library and BLE/Crypto runtime signature matcher (NRF-009, NRF-010).
 *
 * <p>A pack signature is applied only when the context records exact part and series evidence.
 * Missing evidence or unavailable indexes produce explicit non-match reports without guessing.</p>
 */
public final class NordicSignatureMatcher {

    private static final int MAX_UNMATCHED_DETAILS = 128;

    private NordicSignatureMatcher() {
    }

    public static NordicSignatureMatchReport match(
            NordicSignatureContext context,
            NordicSignaturePack pack,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(pack, "pack must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();
        enforceLimits(context, pack, limits);

        if (context.series().isBlank() || context.exactPart().isBlank()) {
            return new NordicSignatureMatchReport(
                    List.of(),
                    List.of(new NordicSignatureNonMatch(
                            NordicSignatureNonMatch.Kind.EVIDENCE_MISSING,
                            "Series or exact part evidence is not recorded for " + context.exactPart())),
                    0,
                    0);
        }

        String series = context.series();
        String compiler = context.compiler().orElse("ANY");

        List<NordicLibrarySignature> indexed = pack.signatures().stream()
                .filter(signature -> (signature.series().equalsIgnoreCase(series)
                                || signature.series().equalsIgnoreCase("ANY"))
                        && (signature.compiler().equalsIgnoreCase(compiler)
                                || signature.compiler().equalsIgnoreCase("ANY")))
                .toList();

        if (indexed.isEmpty()) {
            return new NordicSignatureMatchReport(
                    List.of(),
                    List.of(new NordicSignatureNonMatch(
                            NordicSignatureNonMatch.Kind.INDEX_UNAVAILABLE,
                            "No signature is indexed for " + series + "/" + compiler)),
                    0,
                    0);
        }

        List<NordicSignatureMatch> matches = new ArrayList<>();
        List<NordicSignatureNonMatch> nonMatches = new ArrayList<>();
        int unmatched = 0;

        for (NordicFunctionBytes function : context.functions()) {
            token.throwIfCancellationRequested();
            byte[] bytes = function.bytes();
            boolean matched = false;

            for (NordicLibrarySignature signature : indexed) {
                token.throwIfCancellationRequested();
                if (!signature.matches(bytes)) {
                    continue;
                }
                matched = true;
                Confidence confidence = signature.isFullySpecified()
                        ? Confidence.VERIFIED : Confidence.DERIVED;
                EvidenceKind evidenceKind = signature.isFullySpecified()
                        ? EvidenceKind.EXACT_SIGNATURE_MATCH : EvidenceKind.DERIVED_RULE;

                matches.add(new NordicSignatureMatch(
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
                                "Matched Nordic signature " + signature.signatureId()))));
                break;
            }

            if (!matched) {
                unmatched++;
                if (nonMatches.size() < MAX_UNMATCHED_DETAILS) {
                    nonMatches.add(new NordicSignatureNonMatch(
                            NordicSignatureNonMatch.Kind.NO_MATCH,
                            "No signature matched function at 0x" + Long.toHexString(function.address())));
                }
            }
        }

        matches.sort(Comparator.comparing(NordicSignatureMatch::address));

        return new NordicSignatureMatchReport(
                matches,
                nonMatches,
                context.functions().size(),
                indexed.size());
    }

    private static void enforceLimits(
            NordicSignatureContext context,
            NordicSignaturePack pack,
            ParserLimits limits) throws DiagnosticException {
        if (context.functions().size() > limits.maxObjects()
                || pack.signatures().size() > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Nordic signature input exceeds maximum object limits",
                    null));
        }
    }
}
