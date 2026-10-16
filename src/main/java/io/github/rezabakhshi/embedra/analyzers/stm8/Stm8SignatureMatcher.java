package io.github.rezabakhshi.embedra.analyzers.stm8;

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
 * Pure, bounded, evidence-gated STM8 library and runtime signature matcher (STM8-009).
 *
 * <p>A pack signature is applied only when the context records compiler and family evidence.
 * Missing evidence or unavailable indexes produce explicit non-match reports without guessing.</p>
 */
public final class Stm8SignatureMatcher {

    private static final int MAX_UNMATCHED_DETAILS = 128;

    private Stm8SignatureMatcher() {
    }

    public static Stm8SignatureMatchReport match(
            Stm8SignatureContext context,
            Stm8SignaturePack pack,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(pack, "pack must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();
        enforceLimits(context, pack, limits);

        if (context.family().isBlank() || context.compiler().isEmpty()) {
            return new Stm8SignatureMatchReport(
                    List.of(),
                    List.of(new Stm8SignatureNonMatch(
                            Stm8SignatureNonMatch.Kind.EVIDENCE_MISSING,
                            "Compiler or family evidence is not recorded for " + context.exactPart())),
                    0,
                    0);
        }

        String family = context.family();
        String compiler = context.compiler().orElseThrow();

        List<Stm8LibrarySignature> indexed = pack.signatures().stream()
                .filter(signature -> (signature.family().equalsIgnoreCase(family)
                                || signature.family().equalsIgnoreCase("ANY"))
                        && (signature.compiler().equalsIgnoreCase(compiler)
                                || signature.compiler().equalsIgnoreCase("ANY")))
                .toList();

        if (indexed.isEmpty()) {
            return new Stm8SignatureMatchReport(
                    List.of(),
                    List.of(new Stm8SignatureNonMatch(
                            Stm8SignatureNonMatch.Kind.INDEX_UNAVAILABLE,
                            "No signature is indexed for " + family + "/" + compiler)),
                    0,
                    0);
        }

        List<Stm8SignatureMatch> matches = new ArrayList<>();
        List<Stm8SignatureNonMatch> nonMatches = new ArrayList<>();
        int unmatched = 0;

        for (Stm8FunctionBytes function : context.functions()) {
            token.throwIfCancellationRequested();
            byte[] bytes = function.bytes();
            boolean matched = false;

            for (Stm8LibrarySignature signature : indexed) {
                token.throwIfCancellationRequested();
                if (!signature.matches(bytes)) {
                    continue;
                }
                matched = true;
                Confidence confidence = signature.isFullySpecified()
                        ? Confidence.VERIFIED : Confidence.DERIVED;
                EvidenceKind evidenceKind = signature.isFullySpecified()
                        ? EvidenceKind.EXACT_SIGNATURE_MATCH : EvidenceKind.DERIVED_RULE;

                matches.add(new Stm8SignatureMatch(
                        signature.signatureId(),
                        signature.library(),
                        signature.functionName(),
                        function.address(),
                        pack.identity(),
                        confidence,
                        List.of(new Evidence(
                                evidenceKind,
                                pack.identity(),
                                "Matched STM8 signature " + signature.signatureId()))));
            }

            if (!matched) {
                unmatched++;
                if (nonMatches.size() < MAX_UNMATCHED_DETAILS) {
                    nonMatches.add(new Stm8SignatureNonMatch(
                            Stm8SignatureNonMatch.Kind.NO_MATCH,
                            "No indexed signature matched function at 0x" + Long.toHexString(function.address())));
                }
            }
        }

        if (unmatched > MAX_UNMATCHED_DETAILS) {
            nonMatches.add(new Stm8SignatureNonMatch(
                    Stm8SignatureNonMatch.Kind.NO_MATCH,
                    (unmatched - MAX_UNMATCHED_DETAILS) + " additional functions had no match"));
        }

        matches.sort(Comparator.comparingLong(Stm8SignatureMatch::address)
                .thenComparing(Stm8SignatureMatch::signatureId));

        return new Stm8SignatureMatchReport(
                matches,
                nonMatches,
                context.functions().size(),
                indexed.size());
    }

    private static void enforceLimits(
            Stm8SignatureContext context,
            Stm8SignaturePack pack,
            ParserLimits limits) throws DiagnosticException {
        if (context.functions().size() > limits.maxObjects()
                || pack.signatures().size() > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "STM8 signature input exceeds maximum object limits",
                    null));
        }
    }
}
