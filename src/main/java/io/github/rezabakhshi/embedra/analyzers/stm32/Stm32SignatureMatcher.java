package io.github.rezabakhshi.embedra.analyzers.stm32;

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
 * Pure, bounded, evidence-gated STM32 library signature matcher (STM-012).
 *
 * <p>A pack signature is considered only when the context records the exact
 * family, compiler identity, and optimization level it was built with. Missing
 * evidence, an unavailable index, or no matching candidate all produce explicit
 * {@link Stm32SignatureNonMatch} entries rather than a guessed match. A match
 * never promotes an exact-part support state.</p>
 */
public final class Stm32SignatureMatcher {
    private static final int MAX_UNMATCHED_DETAILS = 128;

    private Stm32SignatureMatcher() {
    }

    public static Stm32SignatureMatchReport match(Stm32SignatureContext context,
            Stm32SignaturePack pack, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(pack, "pack");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        enforceLimits(context, pack, limits);

        if (context.family().isBlank() || context.compiler().isEmpty()
                || context.optimization().isEmpty()) {
            return new Stm32SignatureMatchReport(List.of(), List.of(
                new Stm32SignatureNonMatch(Stm32SignatureNonMatch.Kind.EVIDENCE_MISSING,
                    "Compiler, optimization, or family evidence is not recorded for "
                        + context.exactPart())), 0, 0);
        }
        String family = context.family();
        String compiler = context.compiler().orElseThrow();
        String optimization = context.optimization().orElseThrow();
        List<Stm32LibrarySignature> indexed = pack.signatures().stream()
            .filter(signature -> signature.family().equals(family)
                && signature.compiler().equals(compiler)
                && signature.optimization().equals(optimization))
            .toList();
        if (indexed.isEmpty()) {
            return new Stm32SignatureMatchReport(List.of(), List.of(
                new Stm32SignatureNonMatch(Stm32SignatureNonMatch.Kind.INDEX_UNAVAILABLE,
                    "No signature is indexed for " + family + "/" + compiler + "/"
                        + optimization)), 0, 0);
        }

        List<Stm32SignatureMatch> matches = new ArrayList<>();
        List<Stm32SignatureNonMatch> nonMatches = new ArrayList<>();
        int unmatched = 0;
        for (Stm32FunctionBytes function : context.functions()) {
            token.throwIfCancellationRequested();
            byte[] bytes = function.bytes();
            boolean matched = false;
            for (Stm32LibrarySignature signature : indexed) {
                token.throwIfCancellationRequested();
                if (!signature.matches(bytes)) {
                    continue;
                }
                matched = true;
                Confidence confidence = signature.isFullySpecified()
                    ? Confidence.VERIFIED : Confidence.DERIVED;
                EvidenceKind evidenceKind = signature.isFullySpecified()
                    ? EvidenceKind.EXACT_SIGNATURE_MATCH : EvidenceKind.DERIVED_RULE;
                matches.add(new Stm32SignatureMatch(signature.signatureId(),
                    signature.library(), signature.functionName(), function.address(),
                    pack.identity(), confidence, List.of(new Evidence(evidenceKind,
                        pack.identity(), "Matched indexed signature "
                            + signature.signatureId()))));
            }
            if (!matched) {
                unmatched++;
                if (nonMatches.size() < MAX_UNMATCHED_DETAILS) {
                    nonMatches.add(new Stm32SignatureNonMatch(
                        Stm32SignatureNonMatch.Kind.NO_MATCH,
                        "No indexed signature matched the function at 0x"
                            + Long.toHexString(function.address())));
                }
            }
        }
        if (unmatched > MAX_UNMATCHED_DETAILS) {
            nonMatches.add(new Stm32SignatureNonMatch(Stm32SignatureNonMatch.Kind.NO_MATCH,
                (unmatched - MAX_UNMATCHED_DETAILS) + " additional functions had no match"));
        }
        matches.sort(Comparator.comparingLong(Stm32SignatureMatch::address)
            .thenComparing(Stm32SignatureMatch::signatureId));
        nonMatches.sort(Comparator.comparing(Stm32SignatureNonMatch::kind)
            .thenComparing(Stm32SignatureNonMatch::detail));
        return new Stm32SignatureMatchReport(matches, nonMatches,
            context.functions().size(), indexed.size());
    }

    private static void enforceLimits(Stm32SignatureContext context,
            Stm32SignaturePack pack, ParserLimits limits) throws DiagnosticException {
        long objects = checkedAdd(context.functions().size(), pack.signatures().size());
        long bytes = 0;
        for (Stm32FunctionBytes function : context.functions()) {
            bytes = checkedAdd(bytes, function.bytes().length);
        }
        for (Stm32LibrarySignature signature : pack.signatures()) {
            bytes = checkedAdd(bytes, signature.pattern().length);
            bytes = checkedAdd(bytes, signature.mask().length);
        }
        if (objects > limits.maxObjects() || bytes > limits.maxInputBytes()
            || bytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "STM32 signature input exceeds configured resource limits", null));
        }
    }

    private static long checkedAdd(long left, long right) throws DiagnosticException {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException exception) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "STM32 signature resource accounting overflow", null));
        }
    }
}
