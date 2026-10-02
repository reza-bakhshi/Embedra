package io.github.rezabakhshi.embedra.analyzers.stm32;

import static io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic.error;

import io.github.rezabakhshi.embedra.analyzers.esp.EspArtifactChangeKind;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Applies the shared T025 diff contract to confirmed STM32 firmware artifacts.
 *
 * <p>The shared ESP analyzer is consumed as a contract, not reimplemented: the
 * classification vocabulary {@link EspArtifactChangeKind} and the ADR-0017
 * ordering rule (compare retained content digests before physical extents) are
 * reused verbatim over STM32 artifacts, which carry the confirmed image extent
 * (the T041 {@code ImageRange} contract) instead of an ESP flash range. Binding
 * both artifacts to one exact part and to the digest-pinned curated selection
 * fails closed with stable diagnostics before any comparison is produced. The
 * shared limits and cancellation contracts bound every run.</p>
 */
public final class Stm32FirmwareDiffAnalyzer {
    /** Stable diagnostic codes raised by STM32 firmware binding and comparison. */
    public enum Diagnostic {
        DIFF_EXACT_PART_MISMATCH,
        DIFF_EXACT_PART_UNCURATED;
    }

    /** A binding or comparison failure with a stable diagnostic code. */
    public static final class DiffException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private DiffException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    public Stm32FirmwareDiffReport analyze(Stm32FirmwareDiffContext context,
            ParserLimits limits, CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        enforceLimits(context, limits);
        bind(context);

        Stm32FirmwareArtifact baseline = context.baseline().orElse(null);
        Stm32FirmwareArtifact candidate = context.candidate().orElse(null);
        EspArtifactChangeKind kind;
        if (baseline == null) {
            kind = EspArtifactChangeKind.ADDED;
        }
        else if (candidate == null) {
            kind = EspArtifactChangeKind.REMOVED;
        }
        else if (!baseline.sha256().equals(candidate.sha256())) {
            kind = EspArtifactChangeKind.MODIFIED;
        }
        else if (!baseline.imageRange().equals(candidate.imageRange())) {
            kind = EspArtifactChangeKind.MOVED;
        }
        else {
            kind = EspArtifactChangeKind.UNCHANGED;
        }
        return new Stm32FirmwareDiffReport(new Stm32ArtifactDiff(kind, Confidence.VERIFIED,
            evidence(context, baseline, candidate)), List.of("stm32-firmware-diff"));
    }

    private static void bind(Stm32FirmwareDiffContext context) {
        if (context.baseline().isPresent() && context.candidate().isPresent()
                && !context.baseline().orElseThrow().exactPart()
                    .equals(context.candidate().orElseThrow().exactPart())) {
            throw new DiffException(Diagnostic.DIFF_EXACT_PART_MISMATCH,
                "Baseline " + context.baseline().orElseThrow().exactPart()
                    + " does not match candidate "
                    + context.candidate().orElseThrow().exactPart()
                    + "; STM32 firmware diff binds both artifacts to one exact part");
        }
        String part = (context.baseline().isPresent() ? context.baseline()
            : context.candidate()).orElseThrow().exactPart();
        if (!context.selection().containsExactPart(part)) {
            throw new DiffException(Diagnostic.DIFF_EXACT_PART_UNCURATED,
                "Exact part " + part + " is not in the digest-pinned curated selection; "
                    + "no confirmed STM32 diff input exists");
        }
    }

    private static List<Evidence> evidence(Stm32FirmwareDiffContext context,
            Stm32FirmwareArtifact baseline, Stm32FirmwareArtifact candidate) {
        String part = (baseline != null ? baseline : candidate).exactPart();
        Set<Evidence> entries = new LinkedHashSet<>();
        if (baseline == null) {
            entries.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32-firmware-diff:" + part,
                "Confirmed candidate artifact '" + candidate.id()
                    + "' has no baseline counterpart; classified added"));
        }
        else if (candidate == null) {
            entries.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32-firmware-diff:" + part,
                "Confirmed baseline artifact '" + baseline.id()
                    + "' has no candidate counterpart; classified removed"));
        }
        else {
            entries.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32-firmware-diff:" + part,
                "Compared content SHA-256 before image extents of validated artifacts '"
                    + baseline.id() + "' and '" + candidate.id() + "' bound to " + part));
        }
        if (baseline != null) {
            entries.addAll(baseline.evidence());
        }
        if (candidate != null) {
            entries.addAll(candidate.evidence());
        }
        return List.copyOf(entries);
    }

    private static void enforceLimits(Stm32FirmwareDiffContext context, ParserLimits limits)
            throws DiagnosticException {
        long objects = (context.baseline().isPresent() ? 1L : 0L)
            + (context.candidate().isPresent() ? 1L : 0L);
        long bytes = 0;
        for (Stm32FirmwareArtifact artifact : new Stm32FirmwareArtifact[] {
            context.baseline().orElse(null), context.candidate().orElse(null)}) {
            if (artifact == null) {
                continue;
            }
            bytes = checkedAdd(bytes, utf8Length(artifact.exactPart()));
            bytes = checkedAdd(bytes, utf8Length(artifact.id()));
            bytes = checkedAdd(bytes, utf8Length(artifact.sha256()));
        }
        if (objects > limits.maxObjects() || bytes > limits.maxInputBytes()
                || bytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(error(DiagnosticCode.LIMIT_EXCEEDED,
                "STM32 firmware diff input exceeds configured resource limits", null));
        }
    }

    private static long utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static long checkedAdd(long left, long right) throws DiagnosticException {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException exception) {
            throw new DiagnosticException(error(DiagnosticCode.LIMIT_EXCEEDED,
                "STM32 firmware diff resource accounting overflow", null));
        }
    }
}
