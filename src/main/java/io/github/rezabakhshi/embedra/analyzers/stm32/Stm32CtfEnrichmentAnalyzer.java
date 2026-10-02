package io.github.rezabakhshi.embedra.analyzers.stm32;

import static io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic.error;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityAttribute;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityWindow;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Applies the shared analyzers to confirmed STM32 firmware and ranks leads.
 *
 * <p>The shared analyzers are consumed, never duplicated or weakened: signature
 * identification runs through the T043 {@link Stm32SignatureMatcher} evidence
 * gates (family/compiler/optimization are caller-recorded and passed through
 * unchanged), and TrustZone evidence comes only from a digest-pinned T044
 * {@link Stm32SecurityRecord}. Each signature match becomes a ranked lead that
 * carries the shared match's confidence and evidence verbatim; each missing
 * piece of evidence stays an explicit shared non-match and an explicit
 * capability entry, never an invented finding.</p>
 *
 * <p>Logging/assert recovery is the one shared contract this layer cannot
 * permit for STM32 inputs today: its evidence contract (ADR 0015) requires a
 * resolved logging/assert target and constant tag/format pointers, and no
 * STM32 logging/assert target is pinned anywhere in this repository. The gap is
 * therefore reported as the explicit capability entry
 * {@code stm32-logging-assert-recovery} and produces no lead. Security leads
 * arise only when a confirmed image extent falls entirely inside a pinned
 * {@code SECURE} alias aperture; everything else stays unled. Leads never carry
 * secret material ({@code secret} is always false for the detectors shipped
 * here) and never claim exploitability or device support.</p>
 */
public final class Stm32CtfEnrichmentAnalyzer {
    /** Stable diagnostic codes raised by STM32 enrichment binding. */
    public enum Diagnostic {
        ENRICHMENT_PART_UNCURATED,
        ENRICHMENT_ARTIFACT_PART_MISMATCH,
        ENRICHMENT_SECURITY_PART_MISMATCH;
    }

    /** A binding failure with a stable diagnostic code. */
    public static final class EnrichmentException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private EnrichmentException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    private static final String CODE_SIGNATURE_LEAD = "STM32_SIGNATURE_LIBRARY_FUNCTION";

    private static final String CODE_SECURE_ALIAS_LEAD = "STM32_IMAGE_IN_SECURE_ALIAS";

    private static final String LOGGING_ASSERT_GAP = "stm32-logging-assert-recovery";

    /**
     * Runs the bounded enrichment pass over one confirmed exact part.
     *
     * @param context the confirmed STM32 inputs
     * @param pack the digest-pinned signature pack consumed by the shared matcher
     * @param limits shared parser bounds
     * @param token cooperative cancellation
     * @return the immutable report with ranked leads and explicit availability
     * @throws EnrichmentException when the artifacts disagree on the exact part,
     *         the part is outside the digest-pinned curated selection, or the
     *         security record is for a different part
     * @throws DiagnosticException when the shared limits are exceeded or the
     *         caller cancels
     */
    public Stm32CtfEnrichmentReport analyze(Stm32CtfEnrichmentContext context,
            Stm32SignaturePack pack, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(pack, "pack");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        enforceLimits(context, pack, limits);
        bind(context);

        Stm32SignatureMatchReport signatureReport = Stm32SignatureMatcher.match(
            new Stm32SignatureContext(part(context), context.family().orElse(""),
                context.compiler(), context.optimization(), context.functions()),
            pack, limits, token);
        Stm32SecurityEvidence security = securityEvidence(context, token);
        List<Stm32CtfLead> leads = new ArrayList<>(
            signatureLeads(signatureReport, part(context)));
        leads.addAll(securityLeads(context, security, token));
        leads.sort(Comparator.comparing((Stm32CtfLead lead) -> -Stm32CtfLead.rank(
                lead.severity())).thenComparing(Stm32CtfLead::code)
                .thenComparing(lead -> lead.address().orElse(Long.MAX_VALUE)));
        return new Stm32CtfEnrichmentReport(signatureReport, security, List.copyOf(leads),
            List.of("stm32-signature-match", "stm32-security-evidence"),
            unsupported(signatureReport));
    }

    private static void bind(Stm32CtfEnrichmentContext context) {
        String part = part(context);
        for (Stm32FirmwareArtifact artifact : context.artifacts()) {
            if (!artifact.exactPart().equals(part)) {
                throw new EnrichmentException(Diagnostic.ENRICHMENT_ARTIFACT_PART_MISMATCH,
                    "Confirmed artifact '" + artifact.id() + "' is bound to "
                        + artifact.exactPart() + " instead of " + part
                        + "; STM32 enrichment binds every input to one exact part");
            }
        }
        if (!context.selection().containsExactPart(part)) {
            throw new EnrichmentException(Diagnostic.ENRICHMENT_PART_UNCURATED,
                "Exact part " + part + " is not in the digest-pinned curated selection; "
                    + "no confirmed STM32 enrichment input exists");
        }
        if (context.security().isPresent()
                && !context.security().orElseThrow().exactPart().equals(part)) {
            throw new EnrichmentException(Diagnostic.ENRICHMENT_SECURITY_PART_MISMATCH,
                "Security record " + context.security().orElseThrow().exactPart()
                    + " does not match the analyzed part " + part);
        }
    }

    private static String part(Stm32CtfEnrichmentContext context) {
        return context.artifacts().get(0).exactPart();
    }

    private static List<Stm32CtfLead> signatureLeads(Stm32SignatureMatchReport report,
            String part) {
        List<Stm32CtfLead> leads = new ArrayList<>();
        for (Stm32SignatureMatch match : report.matches()) {
            leads.add(new Stm32CtfLead(CODE_SIGNATURE_LEAD, Stm32CtfLead.Severity.LOW,
                match.confidence(), "Evidence-gated signature match " + match.signatureId()
                    + " identifies " + match.library() + "." + match.functionName()
                    + " at " + Stm32CtfLead.hex(match.address()) + " bound to " + part
                    + "; a function-identification lead with " + match.packIdentity()
                    + " provenance, not a device-support or exploitability claim",
                OptionalLong.of(match.address()), false, match.evidence()));
        }
        return leads;
    }

    private static Stm32SecurityEvidence securityEvidence(Stm32CtfEnrichmentContext context,
            CancellationToken token) throws DiagnosticException {
        String part = part(context);
        if (context.security().isEmpty()) {
            return new Stm32SecurityEvidence(part, Stm32SecurityEvidence.Status.NOT_SUPPLIED,
                "No confirmed TrustZone security record was supplied for " + part,
                List.of(), List.of(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                    "stm32-ctf-enrichment",
                    "Security evidence is unavailable without a confirmed record")));
        }
        Stm32SecurityRecord record = context.security().orElseThrow();
        if (!record.pinned()) {
            return new Stm32SecurityEvidence(part, Stm32SecurityEvidence.Status.UNAVAILABLE,
                record.reason(), List.of(), List.of(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                    "stm32-ctf-enrichment",
                    "The confirmed TrustZone record is unavailable for " + part + ": "
                        + record.reason())));
        }
        token.throwIfCancellationRequested();
        List<String> windowIds = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();
        for (Stm32SecurityWindow window : record.windows()) {
            windowIds.add(window.id());
            evidence.add(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                "stm32-security-domains:" + window.id(),
                "Pinned secure alias aperture " + window.id() + " covers "
                    + Stm32CtfLead.hex(window.start()) + ".."
                    + Stm32CtfLead.hex(window.endExclusive()) + " (header "
                    + window.headerPath() + ":" + window.baseLine() + ")"));
        }
        return new Stm32SecurityEvidence(part, Stm32SecurityEvidence.Status.PINNED, null,
            windowIds, evidence);
    }

    private static List<Stm32CtfLead> securityLeads(Stm32CtfEnrichmentContext context,
            Stm32SecurityEvidence security, CancellationToken token)
            throws DiagnosticException {
        List<Stm32CtfLead> leads = new ArrayList<>();
        if (security.status() != Stm32SecurityEvidence.Status.PINNED) {
            return leads;
        }
        Stm32SecurityRecord record = context.security().orElseThrow();
        for (Stm32FirmwareArtifact artifact : context.artifacts()) {
            token.throwIfCancellationRequested();
            AddressRange image = new AddressRange(Stm32SecurityWindow.ADDRESS_SPACE,
                artifact.imageRange().base(), artifact.imageRange().length());
            for (Stm32SecurityWindow window : record.windows()) {
                token.throwIfCancellationRequested();
                if (window.attribute() != Stm32SecurityAttribute.SECURE
                        || !window.covers(image)) {
                    continue;
                }
                leads.add(new Stm32CtfLead(CODE_SECURE_ALIAS_LEAD,
                    Stm32CtfLead.Severity.MEDIUM, Confidence.DERIVED,
                    "Confirmed artifact '" + artifact.id() + "' image extent "
                        + Stm32CtfLead.hex(image.start()) + ".."
                        + Stm32CtfLead.hex(image.endExclusive()) + " falls inside the pinned "
                        + "secure alias aperture " + window.id() + " of " + part(context)
                        + " (header " + window.headerPath() + ":" + window.baseLine()
                        + "); a TrustZone-boundary lead, not a partition or "
                        + "exploitability claim",
                    OptionalLong.of(image.start()),
                    false,
                    List.of(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                        "stm32-security-domains:" + window.id(),
                        "Pinned secure alias aperture " + window.id() + " covers the "
                            + "confirmed image extent (header " + window.headerPath() + ":"
                            + window.baseLine() + ", " + window.baseDeclaration() + ")"))));
            }
        }
        return leads;
    }

    private static List<String> unsupported(Stm32SignatureMatchReport report) {
        List<String> unsupported = new ArrayList<>();
        unsupported.add(LOGGING_ASSERT_GAP);
        boolean evidenceMissing = report.nonMatches().stream()
            .anyMatch(nonMatch -> nonMatch.kind()
                == Stm32SignatureNonMatch.Kind.EVIDENCE_MISSING);
        boolean indexUnavailable = report.nonMatches().stream()
            .anyMatch(nonMatch -> nonMatch.kind()
                == Stm32SignatureNonMatch.Kind.INDEX_UNAVAILABLE);
        if (evidenceMissing) {
            unsupported.add("signature-evidence-missing");
        }
        if (indexUnavailable) {
            unsupported.add("signature-index-unavailable");
        }
        unsupported.sort(String::compareTo);
        return unsupported;
    }

    private static void enforceLimits(Stm32CtfEnrichmentContext context,
            Stm32SignaturePack pack, ParserLimits limits) throws DiagnosticException {
        long objects = checkedAdd(context.artifacts().size(), context.functions().size());
        objects = checkedAdd(objects, pack.signatures().size());
        long bytes = 0;
        for (Stm32FirmwareArtifact artifact : context.artifacts()) {
            bytes = checkedAdd(bytes, utf8Length(artifact.exactPart()));
            bytes = checkedAdd(bytes, utf8Length(artifact.id()));
            bytes = checkedAdd(bytes, utf8Length(artifact.sha256()));
        }
        for (Stm32FunctionBytes function : context.functions()) {
            bytes = checkedAdd(bytes, function.bytes().length);
        }
        for (Stm32LibrarySignature signature : pack.signatures()) {
            bytes = checkedAdd(bytes, signature.pattern().length);
            bytes = checkedAdd(bytes, signature.mask().length);
        }
        if (objects > limits.maxObjects() || bytes > limits.maxInputBytes()
                || bytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(error(DiagnosticCode.LIMIT_EXCEEDED,
                "STM32 CTF enrichment input exceeds configured resource limits", null));
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
                "STM32 CTF enrichment resource accounting overflow", null));
        }
    }
}
