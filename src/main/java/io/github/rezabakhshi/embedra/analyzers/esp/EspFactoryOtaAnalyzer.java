package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.formats.esp.EspPartitionEntry;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Bounded factory/OTA diff and conservative ESP-specific CTF lead scanner. */
public final class EspFactoryOtaAnalyzer {
    public EspFactoryOtaReport analyze(EspFactoryOtaContext context,
            ParserLimits limits, CancellationToken cancellation)
            throws DiagnosticException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        enforceLimits(context, limits);

        EspArtifactDiff diff = diff(context.factory(), context.ota());
        List<EspCtfFinding> findings = new ArrayList<>();
        invalidHash(context.ota(), findings);
        nvsKeys(context.partitions(), findings, cancellation);
        secureVersion(context.factory(), context.ota(), findings);
        findings.sort(Comparator.comparing(EspCtfFinding::code)
            .thenComparing(finding -> finding.sourceRange()
                .map(range -> range.offset()).orElse(-1L)));
        return new EspFactoryOtaReport(diff, findings,
            List.of("esp-factory-ota-diff", "esp-image-hash-regression",
                "esp-nvs-key-partition", "esp-secure-version-regression"));
    }

    private static EspArtifactDiff diff(Optional<EspFirmwareArtifact> factory,
            Optional<EspFirmwareArtifact> ota) {
        EspArtifactChangeKind kind;
        if (factory.isEmpty()) {
            kind = EspArtifactChangeKind.ADDED;
        }
        else if (ota.isEmpty()) {
            kind = EspArtifactChangeKind.REMOVED;
        }
        else if (!factory.orElseThrow().sha256().equals(ota.orElseThrow().sha256())) {
            kind = EspArtifactChangeKind.MODIFIED;
        }
        else if (!factory.orElseThrow().flashRange().equals(ota.orElseThrow().flashRange())) {
            kind = EspArtifactChangeKind.MOVED;
        }
        else {
            kind = EspArtifactChangeKind.UNCHANGED;
        }
        return new EspArtifactDiff(kind, Confidence.VERIFIED,
            List.of(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "validated ESP workspace", "Compared SHA-256 and physical flash ranges")));
    }

    private static void invalidHash(Optional<EspFirmwareArtifact> ota,
            List<EspCtfFinding> findings) {
        if (ota.isPresent()
            && ota.orElseThrow().imageHashState() == EspImageHashState.INVALID) {
            findings.add(new EspCtfFinding("ESP_INVALID_IMAGE_HASH", "HIGH",
                Confidence.VERIFIED,
                "Candidate OTA image has a mismatched appended image digest",
                Optional.empty(), false, List.of(new Evidence(
                    EvidenceKind.VERIFIED_CHECKSUM, "ESP image footer",
                    "Stored and calculated image digests differ"))));
        }
    }

    private static void nvsKeys(List<EspPartitionEntry> partitions,
            List<EspCtfFinding> findings, CancellationToken cancellation)
            throws DiagnosticException {
        for (EspPartitionEntry partition : partitions) {
            cancellation.throwIfCancellationRequested();
            if (partition.type() == 1 && partition.subtype() == 4
                && !partition.encrypted()) {
                findings.add(new EspCtfFinding("ESP_NVS_KEYS_PLAINTEXT", "HIGH",
                    Confidence.DERIVED,
                    "Unencrypted NVS-key partition is present; contents remain redacted",
                    Optional.of(partition.sourceRange()), true, List.of(new Evidence(
                        EvidenceKind.DOCUMENTED_FIELD, "ESP partition table",
                        "NVS-key subtype is present without the encrypted flag"))));
            }
        }
    }

    private static void secureVersion(Optional<EspFirmwareArtifact> factory,
            Optional<EspFirmwareArtifact> ota, List<EspCtfFinding> findings) {
        if (factory.isEmpty() || ota.isEmpty()
            || factory.orElseThrow().secureVersion().isEmpty()
            || ota.orElseThrow().secureVersion().isEmpty()) {
            return;
        }
        long baseline = factory.orElseThrow().secureVersion().orElseThrow();
        long candidate = ota.orElseThrow().secureVersion().orElseThrow();
        if (candidate < baseline) {
            findings.add(new EspCtfFinding("ESP_SECURE_VERSION_ROLLBACK", "HIGH",
                Confidence.VERIFIED,
                "Candidate OTA secure version is lower than the factory secure version",
                Optional.empty(), false, List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD, "esp_app_desc_t",
                    "Compared validated numeric secure-version fields"))));
        }
    }

    private static void enforceLimits(EspFactoryOtaContext context,
            ParserLimits limits) throws DiagnosticException {
        long objects = context.partitions().size()
            + (context.factory().isPresent() ? 1L : 0L)
            + (context.ota().isPresent() ? 1L : 0L);
        long bytes = context.partitions().stream()
            .mapToLong(partition -> utf8Length(partition.label())).sum();
        if (context.factory().isPresent()) {
            bytes = checkedAdd(bytes, artifactBytes(context.factory().orElseThrow()));
        }
        if (context.ota().isPresent()) {
            bytes = checkedAdd(bytes, artifactBytes(context.ota().orElseThrow()));
        }
        if (objects > limits.maxObjects() || bytes > limits.maxInputBytes()
            || bytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP factory/OTA analysis exceeds configured resource limits", null));
        }
    }

    private static long artifactBytes(EspFirmwareArtifact artifact) {
        return utf8Length(artifact.id()) + utf8Length(artifact.sha256())
            + artifact.partitionLabel().map(EspFactoryOtaAnalyzer::utf8Length).orElse(0)
            + artifact.version().map(EspFactoryOtaAnalyzer::utf8Length).orElse(0);
    }

    private static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static long checkedAdd(long left, long right) throws DiagnosticException {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException exception) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP factory/OTA resource accounting overflow", null));
        }
    }
}
