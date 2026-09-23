package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.formats.esp.EspImageFooter;
import io.github.rezabakhshi.embedra.formats.esp.EspPartitionEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.zip.CRC32;

/** Bounded parsing of offline ESP image security evidence. */
public final class EspSecuritySummaryAnalyzer {
    private static final int SIGNATURE_SECTOR_SIZE = 4096;

    private static final int SIGNATURE_BLOCK_SIZE = 1216;

    private static final int SIGNATURE_CRC_INPUT_SIZE = 1196;

    private static final int SIGNATURE_MAGIC = 0xe7;

    public EspSecuritySummary analyze(EspSecurityContext context, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        byte[] region = context.signatureRegion();
        if (region.length > limits.maxInputBytes()
            || region.length > limits.maxAllocationBytes()
            || context.partitions().size() + 3L > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP security-summary input exceeds configured resource limits", null));
        }

        EspImageHashEvidence hash = imageHash(context.imageFooter());
        List<EspSecureBootSignatureEvidence> signatures = signatures(context, region,
            cancellation);
        EspFlashEncryptionEvidence flash = flashEncryption(context.partitions(),
            cancellation);
        EspNvsEncryptionEvidence nvs = nvsEncryption(context.partitions(), cancellation);
        return new EspSecuritySummary(hash, signatures, flash, nvs,
            EspSecurityState.UNAVAILABLE, EspSecurityState.UNAVAILABLE,
            List.of("image-sha256", "nvs-encryption-indicators",
                "partition-encryption-flags", "secure-boot-v2-signature-blocks"));
    }

    private static EspImageHashEvidence imageHash(EspImageFooter footer) {
        if (!footer.digestPresent()) {
            return new EspImageHashEvidence(EspImageHashState.ABSENT,
                Confidence.UNKNOWN, List.of());
        }
        EspImageHashState state = footer.digestValid()
            ? EspImageHashState.VERIFIED : EspImageHashState.INVALID;
        return new EspImageHashEvidence(state, Confidence.VERIFIED,
            List.of(new Evidence(EvidenceKind.VERIFIED_CHECKSUM, "ESP image footer",
                footer.digestValid() ? "Appended SHA-256 matches calculated image digest"
                    : "Appended SHA-256 does not match calculated image digest")));
    }

    private static List<EspSecureBootSignatureEvidence> signatures(
            EspSecurityContext context, byte[] region, CancellationToken cancellation)
            throws DiagnosticException {
        List<EspSecureBootSignatureEvidence> results = new ArrayList<>();
        int available = Math.min(region.length, SIGNATURE_SECTOR_SIZE);
        for (int offset = 0; offset + SIGNATURE_BLOCK_SIZE <= available;
                offset += SIGNATURE_BLOCK_SIZE) {
            cancellation.throwIfCancellationRequested();
            int magic = region[offset] & 0xff;
            int version = region[offset + 1] & 0xff;
            if (magic != SIGNATURE_MAGIC || version != 2
                || storedUnsignedInt(region, offset + SIGNATURE_CRC_INPUT_SIZE)
                    != crc32(region, offset, SIGNATURE_CRC_INPUT_SIZE)) {
                continue;
            }
            results.add(new EspSecureBootSignatureEvidence(
                context.signatureRegionOffset() + offset, EspSecureBootScheme.RSA_V2,
                EspVerificationState.UNKNOWN, Confidence.DERIVED,
                List.of(new Evidence(EvidenceKind.DERIVED_RULE,
                    "ESP-IDF v6.0 esp32s3/rom/secure_boot.h",
                    "Signature-block magic, scheme, size, and CRC are valid; signature not verified"))));
        }
        return List.copyOf(results);
    }

    private static EspFlashEncryptionEvidence flashEncryption(
            List<EspPartitionEntry> partitions, CancellationToken cancellation)
            throws DiagnosticException {
        List<String> labels = new ArrayList<>();
        for (EspPartitionEntry partition : partitions) {
            cancellation.throwIfCancellationRequested();
            if (partition.encrypted()) {
                labels.add(partition.label());
            }
        }
        EspSecurityState state = labels.isEmpty()
            ? EspSecurityState.NOT_INDICATED : EspSecurityState.INDICATED;
        List<Evidence> evidence = labels.isEmpty() ? List.of()
            : List.of(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                "ESP partition table", "Encrypted partition flag is set"));
        return new EspFlashEncryptionEvidence(state, labels,
            labels.isEmpty() ? Confidence.UNKNOWN : Confidence.DERIVED, evidence);
    }

    private static EspNvsEncryptionEvidence nvsEncryption(
            List<EspPartitionEntry> partitions, CancellationToken cancellation)
            throws DiagnosticException {
        boolean keyPartition = false;
        boolean encryptedNvs = false;
        for (EspPartitionEntry partition : partitions) {
            cancellation.throwIfCancellationRequested();
            keyPartition |= partition.type() == 1 && partition.subtype() == 4;
            encryptedNvs |= partition.type() == 1 && partition.subtype() == 2
                && partition.encrypted();
        }
        EspNvsEncryptionState state = keyPartition
            ? EspNvsEncryptionState.KEY_PARTITION_PRESENT
            : encryptedNvs ? EspNvsEncryptionState.ENCRYPTED_PARTITION_INDICATED
                : EspNvsEncryptionState.NOT_INDICATED;
        List<Evidence> evidence = state == EspNvsEncryptionState.NOT_INDICATED
            ? List.of() : List.of(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                "ESP partition table", "NVS encryption-related partition metadata is present"));
        return new EspNvsEncryptionEvidence(state,
            state == EspNvsEncryptionState.NOT_INDICATED
                ? Confidence.UNKNOWN : Confidence.DERIVED, evidence);
    }

    private static long crc32(byte[] bytes, int offset, int length) {
        CRC32 crc = new CRC32();
        crc.update(bytes, offset, length);
        return crc.getValue();
    }

    private static long storedUnsignedInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffL) | (bytes[offset + 1] & 0xffL) << 8
            | (bytes[offset + 2] & 0xffL) << 16 | (bytes[offset + 3] & 0xffL) << 24;
    }
}
