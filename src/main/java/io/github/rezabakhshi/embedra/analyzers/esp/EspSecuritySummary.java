package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.List;
import java.util.Objects;

/** Deterministic security summary that keeps image evidence separate from eFuses. */
public record EspSecuritySummary(
        EspImageHashEvidence imageHash,
        List<EspSecureBootSignatureEvidence> signatureBlocks,
        EspFlashEncryptionEvidence flashEncryption,
        EspNvsEncryptionEvidence nvsEncryption,
        EspSecurityState secureBootEfuseState,
        EspSecurityState flashEncryptionEfuseState,
        List<String> detectorsRun) {
    public EspSecuritySummary {
        Objects.requireNonNull(imageHash, "imageHash");
        signatureBlocks = List.copyOf(signatureBlocks);
        Objects.requireNonNull(flashEncryption, "flashEncryption");
        Objects.requireNonNull(nvsEncryption, "nvsEncryption");
        Objects.requireNonNull(secureBootEfuseState, "secureBootEfuseState");
        Objects.requireNonNull(flashEncryptionEfuseState, "flashEncryptionEfuseState");
        detectorsRun = List.copyOf(detectorsRun);
    }

    /** Offline images cannot establish that secure boot is enabled in hardware. */
    public boolean secureBootEnabled() {
        return false;
    }
}
