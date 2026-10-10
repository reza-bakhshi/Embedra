package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.Objects;

/**
 * Explicit record of an unsupported cryptographic implementation or variant (AN-012, AN-015).
 *
 * <p>Ensures that absence of a detector or coverage limitation is never confused with absence of crypto.</p>
 *
 * @param sampleId identifier of the corpus sample
 * @param platformName target device or silicon family name
 * @param toolchainOrIsa compiler, optimization, or target architecture
 * @param targetAlgorithm cryptographic algorithm intended by the sample
 * @param reason technical categorization of why this variant is unsupported
 * @param description detailed technical explanation of the variant
 * @param plannedMitigation roadmap or milestone to address or reason for permanent exclusion
 */
public record UnsupportedCase(
        String sampleId,
        String platformName,
        String toolchainOrIsa,
        CryptoAlgorithm targetAlgorithm,
        UnsupportedReason reason,
        String description,
        String plannedMitigation) {

    public UnsupportedCase {
        Objects.requireNonNull(sampleId, "sampleId must not be null");
        Objects.requireNonNull(platformName, "platformName must not be null");
        Objects.requireNonNull(toolchainOrIsa, "toolchainOrIsa must not be null");
        Objects.requireNonNull(targetAlgorithm, "targetAlgorithm must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(plannedMitigation, "plannedMitigation must not be null");
    }
}
