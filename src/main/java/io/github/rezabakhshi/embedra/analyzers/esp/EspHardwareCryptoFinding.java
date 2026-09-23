package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Evidence-backed hardware or ROM crypto finding at one firmware use site. */
public record EspHardwareCryptoFinding(
        long address,
        String algorithm,
        EspCryptoEvidenceKind kind,
        Confidence confidence,
        List<Evidence> evidence) {
    public EspHardwareCryptoFinding {
        if (address < 0) {
            throw new IllegalArgumentException("Finding address must be non-negative");
        }
        Objects.requireNonNull(algorithm, "algorithm");
        if (algorithm.isBlank()) {
            throw new IllegalArgumentException("Algorithm must not be blank");
        }
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
        if (evidence.isEmpty()) {
            throw new IllegalArgumentException("Crypto finding requires evidence");
        }
    }
}
