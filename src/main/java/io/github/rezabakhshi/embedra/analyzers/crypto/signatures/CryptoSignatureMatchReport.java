package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable report produced by cryptographic library signature matching (AN-010, AN-011).
 */
public record CryptoSignatureMatchReport(
        List<CryptoFinding> findings,
        int totalEvaluated,
        int totalMatched) {

    public CryptoSignatureMatchReport {
        Objects.requireNonNull(findings, "findings must not be null");
        if (totalEvaluated < 0 || totalMatched < 0) {
            throw new IllegalArgumentException("Counts must be non-negative");
        }
        findings = Collections.unmodifiableList(List.copyOf(findings));
    }
}
