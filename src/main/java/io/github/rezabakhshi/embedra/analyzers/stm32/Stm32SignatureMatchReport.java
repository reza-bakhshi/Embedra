package io.github.rezabakhshi.embedra.analyzers.stm32;

import java.util.List;

/** Deterministic result of one bounded signature-matching pass. */
public record Stm32SignatureMatchReport(
        List<Stm32SignatureMatch> matches,
        List<Stm32SignatureNonMatch> nonMatches,
        int functionsScanned,
        int signaturesIndexed) {
    public Stm32SignatureMatchReport {
        matches = List.copyOf(matches);
        nonMatches = List.copyOf(nonMatches);
        if (functionsScanned < 0 || signaturesIndexed < 0) {
            throw new IllegalArgumentException("Signature match counts must be non-negative");
        }
    }
}
