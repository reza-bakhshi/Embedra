package io.github.rezabakhshi.embedra.analyzers.stm8;

import java.util.List;

/** Deterministic result of one bounded STM8 signature-matching pass. */
public record Stm8SignatureMatchReport(
        List<Stm8SignatureMatch> matches,
        List<Stm8SignatureNonMatch> nonMatches,
        int functionsScanned,
        int signaturesIndexed) {

    public Stm8SignatureMatchReport {
        matches = List.copyOf(matches);
        nonMatches = List.copyOf(nonMatches);
        if (functionsScanned < 0 || signaturesIndexed < 0) {
            throw new IllegalArgumentException("Signature match counts must be non-negative");
        }
    }
}
