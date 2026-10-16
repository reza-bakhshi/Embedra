package io.github.rezabakhshi.embedra.analyzers.nordic;

import java.util.List;

/** Deterministic result of one bounded Nordic signature-matching pass. */
public record NordicSignatureMatchReport(
        List<NordicSignatureMatch> matches,
        List<NordicSignatureNonMatch> nonMatches,
        int functionsScanned,
        int signaturesIndexed) {

    public NordicSignatureMatchReport {
        matches = List.copyOf(matches);
        nonMatches = List.copyOf(nonMatches);
        if (functionsScanned < 0 || signaturesIndexed < 0) {
            throw new IllegalArgumentException("Signature match counts must be non-negative");
        }
    }
}
