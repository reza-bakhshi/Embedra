package io.github.rezabakhshi.embedra.analyzers.atmel;

import java.util.List;

/** Deterministic result of one bounded Atmel/Microchip signature-matching pass. */
public record AtmelSignatureMatchReport(
        List<AtmelSignatureMatch> matches,
        List<AtmelSignatureNonMatch> nonMatches,
        int functionsScanned,
        int signaturesIndexed) {

    public AtmelSignatureMatchReport {
        matches = List.copyOf(matches);
        nonMatches = List.copyOf(nonMatches);
        if (functionsScanned < 0 || signaturesIndexed < 0) {
            throw new IllegalArgumentException("Signature match counts must be non-negative");
        }
    }
}
