package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.List;

/** Deterministic crypto detector output including negative coverage disclosure. */
public record EspHardwareCryptoReport(
        List<EspHardwareCryptoFinding> findings,
        List<String> detectorsRan,
        List<String> unsupportedAlgorithms) {
    public EspHardwareCryptoReport {
        findings = List.copyOf(findings);
        detectorsRan = List.copyOf(detectorsRan);
        unsupportedAlgorithms = List.copyOf(unsupportedAlgorithms);
    }
}
