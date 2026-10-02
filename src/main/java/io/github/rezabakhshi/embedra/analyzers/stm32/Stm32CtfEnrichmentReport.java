package io.github.rezabakhshi.embedra.analyzers.stm32;

import java.util.List;
import java.util.Objects;

/** Immutable deterministic T048 STM32 CTF enrichment report. */
public record Stm32CtfEnrichmentReport(
        Stm32SignatureMatchReport signatureReport,
        Stm32SecurityEvidence securityEvidence,
        List<Stm32CtfLead> leads,
        List<String> detectorsRun,
        List<String> unsupportedCapabilities) {
    public Stm32CtfEnrichmentReport {
        Objects.requireNonNull(signatureReport, "signatureReport");
        Objects.requireNonNull(securityEvidence, "securityEvidence");
        leads = List.copyOf(leads);
        detectorsRun = List.copyOf(detectorsRun);
        unsupportedCapabilities = List.copyOf(unsupportedCapabilities);
    }
}
