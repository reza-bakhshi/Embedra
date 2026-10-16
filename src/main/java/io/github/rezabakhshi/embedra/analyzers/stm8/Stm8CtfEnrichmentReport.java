package io.github.rezabakhshi.embedra.analyzers.stm8;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import java.util.List;
import java.util.Objects;

/**
 * Deterministic report emitted by the STM8 CTF enrichment and signature analysis pipeline.
 */
public record Stm8CtfEnrichmentReport(
        Stm8SignatureMatchReport signatureReport,
        List<ExtractedString> extractedStrings,
        List<CtfEntity> ctfEntities,
        List<SecurityLead> securityLeads,
        List<String> detectorsRun) {

    public Stm8CtfEnrichmentReport {
        Objects.requireNonNull(signatureReport, "signatureReport must not be null");
        extractedStrings = List.copyOf(extractedStrings);
        ctfEntities = List.copyOf(ctfEntities);
        securityLeads = List.copyOf(securityLeads);
        detectorsRun = List.copyOf(detectorsRun);
    }
}
