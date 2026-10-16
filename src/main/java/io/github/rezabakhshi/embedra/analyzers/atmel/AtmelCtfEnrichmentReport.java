package io.github.rezabakhshi.embedra.analyzers.atmel;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import java.util.List;
import java.util.Objects;

/**
 * Deterministic report emitted by the Atmel/Microchip CTF enrichment and signature analysis pipeline.
 */
public record AtmelCtfEnrichmentReport(
        AtmelSignatureMatchReport signatureReport,
        List<ExtractedString> extractedStrings,
        List<RecoveredStackString> stackStrings,
        List<CtfEntity> ctfEntities,
        List<SecurityLead> securityLeads,
        List<String> detectorsRun) {

    public AtmelCtfEnrichmentReport {
        Objects.requireNonNull(signatureReport, "signatureReport must not be null");
        extractedStrings = List.copyOf(extractedStrings);
        stackStrings = List.copyOf(stackStrings);
        ctfEntities = List.copyOf(ctfEntities);
        securityLeads = List.copyOf(securityLeads);
        detectorsRun = List.copyOf(detectorsRun);
    }
}
