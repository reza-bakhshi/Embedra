package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.List;
import java.util.Objects;

/** Deterministic pure result from all T023 ESP-IDF enrichment detectors. */
public record EspIdfEnrichmentReport(
        EspIdfMetadata idfMetadata,
        List<EspLoggingCall> loggingCalls,
        List<EspFreeRtosEvidence> freeRtosEvidence,
        List<EspLibraryMatch> libraryMatches,
        List<String> detectorsRun,
        List<String> unsupportedCapabilities) {
    public EspIdfEnrichmentReport {
        Objects.requireNonNull(idfMetadata, "idfMetadata");
        loggingCalls = List.copyOf(loggingCalls);
        freeRtosEvidence = List.copyOf(freeRtosEvidence);
        libraryMatches = List.copyOf(libraryMatches);
        detectorsRun = List.copyOf(detectorsRun);
        unsupportedCapabilities = List.copyOf(unsupportedCapabilities);
    }
}
