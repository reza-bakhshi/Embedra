package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/**
 * Composite enrichment report aggregating TinyUSB, lwIP, and CYW43 component detections.
 */
public record RpComponentEnrichmentReport(
        RpTinyUsbMatch tinyUsb,
        RpLwIpMatch lwIp,
        RpCyw43Match cyw43,
        List<Evidence> overallEvidence) {

    public RpComponentEnrichmentReport {
        Objects.requireNonNull(tinyUsb, "tinyUsb must not be null");
        Objects.requireNonNull(lwIp, "lwIp must not be null");
        Objects.requireNonNull(cyw43, "cyw43 must not be null");
        Objects.requireNonNull(overallEvidence, "overallEvidence must not be null");
        overallEvidence = List.copyOf(overallEvidence);
    }

    public boolean hasAnyComponentDetected() {
        return tinyUsb.detected() || lwIp.detected() || cyw43.detected();
    }
}
