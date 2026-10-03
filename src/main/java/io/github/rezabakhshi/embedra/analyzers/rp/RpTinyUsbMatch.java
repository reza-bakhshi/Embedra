package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/**
 * Result of detecting TinyUSB stack components and descriptors.
 */
public record RpTinyUsbMatch(
        boolean detected,
        List<UsbDescriptorInfo> descriptors,
        List<String> apis,
        Confidence confidence,
        List<Evidence> evidence) {

    public RpTinyUsbMatch {
        Objects.requireNonNull(descriptors, "descriptors must not be null");
        Objects.requireNonNull(apis, "apis must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(evidence, "evidence must not be null");
        descriptors = List.copyOf(descriptors);
        apis = List.copyOf(apis);
        evidence = List.copyOf(evidence);
    }

    public static RpTinyUsbMatch notDetected() {
        return new RpTinyUsbMatch(false, List.of(), List.of(), Confidence.UNKNOWN, List.of());
    }
}
