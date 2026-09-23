package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** A resolved logging call use-site, distinct from its target function. */
public record EspLoggingCall(
        long callAddress, long callerAddress, String targetName,
        Optional<String> tag, Optional<String> format,
        Confidence confidence, List<Evidence> evidence) {
    public EspLoggingCall {
        Objects.requireNonNull(targetName, "targetName");
        Objects.requireNonNull(tag, "tag");
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
