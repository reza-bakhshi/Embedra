package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Exact or masked STM32 library-function match with explicit pack provenance. */
public record Stm32SignatureMatch(
        String signatureId, String library, String functionName, long address,
        String packIdentity, Confidence confidence, List<Evidence> evidence) {
    public Stm32SignatureMatch {
        Objects.requireNonNull(signatureId, "signatureId");
        Objects.requireNonNull(library, "library");
        Objects.requireNonNull(functionName, "functionName");
        Objects.requireNonNull(packIdentity, "packIdentity");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
