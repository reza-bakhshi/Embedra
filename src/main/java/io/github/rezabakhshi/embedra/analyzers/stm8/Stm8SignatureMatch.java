package io.github.rezabakhshi.embedra.analyzers.stm8;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Exact or masked STM8 library/runtime routine match with explicit pack provenance. */
public record Stm8SignatureMatch(
        String signatureId,
        String library,
        String functionName,
        long address,
        String packIdentity,
        Confidence confidence,
        List<Evidence> evidence) {

    public Stm8SignatureMatch {
        Objects.requireNonNull(signatureId, "signatureId");
        Objects.requireNonNull(library, "library");
        Objects.requireNonNull(functionName, "functionName");
        Objects.requireNonNull(packIdentity, "packIdentity");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
