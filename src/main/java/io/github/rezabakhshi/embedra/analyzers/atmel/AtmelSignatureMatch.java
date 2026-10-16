package io.github.rezabakhshi.embedra.analyzers.atmel;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Exact or masked Atmel/Microchip library/runtime routine match with explicit pack provenance. */
public record AtmelSignatureMatch(
        String signatureId,
        String library,
        String subsystem,
        String functionName,
        long address,
        String packIdentity,
        Confidence confidence,
        List<Evidence> evidence) {

    public AtmelSignatureMatch {
        Objects.requireNonNull(signatureId, "signatureId");
        Objects.requireNonNull(library, "library");
        Objects.requireNonNull(subsystem, "subsystem");
        Objects.requireNonNull(functionName, "functionName");
        Objects.requireNonNull(packIdentity, "packIdentity");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
