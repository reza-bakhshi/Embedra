package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Exact or masked function-signature match with explicit pack provenance. */
public record EspLibraryMatch(
        String signatureId, String library, String functionName, long address,
        String packIdentity, Confidence confidence, List<Evidence> evidence) {
    public EspLibraryMatch {
        Objects.requireNonNull(signatureId, "signatureId");
        Objects.requireNonNull(library, "library");
        Objects.requireNonNull(functionName, "functionName");
        Objects.requireNonNull(packIdentity, "packIdentity");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
