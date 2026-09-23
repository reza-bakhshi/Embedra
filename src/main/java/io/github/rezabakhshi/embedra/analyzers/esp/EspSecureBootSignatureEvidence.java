package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;

/** Structurally validated signature block, separate from cryptographic verification. */
public record EspSecureBootSignatureEvidence(
        long sourceOffset, EspSecureBootScheme scheme,
        EspVerificationState cryptographicVerification,
        Confidence confidence, List<Evidence> evidence) {
    public EspSecureBootSignatureEvidence {
        Objects.requireNonNull(scheme, "scheme");
        Objects.requireNonNull(cryptographicVerification, "cryptographicVerification");
        Objects.requireNonNull(confidence, "confidence");
        evidence = List.copyOf(evidence);
    }
}
