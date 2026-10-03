package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Result of detecting Infineon CYW43439 wireless driver components.
 */
public record RpCyw43Match(
        boolean detected,
        String chipModel,
        Optional<String> busInterface,
        boolean firmwareBlobPresent,
        List<String> countryCodes,
        List<String> apis,
        Confidence confidence,
        List<Evidence> evidence) {

    public RpCyw43Match {
        Objects.requireNonNull(chipModel, "chipModel must not be null");
        Objects.requireNonNull(busInterface, "busInterface must not be null");
        Objects.requireNonNull(countryCodes, "countryCodes must not be null");
        Objects.requireNonNull(apis, "apis must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(evidence, "evidence must not be null");
        countryCodes = List.copyOf(countryCodes);
        apis = List.copyOf(apis);
        evidence = List.copyOf(evidence);
    }

    public static RpCyw43Match notDetected() {
        return new RpCyw43Match(
                false, "Infineon CYW43439", Optional.empty(), false, List.of(), List.of(),
                Confidence.UNKNOWN, List.of());
    }
}
