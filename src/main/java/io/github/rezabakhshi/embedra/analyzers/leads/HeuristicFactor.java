package io.github.rezabakhshi.embedra.analyzers.leads;

import java.util.Objects;

/**
 * Immutable record representing an individual heuristic factor contributing to a security lead (AN-005).
 *
 * @param factorId unique identifier of the heuristic rule or pattern
 * @param description explanatory summary of the detected indicator
 * @param weight heuristic weight contribution towards overall confidence (typically 0.1 to 1.0)
 */
public record HeuristicFactor(
        String factorId,
        String description,
        double weight) {

    public HeuristicFactor {
        Objects.requireNonNull(factorId, "factorId must not be null");
        Objects.requireNonNull(description, "description must not be null");
        if (factorId.isBlank()) {
            throw new IllegalArgumentException("factorId must not be blank");
        }
        if (weight <= 0.0) {
            throw new IllegalArgumentException("weight must be positive: " + weight);
        }
    }

    public static HeuristicFactor of(String factorId, String description, double weight) {
        return new HeuristicFactor(factorId, description, weight);
    }
}
