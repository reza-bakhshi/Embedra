package io.github.rezabakhshi.embedra.analyzers.leads;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of a candidate security lead (AN-005, AN-006).
 *
 * <p>Under requirement AN-005, candidate password/token comparisons, hidden commands,
 * debug shells, OTA endpoints, and authorization branches are treated as ranked leads,
 * not verified facts.</p>
 *
 * @param id unique lead identifier
 * @param category lead classification category
 * @param confidence heuristic confidence rating
 * @param confidenceScore normalized heuristic confidence score between 0.0 and 1.0
 * @param severity triage severity ranking
 * @param address program memory address where the lead was detected
 * @param symbol optional symbol or function name associated with the lead
 * @param target specific target string, command, endpoint URL, or comparison operand
 * @param description explanatory summary of the lead finding
 * @param heuristicFactors list of contributing heuristic factors
 * @param attributes structured metadata attributes
 * @param secret true if the lead contains candidate sensitive or secret material requiring redaction (AN-008)
 */
public record SecurityLead(
        String id,
        LeadCategory category,
        LeadConfidence confidence,
        double confidenceScore,
        LeadSeverity severity,
        long address,
        String symbol,
        String target,
        String description,
        List<HeuristicFactor> heuristicFactors,
        Map<String, String> attributes,
        boolean secret) {

    public SecurityLead {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        if (address < 0) {
            throw new IllegalArgumentException("Address must be non-negative: " + address);
        }
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(description, "description must not be null");
        heuristicFactors = heuristicFactors == null ? List.of() : List.copyOf(heuristicFactors);
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(attributes));
    }

    /**
     * Returns the target value, masked if secret and masking is requested (AN-008).
     *
     * @param maskSecrets whether secrets should be redacted
     * @return redacted string or raw target
     */
    public String maskedTarget(boolean maskSecrets) {
        if (maskSecrets && secret) {
            return "[REDACTED_SECRET]";
        }
        return target;
    }
}
