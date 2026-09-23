package io.github.rezabakhshi.embedra.targets.esp.catalog;

import java.util.List;
import java.util.Objects;

/** Exact, ambiguous, or unknown result without silently selecting a target. */
public record EspCatalogResolution(
        EspCatalogResolutionStatus status, String query, List<EspCatalogRecord> candidates) {
    public EspCatalogResolution {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(query, "query");
        candidates = List.copyOf(candidates);
        if (query.isBlank() || (status == EspCatalogResolutionStatus.EXACT && candidates.size() != 1)
            || (status == EspCatalogResolutionStatus.AMBIGUOUS && candidates.size() < 2)
            || (status == EspCatalogResolutionStatus.UNKNOWN && !candidates.isEmpty())) {
            throw new IllegalArgumentException("Catalog resolution is inconsistent");
        }
    }

    public EspCatalogRecord requireExact() {
        if (status != EspCatalogResolutionStatus.EXACT) {
            throw new IllegalStateException("Catalog query is not exact: " + query);
        }
        return candidates.getFirst();
    }
}
