package io.github.rezabakhshi.embedra.targets.atmel;

import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Registry and resolver for Atmel / Microchip target providers.
 */
public final class AtmelTargetProviders {

    private static final Map<String, AtmelTargetProvider> PROVIDERS_BY_ID;

    private static final Map<String, AtmelTargetProvider> PROVIDERS_BY_SERIES;

    static {
        Map<String, AtmelTargetProvider> byId = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, AtmelTargetProvider> bySeries = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        List<AtmelTargetProvider> providers = List.of(
            new AtmegaTargetProvider(),
            new AttinyTargetProvider(),
            new AvrDxTargetProvider(),
            new SamdTargetProvider(),
            new SameTargetProvider()
        );

        for (AtmelTargetProvider provider : providers) {
            byId.put(provider.providerId(), provider);
            bySeries.put(provider.series(), provider);
        }

        PROVIDERS_BY_ID = Map.copyOf(byId);
        PROVIDERS_BY_SERIES = Map.copyOf(bySeries);
    }

    private AtmelTargetProviders() {
    }

    public static Optional<AtmelTargetProvider> findById(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(PROVIDERS_BY_ID.get(providerId.trim()));
    }

    public static Optional<AtmelTargetProvider> findBySeries(String series) {
        if (series == null || series.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(PROVIDERS_BY_SERIES.get(series.trim()));
    }

    public static Optional<AtmelTargetProvider> findForPart(AtmelPartRecord part) {
        if (part == null) {
            return Optional.empty();
        }
        return findBySeries(part.series());
    }

    public static List<AtmelTargetProvider> all() {
        return List.copyOf(PROVIDERS_BY_ID.values());
    }
}
