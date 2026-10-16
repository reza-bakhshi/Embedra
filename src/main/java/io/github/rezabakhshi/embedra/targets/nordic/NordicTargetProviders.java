package io.github.rezabakhshi.embedra.targets.nordic;

import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Registry and resolver for Nordic Semiconductor target providers.
 */
public final class NordicTargetProviders {

    private static final Map<String, NordicTargetProvider> PROVIDERS_BY_ID;

    private static final Map<String, NordicTargetProvider> PROVIDERS_BY_SERIES;

    static {
        Map<String, NordicTargetProvider> byId = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, NordicTargetProvider> bySeries = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        List<NordicTargetProvider> providers = List.of(
            new Nrf51TargetProvider(),
            new Nrf52TargetProvider(),
            new Nrf53TargetProvider(),
            new Nrf54TargetProvider(),
            new Nrf91TargetProvider()
        );

        for (NordicTargetProvider provider : providers) {
            byId.put(provider.providerId(), provider);
            bySeries.put(provider.series(), provider);
        }

        PROVIDERS_BY_ID = Map.copyOf(byId);
        PROVIDERS_BY_SERIES = Map.copyOf(bySeries);
    }

    private NordicTargetProviders() {
    }

    public static Optional<NordicTargetProvider> findById(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(PROVIDERS_BY_ID.get(providerId.trim()));
    }

    public static Optional<NordicTargetProvider> findBySeries(String series) {
        if (series == null || series.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(PROVIDERS_BY_SERIES.get(series.trim()));
    }

    public static Optional<NordicTargetProvider> findForPart(NordicPartRecord part) {
        if (part == null) {
            return Optional.empty();
        }
        return findBySeries(part.series());
    }

    public static List<NordicTargetProvider> all() {
        return List.copyOf(PROVIDERS_BY_ID.values());
    }
}
