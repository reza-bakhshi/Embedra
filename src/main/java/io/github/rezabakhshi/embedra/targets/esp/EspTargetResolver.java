package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Exact chip-ID resolver for independently evidenced ESP target providers. */
public final class EspTargetResolver {
    private final Map<Integer, EspTargetProvider> providers;

    public EspTargetResolver(List<? extends EspTargetProvider> providers) {
        Objects.requireNonNull(providers, "providers");
        HashMap<Integer, EspTargetProvider> indexed = new HashMap<>();
        for (EspTargetProvider provider : providers) {
            Objects.requireNonNull(provider, "provider");
            if (indexed.putIfAbsent(provider.chipId(), provider) != null) {
                throw new IllegalArgumentException(
                    "Duplicate ESP target provider chip ID: " + provider.chipId());
            }
        }
        this.providers = Map.copyOf(indexed);
    }

    public Optional<EspTargetResolution> resolve(EspImage image) {
        Objects.requireNonNull(image, "image");
        EspTargetProvider provider = providers.get(image.header().chipId());
        if (provider == null) {
            return Optional.empty();
        }
        SupportDecision support = provider.supports(image);
        if (!support.supported()) {
            return Optional.empty();
        }
        return Optional.of(new EspTargetResolution(provider, support,
            provider.topology(image)));
    }
}
