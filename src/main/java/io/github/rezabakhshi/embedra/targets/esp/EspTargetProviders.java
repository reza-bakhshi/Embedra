package io.github.rezabakhshi.embedra.targets.esp;

import java.util.List;

/** Registry of ESP providers that have independent fixtures and pack evidence. */
public final class EspTargetProviders {
    private EspTargetProviders() {
    }

    public static List<EspTargetProvider> implemented() {
        EspressifChipIdRegistry chipIds = EspressifChipIdRegistry.loadBundled();
        return List.of(new Esp32TargetProvider(chipIds), new Esp32S2TargetProvider(chipIds),
            new Esp32S3TargetProvider(chipIds), new Esp32C3TargetProvider(chipIds));
    }

    public static EspTargetResolver resolver() {
        return new EspTargetResolver(implemented());
    }
}
