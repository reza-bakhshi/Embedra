package io.github.rezabakhshi.embedra.targets.esp;

import java.util.List;

/** Registry of ESP providers backed by maintained chip, architecture, and memory evidence. */
public final class EspTargetProviders {
    private EspTargetProviders() {
    }

    public static List<EspTargetProvider> implemented() {
        EspressifChipIdRegistry chipIds = EspressifChipIdRegistry.loadBundled();
        return List.of(new Esp32TargetProvider(chipIds), new Esp32S2TargetProvider(chipIds),
            new Esp32S3TargetProvider(chipIds), new Esp32C3TargetProvider(chipIds),
            new Esp32S31TargetProvider(chipIds), new Esp32P4TargetProvider(chipIds),
            new Esp32C2TargetProvider(chipIds), new Esp32C5TargetProvider(chipIds),
            new Esp32C6TargetProvider(chipIds), new Esp32C61TargetProvider(chipIds),
            new Esp32E22TargetProvider(chipIds), new Esp32H2TargetProvider(chipIds),
            new Esp32H21TargetProvider(chipIds), new Esp32H4TargetProvider(chipIds));
    }

    public static EspTargetResolver resolver() {
        return new EspTargetResolver(implemented());
    }
}
