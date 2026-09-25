package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import java.util.List;

/** Independent ESP32-C61 identity, memory, language, and topology provider. */
public final class Esp32C61TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32C61TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 20, "esp32c61", 1, false,
            "ESP-IDF 662a3be components/soc/esp32c61/include/soc/soc.h", List.of(
                region(IROM, 0x42000000L, 0x44000000L, false, true),
                region(IRAM, 0x40800000L, 0x40850000L, true, true)));
    }
}
