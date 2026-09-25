package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-C5 identity, memory, language, and topology provider. */
public final class Esp32C5TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32C5TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 23, "esp32c5", 1, true,
            "ESP-IDF 662a3be components/soc/esp32c5/include/soc/soc.h", List.of(
                region(IROM, 0x42000000L, 0x44000000L, false, true),
                region(IRAM, 0x40800000L, 0x40860000L, true, true),
                region(RTC_DATA, 0x50000000L, 0x50004000L, true, true)));
    }
}
