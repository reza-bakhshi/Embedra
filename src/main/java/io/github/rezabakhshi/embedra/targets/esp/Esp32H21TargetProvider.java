package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-H21 identity, memory, language, and topology provider. */
public final class Esp32H21TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32H21TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 25, "esp32h21", 1, false,
            "ESP-IDF 662a3be components/soc/esp32h21/include/soc/soc.h", List.of(
                region(IROM, 0x42000000L, 0x43000000L, false, true),
                region(IRAM, 0x40800000L, 0x40850000L, true, true),
                region(RTC_DATA, 0x50000000L, 0x50001000L, true, true)));
    }
}
