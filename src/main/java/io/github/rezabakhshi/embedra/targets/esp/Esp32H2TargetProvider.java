package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-H2 identity, memory, language, and topology provider. */
public final class Esp32H2TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32H2TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 16, "esp32h2", 1, false,
            "ESP-IDF 662a3be components/soc/esp32h2/include/soc/soc.h", List.of(
                region(IROM, 0x42000000L, 0x43000000L, false, true),
                region(IRAM, 0x40800000L, 0x40850000L, true, true),
                region(RTC_DATA, 0x50000000L, 0x50001000L, true, true)));
    }
}
