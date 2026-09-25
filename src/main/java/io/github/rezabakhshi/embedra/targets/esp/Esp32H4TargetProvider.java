package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-H4 identity, memory, language, and topology provider. */
public final class Esp32H4TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32H4TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 28, "esp32h4", 2, false,
            "ESP-IDF 662a3be components/soc/esp32h4/include/soc/soc.h", List.of(
                region(IROM, 0x42000000L, 0x44000000L, false, true),
                region(IRAM, 0x40810000L, 0x40860000L, true, true),
                region(RTC_DATA, 0x50000000L, 0x50004000L, true, true)));
    }
}
