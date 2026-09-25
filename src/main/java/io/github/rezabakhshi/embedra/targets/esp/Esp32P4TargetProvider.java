package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-P4 identity, memory, language, and topology provider. */
public final class Esp32P4TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32P4TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 18, "esp32p4", 2, true,
            "ESP-IDF 662a3be components/soc/esp32p4/include/soc/soc.h", List.of(
                region(IROM, 0x40000000L, 0x44000000L, false, true),
                region(IRAM, 0x4ff00000L, 0x4ffc0000L, true, true),
                region(RTC_DATA, 0x50108000L, 0x50110000L, true, true)));
    }
}
