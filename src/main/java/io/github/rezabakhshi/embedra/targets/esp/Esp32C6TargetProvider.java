package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-C6 identity, memory, language, and topology provider. */
public final class Esp32C6TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32C6TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 13, "esp32c6", 1, true,
            "ESP-IDF 662a3be components/soc/esp32c6/include/soc/soc.h", List.of(
                region(IROM, 0x42000000L, 0x43000000L, false, true),
                region(IRAM, 0x40800000L, 0x40880000L, true, true),
                region(RTC_DATA, 0x50000000L, 0x50004000L, true, true)));
    }
}
