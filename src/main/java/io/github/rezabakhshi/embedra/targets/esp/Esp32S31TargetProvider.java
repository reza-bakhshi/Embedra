package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-S31 identity, memory, language, and topology provider. */
public final class Esp32S31TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32S31TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 32, "esp32s31", 2, false,
            "esptool v5.4.0 esptool/targets/esp32s31.py MEMORY_MAP", List.of(
                region(IROM, 0x40000000L, 0x54000000L, false, true),
                region(IRAM, 0x2f000000L, 0x2f080000L, true, true),
                region(RTC_DATA, 0x2e000000L, 0x2e008000L, true, true)));
    }
}
