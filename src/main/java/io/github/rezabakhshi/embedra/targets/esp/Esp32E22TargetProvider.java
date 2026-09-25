package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.RTC_DATA;
import java.util.List;

/** Independent ESP32-E22 identity, memory, language, and topology provider. */
public final class Esp32E22TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32E22TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 31, "esp32e22", 2, false,
            "esptool v5.4.0 esptool/targets/esp32e22.py MEMORY_MAP", List.of(
                region(IROM, 0x3c000000L, 0x40000000L, false, true),
                region(IRAM, 0x30fe0000L, 0x31200000L, true, true),
                region(RTC_DATA, 0xc0000000L, 0xc0008000L, true, true)));
    }
}
