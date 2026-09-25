package io.github.rezabakhshi.embedra.targets.esp;

import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.DRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.DROM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IRAM;
import static io.github.rezabakhshi.embedra.targets.MemoryRegionKind.IROM;
import java.util.List;

/** Independent ESP32-C2 identity, memory, language, and topology provider. */
public final class Esp32C2TargetProvider extends ConfiguredRiscVEspTargetProvider {
    public Esp32C2TargetProvider(EspressifChipIdRegistry ids) {
        super(ids, 12, "esp32c2", 1, false,
            "ESP-IDF 662a3be components/soc/esp32c2/include/soc/soc.h", List.of(
                region(DROM, 0x3c000000L, 0x3c400000L, false, false),
                region(IROM, 0x42000000L, 0x42400000L, false, true),
                region(IRAM, 0x4037c000L, 0x403c0000L, true, true),
                region(DRAM, 0x3fca0000L, 0x3fce0000L, true, false)));
    }
}
