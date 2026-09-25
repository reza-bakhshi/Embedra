package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class Esp32C3EnrichmentPackTest {
    @Test
    void loadsPinnedC3RomPeripheralAndSvdPacks() throws Exception {
        ParserLimits limits = ParserLimits.defaults();
        var rom = EspTargetPackLoader.loadRom(pack("rom"), "esp32c3", limits,
            CancellationToken.none());
        var peripherals = EspTargetPackLoader.loadPeripherals(pack("peripherals"),
            "esp32c3", limits, CancellationToken.none());
        var svd = EspTargetPackLoader.loadSvd(pack("svd"), "esp32c3", limits,
            CancellationToken.none());

        assertTrue(rom.symbols().size() > 1000);
        assertTrue(peripherals.registerCount() > 500);
        assertTrue(svd.registerCount() > 1000);
        assertEquals("ESP32-C3", svd.device().name());
        assertEquals("record-conflicts-prefer-svd", svd.reconciliation().policy());
    }

    private static Path pack(String kind) {
        return Path.of("packs", "espressif.esp32c3." + kind, "1.0.0");
    }
}
