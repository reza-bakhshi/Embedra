package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class Esp32AndS2EnrichmentPackTest {
    @Test
    void loadsIndependentOriginalEsp32Packs() throws Exception {
        assertPacks("esp32", "ESP32");
    }

    @Test
    void loadsIndependentEsp32S2Packs() throws Exception {
        assertPacks("esp32s2", "ESP32-S2");
    }

    private static void assertPacks(String deviceId, String displayName) throws Exception {
        ParserLimits limits = ParserLimits.defaults();
        CancellationToken cancellation = CancellationToken.none();
        EspRomSymbolPack rom = EspTargetPackLoader.loadRom(
            pack("espressif." + deviceId + ".rom"), deviceId, limits, cancellation);
        EspPeripheralPack peripherals = EspTargetPackLoader.loadPeripherals(
            pack("espressif." + deviceId + ".peripherals"), deviceId, limits,
            cancellation);
        EspSvdPack svd = EspTargetPackLoader.loadSvd(
            pack("espressif." + deviceId + ".svd"), deviceId, limits, cancellation);

        assertEquals(deviceId, rom.deviceId());
        assertEquals(deviceId, peripherals.deviceId());
        assertEquals(displayName, svd.device().name());
        assertFalse(rom.symbols().isEmpty());
        assertFalse(peripherals.peripherals().isEmpty());
        assertFalse(svd.device().peripherals().isEmpty());
        assertTrue(rom.manifest().packId().contains(deviceId));
    }

    private static Path pack(String packId) {
        return Path.of(System.getProperty("embedra.projectDir"), "packs", packId,
            "1.0.0");
    }
}
