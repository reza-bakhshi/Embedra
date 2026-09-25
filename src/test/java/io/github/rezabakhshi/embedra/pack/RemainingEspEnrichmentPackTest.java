package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RemainingEspEnrichmentPackTest {
    private static final ParserLimits LIMITS = ParserLimits.defaults();

    private static Stream<Arguments> idfTargets() {
        return Stream.of(
            Arguments.of("esp32p4", 700, 5_000),
            Arguments.of("esp32c2", 2_000, 800),
            Arguments.of("esp32c5", 1_000, 2_500),
            Arguments.of("esp32c6", 1_200, 2_000),
            Arguments.of("esp32c61", 1_000, 2_000),
            Arguments.of("esp32h2", 600, 2_000),
            Arguments.of("esp32h21", 600, 1_500),
            Arguments.of("esp32h4", 500, 1_700));
    }

    private static Stream<Arguments> svdTargets() {
        return Stream.of(
            Arguments.of("esp32p4", "ESP32-P4", 6_000),
            Arguments.of("esp32c2", "ESP32-C2", 1_000),
            Arguments.of("esp32c6", "ESP32-C6", 3_900),
            Arguments.of("esp32h2", "ESP32-H2", 3_400));
    }

    @ParameterizedTest
    @MethodSource("idfTargets")
    void loadsPinnedRomAndPeripheralPacks(String deviceId, int minimumSymbols,
            int minimumRegisters) throws Exception {
        CancellationToken cancellation = CancellationToken.none();
        EspRomSymbolPack rom = EspTargetPackLoader.loadRom(pack(deviceId, "rom"),
            deviceId, LIMITS, cancellation);
        EspPeripheralPack peripherals = EspTargetPackLoader.loadPeripherals(
            pack(deviceId, "peripherals"), deviceId, LIMITS, cancellation);

        assertEquals(deviceId, rom.deviceId());
        assertEquals(deviceId, peripherals.deviceId());
        assertTrue(rom.symbols().size() >= minimumSymbols);
        assertTrue(peripherals.registerCount() >= minimumRegisters);
        assertEquals("espressif." + deviceId + ".rom", rom.manifest().packId());
        assertEquals("espressif." + deviceId + ".peripherals",
            peripherals.manifest().packId());
    }

    @ParameterizedTest
    @MethodSource("svdTargets")
    void loadsAvailablePinnedSvdPacks(String deviceId, String displayName,
            int minimumRegisters) throws Exception {
        EspSvdPack svd = EspTargetPackLoader.loadSvd(pack(deviceId, "svd"), deviceId,
            LIMITS, CancellationToken.none());

        assertEquals(displayName, svd.device().name());
        assertTrue(svd.registerCount() >= minimumRegisters);
        assertTrue(svd.reconciliation().matchingPeripheralBases() > 0);
        assertTrue(svd.reconciliation().matchingRegisterAddresses() > 0);
        assertEquals("record-conflicts-prefer-svd", svd.reconciliation().policy());
    }

    private static Path pack(String deviceId, String kind) {
        return Path.of(System.getProperty("embedra.projectDir"), "packs",
            "espressif." + deviceId + "." + kind, "1.0.0");
    }
}
