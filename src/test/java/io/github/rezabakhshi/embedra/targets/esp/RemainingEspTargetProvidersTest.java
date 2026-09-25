package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import java.io.InputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RemainingEspTargetProvidersTest {
    private static Stream<Arguments> providers() {
        EspressifChipIdRegistry ids = EspressifChipIdRegistry.loadBundled();
        return Stream.of(
            Arguments.of(new Esp32S31TargetProvider(ids), 32, "esp32s31", 2),
            Arguments.of(new Esp32P4TargetProvider(ids), 18, "esp32p4", 3),
            Arguments.of(new Esp32C2TargetProvider(ids), 12, "esp32c2", 1),
            Arguments.of(new Esp32C5TargetProvider(ids), 23, "esp32c5", 2),
            Arguments.of(new Esp32C6TargetProvider(ids), 13, "esp32c6", 2),
            Arguments.of(new Esp32C61TargetProvider(ids), 20, "esp32c61", 1),
            Arguments.of(new Esp32E22TargetProvider(ids), 31, "esp32e22", 2),
            Arguments.of(new Esp32H2TargetProvider(ids), 16, "esp32h2", 1),
            Arguments.of(new Esp32H21TargetProvider(ids), 25, "esp32h21", 1),
            Arguments.of(new Esp32H4TargetProvider(ids), 28, "esp32h4", 2));
    }

    @ParameterizedTest
    @MethodSource("providers")
    void resolvesIndependentIdentityLanguageAndTopology(EspTargetProvider provider,
            int chipId, String deviceId, int processorCount) throws Exception {
        EspImage image = imageWithChipId(chipId);

        assertEquals(chipId, provider.chipId());
        assertEquals("target." + deviceId, provider.providerId());
        assertTrue(provider.supports(image).supported());
        assertEquals(deviceId, provider.supports(image).deviceId().orElseThrow());
        assertEquals("RISCV:LE:32:default", provider.language().languageId());
        assertEquals("gcc", provider.language().compilerSpecId());
        assertEquals(2, provider.language().instructionAlignmentBytes());
        assertEquals(processorCount, provider.topology(image).processors().size());
        assertEquals(provider.providerId(),
            EspTargetProviders.resolver().resolve(image).orElseThrow().provider().providerId());
    }

    private static EspImage imageWithChipId(int chipId) throws Exception {
        byte[] bytes;
        try (InputStream input = RemainingEspTargetProvidersTest.class.getResourceAsStream(
                "/fixtures/esp32c3/esp32c3-freestanding-minimal.bin")) {
            assertTrue(input != null);
            bytes = input.readAllBytes();
        }
        bytes[12] = (byte) chipId;
        bytes[13] = (byte) (chipId >>> 8);
        bytes[23] = 0;
        bytes = java.util.Arrays.copyOf(bytes, bytes.length - 32);
        return EspImageParser.parse(bytes, ParserLimits.defaults(), CancellationToken.none());
    }
}
