package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspDeviceCatalogLoader;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
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
        EspImage image = fixture(deviceId);

        assertEquals(chipId, provider.chipId());
        assertEquals("target." + deviceId, provider.providerId());
        assertTrue(provider.supports(image).supported());
        assertEquals(deviceId, provider.supports(image).deviceId().orElseThrow());
        assertEquals("RISCV:LE:32:default", provider.language().languageId());
        assertEquals("gcc", provider.language().compilerSpecId());
        assertEquals(2, provider.language().instructionAlignmentBytes());
        assertEquals(processorCount, provider.topology(image).processors().size());
        assertTrue(provider.validateEntry(image.header().entryPoint(), image).accepted());
        assertEquals(provider.providerId(),
            EspTargetProviders.resolver().resolve(image).orElseThrow().provider().providerId());

        byte[] binary = resource("/fixtures/" + deviceId + "/" + deviceId
            + "-freestanding-minimal.bin");
        String manifest = new String(resource("/fixtures/" + deviceId + "/" + deviceId
            + "-freestanding-minimal.bin.manifest.json"), StandardCharsets.UTF_8);
        String oracle = new String(resource("/oracles/" + deviceId + "/" + deviceId
            + "-freestanding-minimal.expectations.json"), StandardCharsets.UTF_8);
        assertTrue(manifest.contains(HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(binary))));
        assertTrue(oracle.contains("\"projectName\": \"embedra_t030_" + deviceId + "\""));
        assertTrue(oracle.contains("\"elfMachine\": \"RISC-V\""));

        EspDeviceCatalog catalog = EspDeviceCatalogLoader.load(Path.of(
            System.getProperty("embedra.projectDir"), "catalogs", "espressif",
            "2026-09-23"), ParserLimits.defaults(), CancellationToken.none());
        var variants = provider.catalogVariants(catalog);
        assertTrue(!variants.isEmpty());
        assertTrue(variants.stream().allMatch(record -> !record.exactPart().isBlank()
            && !record.embeddedFlashMb().isBlank()
            && !record.embeddedPsramMb().isBlank()
            && record.applicationCoreCount() > 0));
        assertEquals(variants.size(), variants.stream()
            .map(record -> record.exactPart().toUpperCase()).distinct().count());
    }

    private static EspImage fixture(String deviceId) throws Exception {
        return EspImageParser.parse(resource("/fixtures/" + deviceId + "/" + deviceId
            + "-freestanding-minimal.bin"), ParserLimits.defaults(), CancellationToken.none());
    }

    private static byte[] resource(String name) throws Exception {
        try (InputStream input = RemainingEspTargetProvidersTest.class.getResourceAsStream(name)) {
            assertTrue(input != null, "missing fixture resource " + name);
            return input.readAllBytes();
        }
    }
}
