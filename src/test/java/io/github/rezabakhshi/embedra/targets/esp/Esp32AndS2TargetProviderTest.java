package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroupKind;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class Esp32AndS2TargetProviderTest {
    @Test
    void resolvesIndependentEsp32AndEsp32S2FixturesByMaintainedChipId() throws Exception {
        EspressifChipIdRegistry chipIds = EspressifChipIdRegistry.loadBundled();
        EspTargetResolver resolver = new EspTargetResolver(List.of(
            new Esp32TargetProvider(chipIds), new Esp32S2TargetProvider(chipIds),
            new Esp32S3TargetProvider(chipIds)));

        EspTargetResolution esp32 = resolver.resolve(image("esp32",
            "esp32-freestanding-minimal.bin")).orElseThrow();
        EspTargetResolution esp32s2 = resolver.resolve(image("esp32s2",
            "esp32s2-freestanding-minimal.bin")).orElseThrow();

        assertEquals("esp32", esp32.support().deviceId().orElseThrow());
        assertEquals(0, esp32.provider().chipId());
        assertEquals("esp32s2", esp32s2.support().deviceId().orElseThrow());
        assertEquals(2, esp32s2.provider().chipId());
    }

    @Test
    void originalEsp32UsesItsOwnMemoryMapAndDualApplicationCoreTopology()
            throws Exception {
        EspTargetProvider provider = new Esp32TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        EspImage image = image("esp32", "esp32-freestanding-minimal.bin");

        assertEquals(MemoryRegionKind.DROM,
            provider.classify(new AddressRange("default", 0x3f40_0020L, 4)).kind());
        assertEquals(MemoryRegionKind.IRAM,
            provider.classify(new AddressRange("default", 0x4008_0000L, 4)).kind());
        assertEquals(MemoryRegionKind.DRAM,
            provider.classify(new AddressRange("default", 0x3ffa_e000L, 4)).kind());
        assertTrue(provider.validateEntry(image.header().entryPoint(), image).accepted());
        assertEquals(2, provider.topology(image).processors().size());
        assertEquals(1, provider.topology(image).processorGroups().size());
        assertEquals(ProcessorGroupKind.SYMMETRIC,
            provider.topology(image).processorGroups().get(0).kind());
    }

    @Test
    void esp32S2UsesItsOwnMemoryMapAndSingleApplicationCoreTopology()
            throws Exception {
        EspTargetProvider provider = new Esp32S2TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        EspImage image = image("esp32s2", "esp32s2-freestanding-minimal.bin");

        assertEquals(MemoryRegionKind.DROM,
            provider.classify(new AddressRange("default", 0x3f00_0020L, 4)).kind());
        assertEquals(MemoryRegionKind.IRAM,
            provider.classify(new AddressRange("default", 0x4002_0000L, 4)).kind());
        assertEquals(MemoryRegionKind.DRAM,
            provider.classify(new AddressRange("default", 0x3ffb_0000L, 4)).kind());
        assertTrue(provider.validateEntry(image.header().entryPoint(), image).accepted());
        assertEquals(1, provider.topology(image).processors().size());
        assertTrue(provider.topology(image).processorGroups().isEmpty());
        assertFalse(provider.supports(image("esp32",
            "esp32-freestanding-minimal.bin")).supported());
    }

    private static EspImage image(String target, String name) throws Exception {
        return EspImageParser.parse(fixture(target, name), ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static byte[] fixture(String target, String name) throws IOException {
        try (InputStream input = Esp32AndS2TargetProviderTest.class.getResourceAsStream(
                "/fixtures/" + target + "/" + name)) {
            if (input == null) {
                throw new IOException("Missing fixture " + target + "/" + name);
            }
            return input.readAllBytes();
        }
    }
}
