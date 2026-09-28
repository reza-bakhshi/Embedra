package io.github.rezabakhshi.embedra.targets.esp8266;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266Image;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageParser;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import io.github.rezabakhshi.embedra.targets.esp.EspTargetProviders;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

class Esp8266LegacyTargetProviderTest {
    @Test
    void keepsLegacyFamilyIdentityOutsideTheEsp32ChipIdRegistry() throws Exception {
        Esp8266LegacyTargetProvider provider = new Esp8266LegacyTargetProvider();
        Esp8266Image image = fixture();

        assertEquals("target.esp8266.legacy", provider.providerId());
        assertTrue(provider.supports(image).supported());
        assertTrue(provider.supports(image).reason().contains("exact ESP8266EX/ESP8285"));
        assertTrue(EspTargetProviders.implemented().stream()
            .noneMatch(candidate -> candidate.providerId().contains("8266")));
    }

    @Test
    void classifiesPinnedLx106MemoryAndValidatesOnlyTheEncodedEntry() throws Exception {
        Esp8266LegacyTargetProvider provider = new Esp8266LegacyTargetProvider();
        Esp8266Image image = fixture();

        assertEquals(MemoryRegionKind.IRAM,
            provider.classify(new AddressRange("default", 0x4010_0000L, 4)).kind());
        assertEquals(MemoryRegionKind.DRAM,
            provider.classify(new AddressRange("default", 0x3ffe_8000L, 4)).kind());
        assertEquals(MemoryRegionKind.IROM,
            provider.classify(new AddressRange("default", 0x4020_1010L, 4)).kind());
        assertTrue(provider.validateEntry(image.header().entryPoint(), image).accepted());
        assertFalse(provider.validateEntry(0x4010_0000L, image).accepted());
    }

    @Test
    void modelsOneLx106ApplicationProcessor() throws Exception {
        Esp8266LegacyTargetProvider provider = new Esp8266LegacyTargetProvider();
        var topology = provider.topology(fixture());

        assertEquals(1, topology.processors().size());
        assertEquals("Xtensa LX106",
            topology.processors().get(0).instructionSet().orElseThrow());
        assertEquals("Xtensa:LE:32:default", provider.language().languageId());
    }

    private static Esp8266Image fixture() throws Exception {
        try (InputStream input = Esp8266LegacyTargetProviderTest.class.getResourceAsStream(
                "/fixtures/esp8266/esp8266-freestanding-v2-0x01000.bin")) {
            assertTrue(input != null);
            return Esp8266ImageParser.parse(input.readAllBytes(), ParserLimits.defaults(),
                CancellationToken.none());
        }
    }
}
