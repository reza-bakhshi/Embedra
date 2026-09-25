package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.io.InputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Esp32C3TargetProviderTest {
    private Esp32C3TargetProvider provider;

    private EspImage image;

    @BeforeEach
    void setUp() throws Exception {
        provider = new Esp32C3TargetProvider(EspressifChipIdRegistry.loadBundled());
        try (InputStream input = getClass().getResourceAsStream(
                "/fixtures/esp32c3/esp32c3-freestanding-minimal.bin")) {
            assertTrue(input != null);
            image = EspImageParser.parse(input.readAllBytes(), ParserLimits.defaults(),
                CancellationToken.none());
        }
    }

    @Test
    void selectsMaintainedIdentityAndGhidraRiscVLanguage() {
        assertTrue(provider.supports(image).supported());
        assertEquals("esp32c3", provider.supports(image).deviceId().orElseThrow());
        assertEquals("RISCV:LE:32:default", provider.language().languageId());
        assertEquals("gcc", provider.language().compilerSpecId());
        assertEquals("RISC-V", provider.language().instructionSet());
        assertEquals(2, provider.language().instructionAlignmentBytes());
        assertEquals(14, EspTargetProviders.implemented().size());
    }

    @Test
    void classifiesC3MemoryAndAcceptsMappedCompressedInstructionEntry() {
        assertEquals(MemoryRegionKind.DROM, provider.classify(
            new AddressRange("default", 0x3c00_0020L, 4)).kind());
        assertEquals(MemoryRegionKind.DRAM, provider.classify(
            new AddressRange("default", 0x3fc8_0000L, 4)).kind());
        assertEquals(MemoryRegionKind.IRAM, provider.classify(
            new AddressRange("default", 0x4037_c000L, 4)).kind());
        assertEquals(MemoryRegionKind.IROM, provider.classify(
            new AddressRange("default", 0x4200_0000L, 4)).kind());
        assertTrue(provider.validateEntry(0x4200_0000L, image).accepted());
        assertFalse(provider.validateEntry(0x4200_0001L, image).accepted());
        assertTrue(image.segments().stream().anyMatch(segment ->
            segment.isAlignmentPadding()));
    }

    @Test
    void modelsOneRiscVApplicationCpu() {
        var topology = provider.topology(image);
        assertEquals(1, topology.processors().size());
        assertEquals("RISC-V RV32IMC",
            topology.processors().get(0).instructionSet().orElseThrow());
        assertTrue(topology.processorGroups().isEmpty());
        assertTrue(topology.bootRelationships().isEmpty());
    }
}
