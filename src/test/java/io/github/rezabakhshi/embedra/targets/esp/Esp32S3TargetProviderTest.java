package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Esp32S3TargetProviderTest {
    private EspressifChipIdRegistry chipIds;

    private Esp32S3TargetProvider provider;

    private EspImage image;

    @BeforeEach
    void setUp() throws Exception {
        chipIds = EspressifChipIdRegistry.loadBundled();
        provider = new Esp32S3TargetProvider(chipIds);
        image = EspImageParser.parse(fixture("esp32s3-freestanding-minimal.bin"),
            ParserLimits.defaults(), CancellationToken.none());
    }

    @Test
    void resolvesEsp32S3OnlyThroughPinnedMaintainedChipDefinitions() throws Exception {
        EspressifChipDefinition definition = chipIds.requireByChipId(9);

        assertEquals(9, definition.chipId());
        assertEquals("esp32s3", definition.deviceId());
        assertEquals("ESP32-S3", definition.displayName());
        assertEquals("esptool/targets/esp32s3.py", definition.sourcePath());
        assertEquals("v5.4.0", definition.sourceRevision());
        assertEquals("GPL-2.0-or-later", definition.sourceLicense());
        assertTrue(provider.supports(image).supported());
        assertEquals("esp32s3", provider.supports(image).deviceId().orElseThrow());

        EspImage wrongChip = EspImageParser.parse(
            fixture("malformed/malformed-wrong-chip.bin"), ParserLimits.defaults(),
            CancellationToken.none());
        assertFalse(provider.supports(wrongChip).supported());
        assertTrue(provider.supports(wrongChip).deviceId().isEmpty());
    }

    @Test
    void selectsTheVerifiedGhidraXtensaLittleEndianLanguageAndCompiler() {
        LanguageSelection language = provider.language();

        assertEquals("Xtensa:LE:32:default", language.languageId());
        assertEquals("default", language.compilerSpecId());
        assertEquals("Xtensa", language.instructionSet());
        assertEquals(32, language.addressSizeBits());
        assertEquals(1, language.instructionAlignmentBytes());
        assertEquals("little", language.endianness());
        assertFalse(language.evidence().isEmpty());
    }

    @Test
    void classifiesGoldenSegmentsFromAuthoritativeHalfOpenAddressRanges() {
        assertClassification(image.segments().get(0).targetRange(),
            MemoryRegionKind.DROM, true, false, false);
        assertClassification(image.segments().get(1).targetRange(),
            MemoryRegionKind.DRAM, true, true, false);
        assertClassification(image.segments().get(2).targetRange(),
            MemoryRegionKind.IRAM, true, false, true);
        assertClassification(new AddressRange("default", 0x4200_0000L, 4),
            MemoryRegionKind.IROM, true, false, true);

        MemoryClassification crossing = provider.classify(
            new AddressRange("default", 0x3dff_fff0L, 0x20));
        assertEquals(MemoryRegionKind.UNKNOWN, crossing.kind());
        assertFalse(crossing.mappable());
        assertFalse(crossing.executable());

        MemoryClassification foreignSpace = provider.classify(
            new AddressRange("flash", 0x4037_8000L, 4));
        assertEquals(MemoryRegionKind.UNKNOWN, foreignSpace.kind());
        assertFalse(foreignSpace.mappable());
    }

    @Test
    void acceptsOnlyAlignedEntriesInsideMappedExecutableSegments() {
        EntryPointDecision accepted = provider.validateEntry(image.header().entryPoint(), image);
        assertTrue(accepted.accepted());
        assertEquals(MemoryRegionKind.IRAM,
            accepted.classification().orElseThrow().kind());

        assertTrue(provider.validateEntry(0x4037_800aL, image).accepted());
        assertRejected(0x3c01_0020L, "executable");
        assertRejected(0x3fc8_8000L, "executable");
        assertRejected(0x4200_0000L, "mapped segment");
        assertRejected(0x1234_0000L, "recognized memory");
    }

    @Test
    void rangeEndsAreExclusiveAndCannotAcquireMixedPermissions() {
        assertEquals(MemoryRegionKind.DROM,
            provider.classify(new AddressRange("default", 0x3c00_0000L, 1)).kind());
        assertEquals(MemoryRegionKind.UNKNOWN,
            provider.classify(new AddressRange("default", 0x3dff_ffffL, 2)).kind());
        assertEquals(MemoryRegionKind.UNKNOWN,
            provider.classify(new AddressRange("default", 0x4400_0000L, 1)).kind());
        assertEquals(MemoryRegionKind.UNKNOWN,
            provider.classify(new AddressRange("default", 0x403d_ffffL, 2)).kind());
    }

    private void assertClassification(AddressRange range, MemoryRegionKind kind,
            boolean readable, boolean writable, boolean executable) {
        MemoryClassification classification = provider.classify(range);
        assertEquals(kind, classification.kind());
        assertTrue(classification.mappable());
        assertEquals(readable, classification.readable());
        assertEquals(writable, classification.writable());
        assertEquals(executable, classification.executable());
        assertFalse(classification.evidence().isEmpty());
    }

    private void assertRejected(long address, String reasonFragment) {
        EntryPointDecision decision = provider.validateEntry(address, image);
        assertFalse(decision.accepted());
        assertTrue(decision.reason().contains(reasonFragment), decision.reason());
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream input = Esp32S3TargetProviderTest.class.getResourceAsStream(
                "/fixtures/esp32s3/" + name)) {
            assertTrue(input != null, "missing fixture " + name);
            return input.readAllBytes();
        }
    }
}
