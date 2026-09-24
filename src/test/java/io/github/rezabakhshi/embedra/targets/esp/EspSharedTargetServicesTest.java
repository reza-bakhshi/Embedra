package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class EspSharedTargetServicesTest {
    private static final Evidence TEST_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "synthetic contract fixture", "test-only target facts");

    @Test
    void resolvesAValidatedImageThroughTheNeutralProviderContract() throws Exception {
        EspImage image = goldenImage();
        EspTargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        EspTargetResolver resolver = new EspTargetResolver(List.of(provider));

        EspTargetResolution resolution = resolver.resolve(image).orElseThrow();

        assertSame(provider, resolution.provider());
        assertTrue(resolution.support().supported());
        assertEquals("esp32s3", resolution.support().deviceId().orElseThrow());
        assertEquals("target.esp32s3", provider.providerId());
        assertEquals(9, provider.chipId());
    }

    @Test
    void resolverRejectsDuplicateChipIdsAndReturnsEmptyForUnknownTargets() throws Exception {
        EspTargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());

        assertThrows(IllegalArgumentException.class,
            () -> new EspTargetResolver(List.of(provider, provider)));
        assertTrue(new EspTargetResolver(List.of()).resolve(goldenImage()).isEmpty());
    }

    @Test
    void dataDrivenMemoryAndEntryServicesContainNoXtensaAssumption() throws Exception {
        EspImage image = goldenImage();
        LanguageSelection riscV = new LanguageSelection(
            "RISCV:LE:32:test", "default", "RISC-V", 32, 2, "little",
            List.of(TEST_EVIDENCE));
        EspMemoryMap memory = new EspMemoryMap("default", List.of(
            new EspMemoryRegion(MemoryRegionKind.IRAM, 0x4037_0000L, 0x403e_0000L,
                true, false, true, TEST_EVIDENCE)));

        MemoryClassification classification = memory.classify(
            new AddressRange("default", image.header().entryPoint(), 1));
        EntryPointDecision decision = EspEntryPointValidator.validate(
            image.header().entryPoint(), image, riscV, "default", memory::classify);

        assertEquals(MemoryRegionKind.IRAM, classification.kind());
        assertTrue(decision.accepted());
        assertFalse(EspEntryPointValidator.validate(
            image.header().entryPoint() + 1, image, riscV, "default",
            memory::classify).accepted());
        assertFalse(memory.classify(new AddressRange("other", 0x4037_8000L, 1)).mappable());
    }

    @Test
    void esp32s3BuildsItsProvenSingleApplicationCpuTopology() throws Exception {
        EspTargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        ExecutionTopology topology = provider.topology(goldenImage());

        assertEquals(1, topology.processors().size());
        assertEquals(ProcessorKind.CPU_CORE, topology.processors().get(0).kind());
        assertEquals("Xtensa LX7", topology.processors().get(0).instructionSet().orElseThrow());
        assertEquals("Xtensa:LE:32:esp32s3",
            topology.processors().get(0).ghidraLanguageId().orElseThrow());
        assertEquals(1, topology.processors().get(0).resetEntries().size());
        assertEquals(goldenImage().header().entryPoint(),
            topology.processors().get(0).resetEntries().get(0).address());
        assertTrue(topology.sharedMemories().isEmpty());
        assertTrue(topology.processorGroups().isEmpty());
    }

    private static EspImage goldenImage() throws Exception {
        String resource = "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin";
        try (InputStream input = EspSharedTargetServicesTest.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("Missing fixture " + resource);
            }
            return EspImageParser.parse(input.readAllBytes(), ParserLimits.defaults(),
                CancellationToken.none());
        }
    }
}
