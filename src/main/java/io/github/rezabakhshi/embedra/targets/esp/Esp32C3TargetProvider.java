package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.ResetEntry;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Pure ESP32-C3 identity, RISC-V language, memory, and entry provider. */
public final class Esp32C3TargetProvider implements EspTargetProvider {
    private static final int CHIP_ID = 5;

    private static final String ADDRESS_SPACE = "default";

    private static final String PROVIDER_VERSION = "esptool-v5.4.0+esp-idf-v6.0";

    private static final Evidence MEMORY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK,
        "ESP-IDF v6.0 components/soc/esp32c3/include/soc/soc.h",
        "SOC_DROM/IROM/IRAM/DRAM and SOC_RTC_DATA half-open address definitions");

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD,
        "Ghidra 12.1.3 Processors/RISCV/data/languages/riscv.ldefs",
        "RISCV:LE:32:default language with gcc compiler specification");

    private static final EspMemoryMap MEMORY_MAP = new EspMemoryMap(ADDRESS_SPACE, List.of(
        new EspMemoryRegion(MemoryRegionKind.DROM, 0x3c00_0000L, 0x3c80_0000L,
            true, false, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IROM, 0x4200_0000L, 0x4280_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IRAM, 0x4037_c000L, 0x403e_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.DRAM, 0x3fc8_0000L, 0x3fce_0000L,
            true, true, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.RTC_DATA, 0x5000_0000L, 0x5000_2000L,
            true, true, false, MEMORY_EVIDENCE)));

    private final EspressifChipDefinition chipDefinition;

    public Esp32C3TargetProvider(EspressifChipIdRegistry chipIds) {
        chipDefinition = Objects.requireNonNull(chipIds, "chipIds").requireByChipId(CHIP_ID);
        if (!chipDefinition.deviceId().equals("esp32c3")) {
            throw new IllegalArgumentException("Chip ID 5 is not defined as ESP32-C3");
        }
    }

    @Override
    public String providerId() {
        return "target.esp32c3";
    }

    @Override
    public String providerVersion() {
        return PROVIDER_VERSION;
    }

    @Override
    public String canonicalIdentity() {
        return "esp32c3|chip-id-5|RISCV:LE:32:default|gcc|" + PROVIDER_VERSION;
    }

    @Override
    public int chipId() {
        return CHIP_ID;
    }

    @Override
    public SupportDecision supports(EspImage image) {
        Objects.requireNonNull(image, "image");
        Evidence evidence = chipEvidence(image.header().chipId());
        if (image.header().chipId() != CHIP_ID) {
            return new SupportDecision(false, Optional.empty(),
                "Image chip ID is not ESP32-C3", List.of(evidence));
        }
        return new SupportDecision(true, Optional.of("esp32c3"),
            "Image chip ID matches the maintained ESP32-C3 definition", List.of(evidence));
    }

    @Override
    public LanguageSelection language() {
        return new LanguageSelection("RISCV:LE:32:default", "gcc", "RISC-V", 32, 2,
            "little", List.of(LANGUAGE_EVIDENCE));
    }

    @Override
    public MemoryClassification classify(AddressRange range) {
        return MEMORY_MAP.classify(range);
    }

    @Override
    public EntryPointDecision validateEntry(long address, EspImage image) {
        return EspEntryPointValidator.validate(address, image, language(), ADDRESS_SPACE,
            this::classify);
    }

    @Override
    public ExecutionTopology topology(EspImage image) {
        Objects.requireNonNull(image, "image");
        Evidence chip = chipEvidence(image.header().chipId());
        ResetEntry entry = new ResetEntry("image-entry", ADDRESS_SPACE,
            image.header().entryPoint(), Confidence.DERIVED,
            List.of(LANGUAGE_EVIDENCE, MEMORY_EVIDENCE));
        ProcessorNode cpu = new ProcessorNode("application-cpu", ProcessorKind.CPU_CORE,
            Optional.of("RISC-V RV32IMC"), Optional.of(language().languageId()),
            Optional.of(language().compilerSpecId()), "ESP application processor",
            SecurityDomain.unknown(), "esp32c3", Set.of(ADDRESS_SPACE), List.of(entry),
            FirmwareSource.SHARED_IMAGE, Confidence.DERIVED,
            List.of(chip, LANGUAGE_EVIDENCE, MEMORY_EVIDENCE));
        return new ExecutionTopology(List.of(cpu), List.of(), List.of(), List.of(),
            List.of(), ProgramStrategy.SHARED_PROGRAM);
    }

    private Evidence chipEvidence(int observedChipId) {
        return new Evidence(EvidenceKind.VENDOR_DATA_PACK,
            chipDefinition.sourcePath() + "@" + chipDefinition.sourceRevision(),
            "Maintained ESP32-C3 chip ID " + CHIP_ID + "; observed image chip ID "
                + observedChipId);
    }
}
