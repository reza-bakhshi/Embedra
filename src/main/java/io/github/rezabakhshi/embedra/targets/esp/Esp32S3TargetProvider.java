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

/** Pure ESP32-S3 identity, language, memory, and entry provider. */
public final class Esp32S3TargetProvider implements EspTargetProvider {
    private static final int CHIP_ID = 9;

    private static final String ADDRESS_SPACE = "default";

    private static final String PROVIDER_VERSION = "esptool-v5.4.0+esp-idf-v6.0";

    private static final Evidence MEMORY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK,
        "ESP-IDF v6.0 components/soc/esp32s3/include/soc/soc.h",
        "SOC_DROM/IROM/IRAM/DRAM and SOC_RTC_DATA half-open address definitions");

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD,
        "Embedra data/languages/embedra_esp32s3.ldefs",
        "Xtensa:LE:32:esp32s3 language with default compiler specification");

    private static final EspMemoryMap MEMORY_MAP = new EspMemoryMap(ADDRESS_SPACE, List.of(
        new EspMemoryRegion(MemoryRegionKind.DROM, 0x3c00_0000L, 0x3e00_0000L,
            true, false, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IROM, 0x4200_0000L, 0x4400_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IRAM, 0x4037_0000L, 0x403e_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.DRAM, 0x3fc8_8000L, 0x3fd0_0000L,
            true, true, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.RTC_DATA, 0x5000_0000L, 0x5000_2000L,
            true, true, false, MEMORY_EVIDENCE)));

    private final EspressifChipDefinition chipDefinition;

    public Esp32S3TargetProvider(EspressifChipIdRegistry chipIds) {
        chipDefinition = Objects.requireNonNull(chipIds, "chipIds").requireByChipId(CHIP_ID);
        if (!chipDefinition.deviceId().equals("esp32s3")) {
            throw new IllegalArgumentException("Chip ID 9 is not defined as ESP32-S3");
        }
    }

    @Override
    public String providerId() {
        return "target.esp32s3";
    }

    @Override
    public String providerVersion() {
        return PROVIDER_VERSION;
    }

    @Override
    public String canonicalIdentity() {
        return "esp32s3|chip-id-9|Xtensa:LE:32:esp32s3|default|" + PROVIDER_VERSION;
    }

    @Override
    public int chipId() {
        return CHIP_ID;
    }

    @Override
    public SupportDecision supports(EspImage image) {
        Objects.requireNonNull(image, "image");
        Evidence evidence = chipEvidence(image.header().chipId());
        if (image.header().chipId() != chipDefinition.chipId()) {
            return new SupportDecision(false, Optional.empty(),
                "Image chip ID is not ESP32-S3", List.of(evidence));
        }
        return new SupportDecision(true, Optional.of(chipDefinition.deviceId()),
            "Image chip ID matches the maintained ESP32-S3 definition",
            List.of(evidence));
    }

    @Override
    public LanguageSelection language() {
        return new LanguageSelection("Xtensa:LE:32:esp32s3", "default", "Xtensa", 32, 1,
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
        ProcessorNode applicationCpu = new ProcessorNode("application-cpu",
            ProcessorKind.CPU_CORE, Optional.of("Xtensa LX7"),
            Optional.of(language().languageId()), Optional.of(language().compilerSpecId()),
            "ESP application processor", SecurityDomain.unknown(), "esp32s3",
            Set.of(ADDRESS_SPACE), List.of(entry), FirmwareSource.SHARED_IMAGE,
            Confidence.DERIVED, List.of(chip, LANGUAGE_EVIDENCE, MEMORY_EVIDENCE));
        return new ExecutionTopology(List.of(applicationCpu), List.of(), List.of(),
            List.of(), List.of(), ProgramStrategy.SHARED_PROGRAM);
    }

    private Evidence chipEvidence(int observedChipId) {
        return new Evidence(EvidenceKind.VENDOR_DATA_PACK,
            chipDefinition.sourcePath() + "@" + chipDefinition.sourceRevision(),
            "Maintained ESP32-S3 chip ID " + chipDefinition.chipId()
                + "; observed image chip ID " + observedChipId);
    }

}
