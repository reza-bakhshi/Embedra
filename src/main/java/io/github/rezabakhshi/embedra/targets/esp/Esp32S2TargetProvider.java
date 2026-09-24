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

/** ESP32-S2 provider with independently pinned memory and single-core evidence. */
public final class Esp32S2TargetProvider implements EspTargetProvider {
    private static final int CHIP_ID = 2;

    private static final String ADDRESS_SPACE = "default";

    private static final String PROVIDER_VERSION = "esptool-v5.4.0+esp-idf-v6.0";

    private static final Evidence MEMORY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK,
        "ESP-IDF v6.0 components/soc/esp32s2/include/soc/soc.h",
        "Pinned DROM, IROM, IRAM, DRAM, and RTC data boundaries");

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "Ghidra 12.1.3 Xtensa language",
        "Xtensa:LE:32:default resolves and maps the generated ESP32-S2 fixture");

    private static final Evidence TOPOLOGY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK, "ESP-IDF v6.0 ESP32-S2 SoC capabilities",
        "One Xtensa LX7 application core executes the supplied image");

    private static final EspMemoryMap MEMORY_MAP = new EspMemoryMap(ADDRESS_SPACE, List.of(
        new EspMemoryRegion(MemoryRegionKind.DROM, 0x3f00_0000L, 0x3ff8_0000L,
            true, false, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IROM, 0x4008_0000L, 0x4080_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IRAM, 0x4002_0000L, 0x4007_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.DRAM, 0x3ffb_0000L, 0x4000_0000L,
            true, true, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.RTC_DATA, 0x5000_0000L, 0x5000_2000L,
            true, true, false, MEMORY_EVIDENCE)));

    private final EspressifChipDefinition chipDefinition;

    public Esp32S2TargetProvider(EspressifChipIdRegistry chipIds) {
        chipDefinition = Objects.requireNonNull(chipIds, "chipIds").requireByChipId(CHIP_ID);
        if (!chipDefinition.deviceId().equals("esp32s2")) {
            throw new IllegalArgumentException("Chip ID 2 is not the maintained ESP32-S2 entry");
        }
    }

    @Override
    public String providerId() {
        return "target.esp32s2";
    }

    @Override
    public String providerVersion() {
        return PROVIDER_VERSION;
    }

    @Override
    public String canonicalIdentity() {
        return "esp32s2|chip-id-2|Xtensa:LE:32:default|default|" + PROVIDER_VERSION;
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
                "Image chip ID is not ESP32-S2", List.of(evidence));
        }
        return new SupportDecision(true, Optional.of("esp32s2"),
            "Image chip ID matches the maintained ESP32-S2 definition", List.of(evidence));
    }

    @Override
    public LanguageSelection language() {
        return new LanguageSelection("Xtensa:LE:32:default", "default", "Xtensa", 32, 1,
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
        ResetEntry entry = new ResetEntry("image-entry", ADDRESS_SPACE,
            image.header().entryPoint(), Confidence.VERIFIED,
            List.of(LANGUAGE_EVIDENCE, MEMORY_EVIDENCE));
        ProcessorNode cpu = new ProcessorNode("application-cpu", ProcessorKind.CPU_CORE,
            Optional.of("Xtensa LX7"), Optional.of(language().languageId()),
            Optional.of(language().compilerSpecId()), "application processor",
            SecurityDomain.unknown(), "esp32s2", Set.of(ADDRESS_SPACE), List.of(entry),
            FirmwareSource.SHARED_IMAGE, Confidence.VERIFIED,
            List.of(TOPOLOGY_EVIDENCE, LANGUAGE_EVIDENCE));
        return new ExecutionTopology(List.of(cpu), List.of(), List.of(), List.of(),
            List.of(), ProgramStrategy.SHARED_PROGRAM);
    }

    private Evidence chipEvidence(int observedChipId) {
        return new Evidence(EvidenceKind.VENDOR_DATA_PACK,
            chipDefinition.sourcePath() + "@" + chipDefinition.sourceRevision(),
            "Maintained ESP32-S2 chip ID " + CHIP_ID + "; observed image chip ID "
                + observedChipId);
    }
}
