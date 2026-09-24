package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroup;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroupKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.ResetEntry;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
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

/** Original ESP32 provider with independently pinned memory and dual-core evidence. */
public final class Esp32TargetProvider implements EspTargetProvider {
    private static final int CHIP_ID = 0;

    private static final String ADDRESS_SPACE = "default";

    private static final String PROVIDER_VERSION = "esptool-v5.4.0+esp-idf-v6.0";

    private static final Evidence MEMORY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK,
        "ESP-IDF v6.0 components/soc/esp32/include/soc/soc.h",
        "Pinned DROM, IROM, IRAM, DRAM, and RTC data boundaries");

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "Ghidra 12.1.3 Xtensa language",
        "Xtensa:LE:32:default resolves and maps the generated ESP32 fixture");

    private static final Evidence TOPOLOGY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK, "ESP-IDF v6.0 ESP32 SoC capabilities",
        "Two symmetric Xtensa LX6 application cores share application memory");

    private static final EspMemoryMap MEMORY_MAP = new EspMemoryMap(ADDRESS_SPACE, List.of(
        new EspMemoryRegion(MemoryRegionKind.DROM, 0x3f40_0000L, 0x3f80_0000L,
            true, false, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IROM, 0x400d_0000L, 0x4040_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.IRAM, 0x4008_0000L, 0x400c_0000L,
            true, false, true, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.DRAM, 0x3ffa_e000L, 0x4000_0000L,
            true, true, false, MEMORY_EVIDENCE),
        new EspMemoryRegion(MemoryRegionKind.RTC_DATA, 0x5000_0000L, 0x5000_2000L,
            true, true, false, MEMORY_EVIDENCE)));

    private final EspressifChipDefinition chipDefinition;

    public Esp32TargetProvider(EspressifChipIdRegistry chipIds) {
        chipDefinition = Objects.requireNonNull(chipIds, "chipIds").requireByChipId(CHIP_ID);
        if (!chipDefinition.deviceId().equals("esp32")) {
            throw new IllegalArgumentException("Chip ID 0 is not the maintained ESP32 entry");
        }
    }

    @Override
    public String providerId() {
        return "target.esp32";
    }

    @Override
    public String providerVersion() {
        return PROVIDER_VERSION;
    }

    @Override
    public String canonicalIdentity() {
        return "esp32|chip-id-0|Xtensa:LE:32:default|default|" + PROVIDER_VERSION;
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
                "Image chip ID is not ESP32", List.of(evidence));
        }
        return new SupportDecision(true, Optional.of("esp32"),
            "Image chip ID matches the maintained ESP32 definition", List.of(evidence));
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
        ProcessorNode cpu0 = cpu("application-cpu-0", "PRO_CPU", List.of(entry));
        ProcessorNode cpu1 = cpu("application-cpu-1", "APP_CPU", List.of());
        Set<String> cores = Set.of(cpu0.id(), cpu1.id());
        List<SharedMemoryRegion> shared = image.segments().stream().map(segment -> {
            MemoryClassification classification = classify(segment.targetRange());
            Set<String> writers = classification.writable() ? cores : Set.<String>of();
            return new SharedMemoryRegion("image-segment-" + segment.index(),
                segment.targetRange(), cores, cores, writers, List.of(), Confidence.VERIFIED,
                List.of(MEMORY_EVIDENCE));
        }).toList();
        BootRelationship release = new BootRelationship("cpu0-releases-cpu1", cpu0.id(),
            cpu1.id(), BootRelationshipType.RELEASES_FROM_RESET,
            "ESP32 application CPU start control", Confidence.DERIVED,
            List.of(TOPOLOGY_EVIDENCE));
        ProcessorGroup symmetric = new ProcessorGroup("application-cores",
            ProcessorGroupKind.SYMMETRIC, cores);
        return new ExecutionTopology(List.of(cpu0, cpu1), shared, List.of(release),
            List.of(), List.of(symmetric), ProgramStrategy.SHARED_PROGRAM);
    }

    private ProcessorNode cpu(String id, String role, List<ResetEntry> entries) {
        return new ProcessorNode(id, ProcessorKind.CPU_CORE, Optional.of("Xtensa LX6"),
            Optional.of(language().languageId()), Optional.of(language().compilerSpecId()),
            role, SecurityDomain.unknown(), "esp32", Set.of(ADDRESS_SPACE), entries,
            FirmwareSource.SHARED_IMAGE, Confidence.VERIFIED,
            List.of(TOPOLOGY_EVIDENCE, LANGUAGE_EVIDENCE));
    }

    private Evidence chipEvidence(int observedChipId) {
        return new Evidence(EvidenceKind.VENDOR_DATA_PACK,
            chipDefinition.sourcePath() + "@" + chipDefinition.sourceRevision(),
            "Maintained ESP32 chip ID " + CHIP_ID + "; observed image chip ID "
                + observedChipId);
    }
}
