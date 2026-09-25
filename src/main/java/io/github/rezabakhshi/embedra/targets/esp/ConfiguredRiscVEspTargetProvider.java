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
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Common mechanics for independently configured 32-bit RISC-V ESP providers. */
abstract class ConfiguredRiscVEspTargetProvider implements EspTargetProvider {
    static final String ADDRESS_SPACE = "default";

    static final String PROVIDER_VERSION = "esptool-v5.4.0+esp-idf-v6.0";

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD,
        "Ghidra 12.1.3 Processors/RISCV/data/languages/riscv.ldefs",
        "RISCV:LE:32:default language with gcc compiler specification");

    private final EspressifChipDefinition chipDefinition;

    private final EspMemoryMap memoryMap;

    private final Evidence memoryEvidence;

    private final int applicationCoreCount;

    private final boolean lowPowerCore;

    ConfiguredRiscVEspTargetProvider(EspressifChipIdRegistry chipIds, int chipId,
            String deviceId, int applicationCoreCount, boolean lowPowerCore,
            String memorySource, List<EspMemoryRegion> memoryRegions) {
        chipDefinition = Objects.requireNonNull(chipIds, "chipIds").requireByChipId(chipId);
        if (!chipDefinition.deviceId().equals(deviceId)) {
            throw new IllegalArgumentException("Chip ID " + chipId + " is not " + deviceId);
        }
        if (applicationCoreCount < 1) {
            throw new IllegalArgumentException("An ESP target requires an application core");
        }
        this.applicationCoreCount = applicationCoreCount;
        this.lowPowerCore = lowPowerCore;
        memoryEvidence = new Evidence(EvidenceKind.VENDOR_DATA_PACK, memorySource,
            "Maintained half-open address definitions for " + chipDefinition.displayName());
        memoryMap = new EspMemoryMap(ADDRESS_SPACE, memoryRegions.stream()
            .map(region -> new EspMemoryRegion(region.kind(), region.start(),
                region.endExclusive(), region.readable(), region.writable(),
                region.executable(), memoryEvidence))
            .toList());
    }

    static EspMemoryRegion region(io.github.rezabakhshi.embedra.targets.MemoryRegionKind kind,
            long start, long endExclusive, boolean writable, boolean executable) {
        Evidence placeholder = new Evidence(EvidenceKind.DERIVED_RULE,
            "provider-construction", "Replaced with target memory evidence");
        return new EspMemoryRegion(kind, start, endExclusive, true, writable, executable,
            placeholder);
    }

    @Override
    public final String providerId() {
        return "target." + chipDefinition.deviceId();
    }

    @Override
    public final String providerVersion() {
        return PROVIDER_VERSION;
    }

    @Override
    public final String canonicalIdentity() {
        return chipDefinition.deviceId() + "|chip-id-" + chipId()
            + "|RISCV:LE:32:default|gcc|" + PROVIDER_VERSION;
    }

    @Override
    public final int chipId() {
        return chipDefinition.chipId();
    }

    @Override
    public final SupportDecision supports(EspImage image) {
        Objects.requireNonNull(image, "image");
        Evidence evidence = chipEvidence(image.header().chipId());
        if (image.header().chipId() != chipId()) {
            return new SupportDecision(false, Optional.empty(),
                "Image chip ID is not " + chipDefinition.displayName(), List.of(evidence));
        }
        return new SupportDecision(true, Optional.of(chipDefinition.deviceId()),
            "Image chip ID matches the maintained " + chipDefinition.displayName()
                + " definition", List.of(evidence));
    }

    @Override
    public final LanguageSelection language() {
        return new LanguageSelection("RISCV:LE:32:default", "gcc", "RISC-V", 32, 2,
            "little", List.of(LANGUAGE_EVIDENCE));
    }

    @Override
    public final MemoryClassification classify(AddressRange range) {
        return memoryMap.classify(range);
    }

    @Override
    public final EntryPointDecision validateEntry(long address, EspImage image) {
        return EspEntryPointValidator.validate(address, image, language(), ADDRESS_SPACE,
            this::classify);
    }

    @Override
    public final ExecutionTopology topology(EspImage image) {
        Objects.requireNonNull(image, "image");
        List<ProcessorNode> processors = new ArrayList<>();
        for (int core = 0; core < applicationCoreCount; core++) {
            ResetEntry entry = new ResetEntry("image-entry", ADDRESS_SPACE,
                image.header().entryPoint(), Confidence.DERIVED,
                List.of(LANGUAGE_EVIDENCE, memoryEvidence));
            processors.add(new ProcessorNode("application-cpu-" + core,
                ProcessorKind.CPU_CORE, Optional.of("RISC-V 32-bit"),
                Optional.of(language().languageId()), Optional.of(language().compilerSpecId()),
                "ESP application processor " + core, SecurityDomain.unknown(),
                chipDefinition.deviceId(), Set.of(ADDRESS_SPACE), List.of(entry),
                FirmwareSource.SHARED_IMAGE, Confidence.DERIVED,
                List.of(chipEvidence(image.header().chipId()), LANGUAGE_EVIDENCE,
                    memoryEvidence)));
        }
        if (lowPowerCore) {
            processors.add(new ProcessorNode("low-power-riscv",
                ProcessorKind.PROGRAMMABLE_COPROCESSOR, Optional.of("RISC-V 32-bit"),
                Optional.of(language().languageId()), Optional.of(language().compilerSpecId()),
                "Low-power RISC-V processor", SecurityDomain.unknown(),
                chipDefinition.deviceId(), Set.of(ADDRESS_SPACE), List.of(),
                FirmwareSource.UNKNOWN, Confidence.DERIVED,
                List.of(chipEvidence(image.header().chipId()), memoryEvidence)));
        }
        return new ExecutionTopology(processors, List.of(), List.of(), List.of(), List.of(),
            ProgramStrategy.SHARED_PROGRAM);
    }

    private Evidence chipEvidence(int observedChipId) {
        return new Evidence(EvidenceKind.VENDOR_DATA_PACK,
            chipDefinition.sourcePath() + "@" + chipDefinition.sourceRevision(),
            "Maintained " + chipDefinition.displayName() + " chip ID " + chipId()
                + "; observed image chip ID " + observedChipId);
    }
}
