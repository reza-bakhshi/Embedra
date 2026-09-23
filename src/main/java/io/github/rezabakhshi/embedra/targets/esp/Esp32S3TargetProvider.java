package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageSegment;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Pure ESP32-S3 identity, language, memory, and entry provider. */
public final class Esp32S3TargetProvider {
    private static final int CHIP_ID = 9;

    private static final String ADDRESS_SPACE = "default";

    private static final List<RegionDefinition> REGIONS = List.of(
        new RegionDefinition(MemoryRegionKind.DROM, 0x3c00_0000L, 0x3e00_0000L,
            true, false, false),
        new RegionDefinition(MemoryRegionKind.IROM, 0x4200_0000L, 0x4400_0000L,
            true, false, true),
        new RegionDefinition(MemoryRegionKind.IRAM, 0x4037_0000L, 0x403e_0000L,
            true, false, true),
        new RegionDefinition(MemoryRegionKind.DRAM, 0x3fc8_8000L, 0x3fd0_0000L,
            true, true, false),
        new RegionDefinition(MemoryRegionKind.RTC_DATA, 0x5000_0000L, 0x5000_2000L,
            true, true, false));

    private static final Evidence MEMORY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK,
        "ESP-IDF v6.0 components/soc/esp32s3/include/soc/soc.h",
        "SOC_DROM/IROM/IRAM/DRAM and SOC_RTC_DATA half-open address definitions");

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD,
        "Ghidra 12.1.3 Ghidra/Processors/Xtensa/data/languages/xtensa.ldefs",
        "Xtensa:LE:32:default language with default compiler specification");

    private final EspressifChipDefinition chipDefinition;

    public Esp32S3TargetProvider(EspressifChipIdRegistry chipIds) {
        chipDefinition = Objects.requireNonNull(chipIds, "chipIds").requireByChipId(CHIP_ID);
        if (!chipDefinition.deviceId().equals("esp32s3")) {
            throw new IllegalArgumentException("Chip ID 9 is not defined as ESP32-S3");
        }
    }

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

    public LanguageSelection language() {
        return new LanguageSelection("Xtensa:LE:32:default", "default", "Xtensa", 32, 1,
            "little", List.of(LANGUAGE_EVIDENCE));
    }

    public MemoryClassification classify(AddressRange range) {
        Objects.requireNonNull(range, "range");
        if (!range.addressSpace().equals(ADDRESS_SPACE) || range.length() == 0) {
            return unknown(range);
        }
        for (RegionDefinition region : REGIONS) {
            if (region.contains(range)) {
                return new MemoryClassification(range, region.kind(), true,
                    region.readable(), region.writable(), region.executable(),
                    List.of(MEMORY_EVIDENCE));
            }
        }
        return unknown(range);
    }

    public EntryPointDecision validateEntry(long address, EspImage image) {
        Objects.requireNonNull(image, "image");
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("Entry address must be an unsigned 32-bit value");
        }
        MemoryClassification addressClass = classify(
            new AddressRange(ADDRESS_SPACE, address, 1));
        if (!addressClass.mappable()) {
            return rejected(address, "Entry address is outside recognized memory",
                Optional.of(addressClass), addressClass.evidence());
        }
        if (!addressClass.executable()) {
            return rejected(address, "Entry address is not in executable memory",
                Optional.of(addressClass), addressClass.evidence());
        }
        Optional<EspImageSegment> containingSegment = image.segments().stream()
            .filter(segment -> contains(segment.targetRange(), address))
            .findFirst();
        if (containingSegment.isEmpty()) {
            return rejected(address, "Entry address is not inside a mapped segment",
                Optional.of(addressClass), addressClass.evidence());
        }
        MemoryClassification segmentClass = classify(containingSegment.orElseThrow().targetRange());
        if (!segmentClass.executable()) {
            return rejected(address, "Mapped segment is not executable",
                Optional.of(segmentClass), segmentClass.evidence());
        }
        return new EntryPointDecision(true, address,
            "Entry address satisfies language alignment and is inside a mapped executable segment",
            Optional.of(segmentClass), combineEvidence(LANGUAGE_EVIDENCE, MEMORY_EVIDENCE));
    }

    private Evidence chipEvidence(int observedChipId) {
        return new Evidence(EvidenceKind.VENDOR_DATA_PACK,
            chipDefinition.sourcePath() + "@" + chipDefinition.sourceRevision(),
            "Maintained ESP32-S3 chip ID " + chipDefinition.chipId()
                + "; observed image chip ID " + observedChipId);
    }

    private static EntryPointDecision rejected(long address, String reason,
            Optional<MemoryClassification> classification, List<Evidence> evidence) {
        return new EntryPointDecision(false, address, reason, classification, evidence);
    }

    private static List<Evidence> combineEvidence(Evidence first, Evidence second) {
        return List.of(first, second);
    }

    private static boolean contains(AddressRange range, long address) {
        return address >= range.start() && address < range.endExclusive();
    }

    private static MemoryClassification unknown(AddressRange range) {
        return new MemoryClassification(range, MemoryRegionKind.UNKNOWN, false,
            false, false, false, List.of(MEMORY_EVIDENCE));
    }

    private record RegionDefinition(
            MemoryRegionKind kind,
            long start,
            long endExclusive,
            boolean readable,
            boolean writable,
            boolean executable) {
        private boolean contains(AddressRange range) {
            return range.start() >= start && range.endExclusive() <= endExclusive;
        }
    }
}
