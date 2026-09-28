package io.github.rezabakhshi.embedra.targets.esp8266;

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
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266Image;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.esp.EspMemoryMap;
import io.github.rezabakhshi.embedra.targets.esp.EspMemoryRegion;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Independent provider for ESP8266/ESP8285 legacy images and the Xtensa LX106. */
public final class Esp8266LegacyTargetProvider {
    public static final String PROVIDER_ID = "target.esp8266.legacy";

    private static final String ADDRESS_SPACE = "default";

    private static final String PROVIDER_VERSION = "esptool-v5.4.0";

    private static final Evidence FORMAT_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD,
        "esptool v5.4.0 esptool/bin_image.py ESP8266 image classes",
        "Version 1 and 2 image structures identify the legacy ESP8266 family but do not "
            + "encode an exact ESP8266EX or ESP8285 part");

    private static final Evidence MEMORY_EVIDENCE = new Evidence(
        EvidenceKind.VENDOR_DATA_PACK,
        "esptool v5.4.0 esptool/targets/esp8266.py",
        "Pinned ESP8266 DRAM, IRAM, and flash-mapped IROM boundaries");

    private static final Evidence LANGUAGE_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "Ghidra 12.1.3 Xtensa language",
        "Xtensa:LE:32:default models the generated LX106 fixture");

    private static final EspMemoryMap MEMORY_MAP = new EspMemoryMap(ADDRESS_SPACE,
        List.of(
            new EspMemoryRegion(MemoryRegionKind.DRAM, 0x3ffe_8000L, 0x4000_0000L,
                true, true, false, MEMORY_EVIDENCE),
            new EspMemoryRegion(MemoryRegionKind.IRAM, 0x4010_0000L, 0x4010_8000L,
                true, false, true, MEMORY_EVIDENCE),
            new EspMemoryRegion(MemoryRegionKind.IROM, 0x4020_1010L, 0x402e_1010L,
                true, false, true, MEMORY_EVIDENCE)));

    public String providerId() {
        return PROVIDER_ID;
    }

    public String providerVersion() {
        return PROVIDER_VERSION;
    }

    public String canonicalIdentity() {
        return "esp8266-legacy-family|exact-part-unencoded|Xtensa:LE:32:default|default|"
            + PROVIDER_VERSION;
    }

    public SupportDecision supports(Esp8266Image image) {
        Objects.requireNonNull(image, "image");
        return new SupportDecision(true, Optional.of("esp8266-legacy-family"),
            "Legacy image structure is supported; exact ESP8266EX/ESP8285 identity is "
                + "not encoded",
            List.of(FORMAT_EVIDENCE));
    }

    public LanguageSelection language() {
        return new LanguageSelection("Xtensa:LE:32:default", "default", "Xtensa LX106",
            32, 1, "little", List.of(LANGUAGE_EVIDENCE));
    }

    public MemoryClassification classify(AddressRange range) {
        return MEMORY_MAP.classify(range);
    }

    public EntryPointDecision validateEntry(long address, Esp8266Image image) {
        Objects.requireNonNull(image, "image");
        AddressRange point = new AddressRange(ADDRESS_SPACE, address, 1);
        MemoryClassification classification = classify(point);
        boolean encoded = image.segments().stream()
            .filter(segment -> !segment.flashMapped())
            .anyMatch(segment -> address >= segment.directTargetRange().start()
                && address < segment.directTargetRange().endExclusive());
        boolean accepted = address == image.header().entryPoint() && encoded
            && classification.mappable() && classification.executable();
        return new EntryPointDecision(accepted, address,
            accepted ? "Entry point is inside executable LX106 RAM"
                : "Entry point is not the validated executable image entry",
            accepted ? Optional.of(classification) : Optional.empty(),
            List.of(MEMORY_EVIDENCE, LANGUAGE_EVIDENCE));
    }

    public ExecutionTopology topology(Esp8266Image image) {
        Objects.requireNonNull(image, "image");
        ResetEntry entry = new ResetEntry("image-entry", ADDRESS_SPACE,
            image.header().entryPoint(), Confidence.VERIFIED,
            List.of(FORMAT_EVIDENCE, MEMORY_EVIDENCE));
        ProcessorNode processor = new ProcessorNode("application-cpu",
            ProcessorKind.CPU_CORE, Optional.of("Xtensa LX106"),
            Optional.of(language().languageId()), Optional.of(language().compilerSpecId()),
            "application processor", SecurityDomain.unknown(), "esp8266-legacy-family",
            Set.of(ADDRESS_SPACE), List.of(entry), FirmwareSource.SHARED_IMAGE,
            Confidence.VERIFIED, List.of(FORMAT_EVIDENCE, LANGUAGE_EVIDENCE));
        return new ExecutionTopology(List.of(processor), List.of(), List.of(), List.of(),
            List.of(), ProgramStrategy.SHARED_PROGRAM);
    }
}
