package io.github.rezabakhshi.embedra.targets.stm32.memory;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.InterProcessorLink;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32DevicePackRegistry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Pure exact-part plans. Incomplete records fail closed; boot configuration is an explicit input. */
public final class Stm32MemoryPlanner {
    public static final String CATALOG_SHA256 =
        "00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66";

    private static final Set<String> REVIEWED_PROFILES = Set.of(
        "F103_MEDIUM_DENSITY_SINGLE_CORE", "G4_CATEGORY2_SINGLE_CORE", "G4_CATEGORY4_SINGLE_CORE",
        "F2_SINGLE_CORE", "F4_F401_SINGLE_CORE", "F7_SINGLE_CORE",
        "G4_CATEGORY3_SINGLE_CORE", "L4_L412_SINGLE_CORE", "L4P5_PLUS_SINGLE_CORE",
        "L4R5_PLUS_SINGLE_CORE", "L5_SINGLE_CORE", "H5_SINGLE_CORE", "G0_SINGLE_CORE",
        "C0_SINGLE_CORE", "H7_SINGLE_CORE", "U0_SINGLE_CORE", "U5_SINGLE_CORE",
        "WBA_SINGLE_CORE", "H7RS_SINGLE_CORE", "WB0_SINGLE_CORE",
        "WL3_SINGLE_CORE", "U3_SINGLE_CORE", "N6_SINGLE_CORE", "WB_DUAL_CORE");

    public enum BootMode {
        UNKNOWN, MAIN_FLASH, SYSTEM_MEMORY, SRAM
    }

    public record Region(String id, String kind, AddressRange range, String access,
            String configuration, Map<String, String> sharedAccess) {
        public Region {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(access, "access");
            requireRange(range);
            if (id.isBlank() || !Set.of("FLASH", "RAM", "SYSTEM", "OPTION", "OTP").contains(kind)
                    || !Set.of("r", "rx", "rw", "rwx").contains(access)) {
                throw new IllegalArgumentException("Invalid physical region");
            }
            configuration = configuration == null ? "FIXED" : configuration;
            if (!Set.of("FIXED", "ITCM_AXI_SHARED").contains(configuration)) {
                throw new IllegalArgumentException("Invalid region configuration");
            }
            sharedAccess = sharedAccess == null ? Map.of() : Map.copyOf(sharedAccess);
            if (sharedAccess.values().stream()
                    .anyMatch(value -> !Set.of("r", "rw").contains(value))) {
                throw new IllegalArgumentException("Invalid shared-memory access right");
            }
        }
    }

    public record Alias(String id, String target, AddressRange range, String condition) {
        public Alias {
            requireRange(range);
            if (!Set.of("ALWAYS", "MAIN_FLASH", "SYSTEM_MEMORY", "SRAM").contains(condition)) {
                throw new IllegalArgumentException("Invalid alias condition");
            }
        }
    }

    public record BitReference(long byteAddress, int bit) {
    }

    /** A nonlinear bit-band word view, never an ordinary byte alias or extra physical SRAM. */
    public record BitBandView(String id, AddressRange range, AddressRange target) {
        public BitBandView {
            requireRange(range);
            requireRange(target);
            if (range.length() != Math.multiplyExact(target.length(), 32)) {
                throw new IllegalArgumentException("Bit-band extent does not match backed SRAM");
            }
        }

        public BitReference translate(long wordAddress) {
            if (wordAddress < range.start() || wordAddress >= range.endExclusive()
                    || (wordAddress & 3) != 0) {
                throw new IllegalArgumentException("Not a backed aligned bit-band word");
            }
            long offset = wordAddress - range.start();
            return new BitReference(target.start() + offset / 32, (int) ((offset % 32) / 4));
        }
    }

    public record Plan(String exactPart, List<Region> regions, List<Alias> aliases,
            List<Alias> unresolvedBootAliases, List<Region> unresolvedConfigurationRegions,
            List<BitBandView> bitBandViews, ExecutionTopology topology, String otpAvailability,
            String otpReason, String peripheralBitBandReason, List<Evidence> evidence) {
        public Plan {
            regions = List.copyOf(regions);
            aliases = List.copyOf(aliases);
            unresolvedBootAliases = List.copyOf(unresolvedBootAliases);
            unresolvedConfigurationRegions = List.copyOf(unresolvedConfigurationRegions);
            bitBandViews = List.copyOf(bitBandViews);
            evidence = List.copyOf(evidence);
        }

        public String supportState() {
            return "PLANNED";
        }

        public String resetHandlerAvailability() {
            return "UNKNOWN_UNTIL_VECTOR_BYTES_ARE_SUPPLIED";
        }
    }

    private final Map<String, Map<?, ?>> records;

    private final Map<String, Evidence> documents;

    private Stm32MemoryPlanner(Map<String, Map<?, ?>> records, Map<String, Evidence> documents) {
        this.records = Map.copyOf(records);
        this.documents = Map.copyOf(documents);
    }

    public static Stm32MemoryPlanner load(Path path, Stm32CuratedPartIds ids,
            ParserLimits limits, CancellationToken cancellation) throws IOException, DiagnosticException {
        Objects.requireNonNull(ids, "ids");
        cancellation.throwIfCancellationRequested();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || ids.size() != 53) {
            throw new IOException("Memory plans require a regular file and pinned selection");
        }
        long size = Files.size(path);
        if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
            throw new IOException("Memory plans exceed parser limits");
        }
        byte[] bytes = Files.readAllBytes(path);
        cancellation.throwIfCancellationRequested();
        if (!CATALOG_SHA256.equals(sha256(bytes))) {
            throw new IOException("Memory plans digest mismatch");
        }
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(bytes, limits, cancellation);
            if (!"urn:embedra:schema:stm32-memory-plans:1".equals(root.get("$schema"))
                    || !Stm32CuratedPartIds.SELECTION_SHA256.equals(root.get("selectionSha256"))
                    || !Stm32DevicePackRegistry.CATALOG_SHA256.equals(root.get("sourceCatalogSha256"))) {
                throw new IOException("Memory plans schema or source identity mismatch");
            }
            Map<String, Map<?, ?>> parsed = new LinkedHashMap<>();
            for (Object value : (List<?>) root.get("records")) {
                cancellation.throwIfCancellationRequested();
                Map<?, ?> record = (Map<?, ?>) value;
                String exact = (String) record.get("exactPart");
                if (!ids.containsExactPart(exact) || parsed.putIfAbsent(exact, record) != null) {
                    throw new IOException("Unknown or duplicate exact part in memory plans");
                }
            }
            if (parsed.size() != ids.size()) {
                throw new IOException("Memory plans do not cover the exact selection");
            }
            Map<String, Evidence> documents = new LinkedHashMap<>();
            for (Object value : (List<?>) root.get("sourceDocuments")) {
                Map<?, ?> document = (Map<?, ?>) value;
                String digest = (String) document.get("sha256");
                if (!digest.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Document hash missing");
                }
                String id = (String) document.get("id");
                Evidence source = new Evidence(EvidenceKind.DOCUMENTED_FIELD,
                    id + ":sha256:" + digest, document.get("title") + "; " + document.get("revision")
                        + "; " + document.get("containerUrl") + "#" + document.get("containerEntry"));
                if (documents.putIfAbsent(id, source) != null) {
                    throw new IllegalArgumentException("Duplicate source document");
                }
            }
            Stm32MemoryPlanner planner = new Stm32MemoryPlanner(parsed, documents);
            for (Map.Entry<String, Map<?, ?>> entry : parsed.entrySet()) {
                if ("VALIDATED_MAP".equals(entry.getValue().get("status"))) {
                    planner.plan(entry.getKey(), BootMode.UNKNOWN);
                }
            }
            return planner;
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException exception) {
            throw new IOException("Invalid memory plan fields", exception);
        }
    }

    public Plan plan(String exactPart, BootMode bootMode) {
        return plan(exactPart, bootMode, Map.of());
    }

    /**
     * Builds an exact-part plan. Configuration-dependent regions (for example the H735
     * 192 KiB RAM shared between ITCM and AXI via TCM_AXI_SHARED) are placed only when a
     * matching {@code configurationInputs} selection is supplied; otherwise they are
     * reported as unresolved instead of being silently committed to one allocation.
     */
    public Plan plan(String exactPart, BootMode bootMode, Map<String, String> configurationInputs) {
        Objects.requireNonNull(bootMode, "bootMode");
        Objects.requireNonNull(configurationInputs, "configurationInputs");
        Map<?, ?> record = records.get(exactPart);
        if (record == null) {
            throw new IllegalArgumentException("Exact selected part required: " + exactPart);
        }
        if (!"VALIDATED_MAP".equals(record.get("status"))) {
            throw new IllegalStateException("Incomplete memory evidence for " + exactPart
                + ": " + record.get("missingProperties"));
        }
        if (!REVIEWED_PROFILES.contains(record.get("profile"))) {
            throw new IllegalArgumentException("No validated topology builder for this profile");
        }
        List<Region> regions = new ArrayList<>();
        List<Region> unresolvedConfiguration = new ArrayList<>();
        Map<String, Region> byId = new LinkedHashMap<>();
        Map<?, ?> alternatives = (Map<?, ?>) record.get("configurationAlternatives");
        for (Object value : (List<?>) record.get("regions")) {
            addRegion(regions, byId, region((Map<?, ?>) value));
        }
        for (Region region : regions) {
            if (!"FIXED".equals(region.configuration())
                    && (alternatives == null || !alternatives.containsKey(region.configuration()))) {
                throw new IllegalArgumentException("Region has an undeclared configuration marker");
            }
        }
        Set<String> resolvedKeys = new LinkedHashSet<>();
        if (alternatives != null) {
            for (Map.Entry<?, ?> entry : alternatives.entrySet()) {
                String key = (String) entry.getKey();
                Map<?, ?> spec = (Map<?, ?>) entry.getValue();
                String selected = configurationInputs.get(key);
                if (selected == null) {
                    unresolvedConfiguration.add(configurationPlaceholder(key, spec));
                }
                else {
                    for (Region region : resolveConfiguration(key, spec, selected)) {
                        addRegion(regions, byId, region);
                    }
                    resolvedKeys.add(key);
                }
            }
        }
        for (String key : configurationInputs.keySet()) {
            if (!resolvedKeys.contains(key)) {
                throw new IllegalArgumentException("Unknown configuration input: " + key);
            }
        }
        List<Alias> aliases = new ArrayList<>();
        List<Alias> unresolved = new ArrayList<>();
        List<Object> aliasRecords = new ArrayList<>((List<?>) record.get("aliases"));
        aliasRecords.addAll((List<?>) record.get("bootAliases"));
        for (Object value : aliasRecords) {
            Map<?, ?> raw = (Map<?, ?>) value;
            Alias alias = new Alias((String) raw.get("id"), (String) raw.get("target"),
                range(raw), (String) raw.get("condition"));
            Region target = byId.get(alias.target());
            if (target == null || target.range().length() != alias.range().length()) {
                throw new IllegalArgumentException("Alias has no equal-sized physical target");
            }
            if (alias.condition().equals("ALWAYS")) {
                aliases.add(alias);
            }
            else if (bootMode == BootMode.UNKNOWN) {
                unresolved.add(alias);
            }
            else if (bootMode.name().equals(alias.condition())) {
                aliases.add(alias);
            }
        }
        List<BitBandView> bitBands = new ArrayList<>();
        for (Object value : (List<?>) record.get("bitBandViews")) {
            Map<?, ?> raw = (Map<?, ?>) value;
            Region target = byId.get((String) raw.get("target"));
            if (target == null || !"RAM".equals(target.kind())) {
                throw new IllegalArgumentException("Bit-band view requires backed SRAM");
            }
            bitBands.add(new BitBandView((String) raw.get("id"), range(raw), target.range()));
        }
        List<Evidence> evidence = new ArrayList<>();
        for (Object id : (List<?>) record.get("sourceDocumentIds")) {
            Evidence document = documents.get((String) id);
            if (document == null) {
                throw new IllegalArgumentException("Unknown source document");
            }
            evidence.add(document);
        }
        evidence.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
            "stm32.memory-plans:" + CATALOG_SHA256, record.get("sourceSections").toString()));
        return new Plan(exactPart, regions, aliases, unresolved, unresolvedConfiguration, bitBands,
            topology(record, regions, aliases, evidence),
            (String) record.get("otpAvailability"), (String) record.get("otpReason"),
            (String) record.get("peripheralBitBandReason"), evidence);
    }

    private static Region region(Map<?, ?> raw) {
        Map<String, String> shared = new LinkedHashMap<>();
        Object sharedRaw = raw.get("sharedAccess");
        if (sharedRaw instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                shared.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
        }
        return new Region((String) raw.get("id"), (String) raw.get("kind"), range(raw),
            (String) raw.get("access"), (String) raw.get("configuration"), shared);
    }

    private static void addRegion(List<Region> regions, Map<String, Region> byId, Region region) {
        if (byId.putIfAbsent(region.id(), region) != null || regions.stream()
                .anyMatch(previous -> previous.range().overlaps(region.range()))) {
            throw new IllegalArgumentException("Duplicate or overlapping physical region");
        }
        regions.add(region);
    }

    /** The unresolved view of a configuration-dependent bank, counted once for capacity. */
    private static Region configurationPlaceholder(String key, Map<?, ?> spec) {
        Map<?, ?> allocations = spec.get("allocations") instanceof Map<?, ?> map ? map : Map.of();
        long start = Long.MAX_VALUE;
        for (Object allocationValue : allocations.values()) {
            Map<?, ?> allocation = (Map<?, ?>) allocationValue;
            for (Object rangeValue : (List<?>) allocation.get("ranges")) {
                Map<?, ?> raw = (Map<?, ?>) rangeValue;
                start = Math.min(start, ((Number) raw.get("start")).longValue());
            }
        }
        if (start == Long.MAX_VALUE) {
            throw new IllegalArgumentException("Configuration alternative has no ranges");
        }
        if (!(spec.get("physicalKiB") instanceof Number physical) || physical.longValue() <= 0) {
            throw new IllegalArgumentException("Configuration alternative has no physical size");
        }
        long size = Math.multiplyExact(physical.longValue(), 1024L);
        if (size > 0x1_0000_0000L - start) {
            throw new IllegalArgumentException("Configuration alternative exceeds the 32-bit space");
        }
        return new Region(key, (String) spec.get("kind"), new AddressRange("ram", start, size),
            "rwx", key, Map.of());
    }

    /** Resolves one allocation ID into its concrete ITCM/AXI backed ranges. */
    private static List<Region> resolveConfiguration(String key, Map<?, ?> spec, String allocation) {
        Map<?, ?> allocations = spec.get("allocations") instanceof Map<?, ?> map ? map : Map.of();
        Map<?, ?> selected = allocations.get(allocation) instanceof Map<?, ?> map ? map : null;
        if (selected == null) {
            throw new IllegalArgumentException(
                "Configuration selection does not match a declared allocation: " + allocation);
        }
        List<?> ranges = selected.get("ranges") instanceof List<?> list ? list : List.of();
        if (ranges.isEmpty()) {
            throw new IllegalArgumentException("Allocation has no backed ranges");
        }
        List<Region> result = new ArrayList<>();
        int index = 0;
        for (Object value : ranges) {
            Map<?, ?> raw = (Map<?, ?>) value;
            String id = ranges.size() == 1 ? key + "_" + allocation : key + "_" + allocation + "_" + index;
            result.add(new Region(id, (String) spec.get("kind"),
                new AddressRange("ram", ((Number) raw.get("start")).longValue(),
                    ((Number) raw.get("size")).longValue()),
                "rwx", key, Map.of()));
            index++;
        }
        return result;
    }

    private static ExecutionTopology topology(Map<?, ?> record, List<Region> regions,
            List<Alias> aliases, List<Evidence> evidence) {
        Map<?, ?> topology = (Map<?, ?>) record.get("topology");
        if (topology == null || !(topology.get("physicalCoreCount") instanceof Number count)) {
            throw new IllegalArgumentException("Topology requires physicalCoreCount");
        }
        int physicalCoreCount = count.intValue();
        if ("WB_DUAL_CORE".equals(record.get("profile"))) {
            if (physicalCoreCount != 2) {
                throw new IllegalArgumentException("WB_DUAL_CORE profile requires physicalCoreCount 2");
            }
            return dualCoreTopology(topology, regions, aliases, evidence);
        }
        if (physicalCoreCount != 1) {
            throw new IllegalArgumentException("Single-core profile requires physicalCoreCount 1");
        }
        SecurityDomain domain = new SecurityDomain("unpartitioned", SecurityDomainKind.CUSTOM);
        List<ProcessorNode> nodes = List.of(
            node("cpu", ProcessorKind.CPU_CORE, "Application " + topology.get("core"), FirmwareSource.SHARED_IMAGE,
                topology, domain, evidence),
            node("boot-rom", ProcessorKind.BOOT_ROM, "Factory boot context on cpu", FirmwareSource.ROM,
                topology, domain, evidence));
        BootRelationship alternative = new BootRelationship("boot-selection", "cpu", "boot-rom",
            BootRelationshipType.ALTERNATIVE_TO,
            (String) topology.get("bootSelectionMechanism"),
            Confidence.VERIFIED, evidence);
        return new ExecutionTopology(nodes, List.of(), List.of(alternative), List.of(), List.of(),
            ProgramStrategy.SHARED_PROGRAM);
    }

    /** Two genuine physical cores on one die sharing flash, SRAM, IPCC mailboxes, and HSEM semaphores. */
    private static ExecutionTopology dualCoreTopology(Map<?, ?> topology, List<Region> regions,
            List<Alias> aliases, List<Evidence> evidence) {
        SecurityDomain domain = new SecurityDomain("unpartitioned", SecurityDomainKind.CUSTOM);
        ProcessorNode cpu1 = coreNode("cpu1", "Application " + topology.get("core"), FirmwareSource.SHARED_IMAGE,
            (String) topology.get("instructionSet"), (String) topology.get("languageId"),
            (String) topology.get("compilerSpecId"), domain, evidence);
        ProcessorNode cpu2 = coreNode("cpu2", "Network " + topology.get("secondaryCore"),
            FirmwareSource.INDEPENDENT_IMAGE, (String) topology.get("secondaryInstructionSet"),
            (String) topology.get("secondaryLanguageId"), (String) topology.get("secondaryCompilerSpecId"),
            domain, evidence);
        ProcessorNode bootRom = node("boot-rom", ProcessorKind.BOOT_ROM, "Factory boot context on cpu1",
            FirmwareSource.ROM, topology, domain, evidence);
        List<BootRelationship> boots = List.of(
            new BootRelationship("cpu1-boot-selection", "cpu1", "boot-rom", BootRelationshipType.ALTERNATIVE_TO,
                (String) topology.get("bootSelectionMechanism"), Confidence.VERIFIED, evidence),
            new BootRelationship("cpu1-releases-cpu2", "cpu1", "cpu2", BootRelationshipType.RELEASES_FROM_RESET,
                (String) topology.get("secondaryBootMechanism"), Confidence.VERIFIED, evidence));
        List<SharedMemoryRegion> shared = new ArrayList<>();
        for (Region region : regions) {
            if (!"RAM".equals(region.kind())) {
                continue;
            }
            List<AddressRange> mirrors = new ArrayList<>();
            for (Alias alias : aliases) {
                if (alias.target().equals(region.id())) {
                    mirrors.add(alias.range());
                }
            }
            Set<String> readers = new LinkedHashSet<>();
            Set<String> writers = new LinkedHashSet<>();
            if (region.sharedAccess().isEmpty()) {
                throw new IllegalArgumentException(
                    "Dual-core shared RAM requires explicit sharedAccess metadata");
            }
            for (Map.Entry<String, String> entry : region.sharedAccess().entrySet()) {
                String node = entry.getKey().equals("cpu1") ? "cpu1"
                    : entry.getKey().equals("cpu2") ? "cpu2" : null;
                if (node == null) {
                    throw new IllegalArgumentException("Unknown shared-memory participant");
                }
                readers.add(node);
                if ("rw".equals(entry.getValue())) {
                    writers.add(node);
                }
            }
            if (readers.isEmpty()) {
                throw new IllegalArgumentException("Shared RAM requires at least one reader");
            }
            shared.add(new SharedMemoryRegion(region.id() + "-shared", region.range(), Set.copyOf(readers),
                Set.copyOf(readers), Set.copyOf(writers), mirrors, Confidence.VERIFIED, evidence));
        }
        List<InterProcessorLink> links = List.of(
            new InterProcessorLink("ipcc-mailbox", CommunicationKind.MAILBOX, Set.of("cpu1", "cpu2"),
                Optional.of(peripheralRange(topology.get("ipccRegisterRange"))), Confidence.VERIFIED, evidence),
            new InterProcessorLink("hsem-semaphore", CommunicationKind.HARDWARE_SEMAPHORE, Set.of("cpu1", "cpu2"),
                Optional.of(peripheralRange(topology.get("hsemRegisterRange"))), Confidence.VERIFIED, evidence));
        return new ExecutionTopology(List.of(cpu1, cpu2, bootRom), shared, boots, links, List.of(),
            ProgramStrategy.SHARED_PROGRAM);
    }

    private static ProcessorNode coreNode(String id, String role, FirmwareSource source, String instructionSet,
            String languageId, String compilerSpecId, SecurityDomain domain, List<Evidence> evidence) {
        return new ProcessorNode(id, ProcessorKind.CPU_CORE, Optional.of(instructionSet),
            Optional.of(languageId), Optional.of(compilerSpecId), role, domain, "physical " + id,
            Set.of("ram"), List.of(), source, Confidence.VERIFIED, evidence);
    }

    private static AddressRange peripheralRange(Object raw) {
        if (!(raw instanceof List<?> bounds) || bounds.size() != 2
                || !(bounds.get(0) instanceof Number startNum)
                || !(bounds.get(1) instanceof Number endNum)) {
            throw new IllegalArgumentException("Malformed peripheral range bounds");
        }
        long start = startNum.longValue();
        long end = endNum.longValue();
        if (start < 0 || end <= start || end > 0x1_0000_0000L) {
            throw new IllegalArgumentException("Peripheral range out of bounds: " + start + ".." + end);
        }
        return new AddressRange("peripheral", start, end - start);
    }

    private static ProcessorNode node(String id, ProcessorKind kind, String role, FirmwareSource source,
            Map<?, ?> topology, SecurityDomain domain, List<Evidence> evidence) {
        return new ProcessorNode(id, kind, Optional.of((String) topology.get("instructionSet")),
            Optional.of((String) topology.get("languageId")), Optional.of((String) topology.get("compilerSpecId")),
            role, domain, "same physical " + topology.get("core"), Set.of("ram"), List.of(), source,
            Confidence.VERIFIED, evidence);
    }

    private static AddressRange range(Map<?, ?> raw) {
        return new AddressRange("ram", (Long) raw.get("start"), (Long) raw.get("size"));
    }

    private static void requireRange(AddressRange range) {
        Objects.requireNonNull(range, "range");
        if (!"ram".equals(range.addressSpace()) || range.length() <= 0 || range.endExclusive() > 0x100000000L) {
            throw new IllegalArgumentException("Memory range must fit the 32-bit address space");
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
